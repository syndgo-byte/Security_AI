"""Backed-up kernel hardening and verified rollback."""
from __future__ import annotations

import difflib
import os
from datetime import datetime, timezone
from pathlib import Path

from . import baseline, host


def build_plan(root: Path, *, allow_userns: bool = False) -> dict:
    snapshot = host.inspect(root)
    targets, skipped = {}, {}
    for key, value in host.TARGETS.items():
        if key == host.USERNS_KEY and (snapshot["runtimes"] or allow_userns):
            skipped[key] = "container runtime detected or --allow-userns selected"
        elif key not in snapshot["sysctls"]:
            # A missing optional knob is fine; permission/read errors are not absence.
            if host.path(root, "/proc/sys/" + key.replace(".", "/")).exists():
                raise OSError(snapshot["unavailable"][key])
            skipped[key] = "sysctl unavailable"
        else:
            if snapshot["sysctls"][key] not in {"0", "1", "2"}:
                raise ValueError(f"unexpected runtime value: {key}")
            targets[key] = value
    loaded = sorted(set(snapshot["modules"]) & set(host.MODULES))
    blacklist = [m for m in host.MODULES if m not in loaded]
    for module in loaded:
        skipped["module:" + module] = "currently loaded; manual review required"
    # The BPF latch is last so earlier sysctl errors are less likely to require reboot.
    ordered = sorted(targets, key=lambda key: (key == host.BPF_KEY, key))
    files = {
        host.SYSCTL_FILE: "# Managed by security kernel harden.\n" +
                         "".join(f"{key} = {targets[key]}\n" for key in ordered),
        host.MODULE_FILE: "# Managed by security; loaded modules are left unchanged.\n" +
                         "".join(f"blacklist {m}\ninstall {m} /bin/false\n" for m in blacklist),
    }
    diffs = {}
    for name, after in files.items():
        target = host.path(root, name)
        host.no_symlinks(target)
        before = target.read_text() if target.exists() else ""
        diffs[name] = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                                 fromfile=name, tofile=name + " (planned)"))
    return {"sysctls": targets, "runtime_before": {k: snapshot["sysctls"][k] for k in targets},
            "files": files, "diff": diffs, "skipped": skipped,
            "loaded_modules_skipped": loaded, "blacklisted_modules": blacklist,
            "runtimes": snapshot["runtimes"],
            "warnings": ["BPF value 1 cannot be lowered until reboot; rollback may require reboot.",
                         "io_uring_disabled=2 also disables root workloads using io_uring."]}


def latest(directory: Path) -> Path:
    backups = sorted(p for p in directory.glob("*/transaction.json") if not p.parent.is_symlink())
    if not backups:
        raise FileNotFoundError("kernel backup not found")
    return backups[-1].parent


def require_root() -> None:
    if os.name == "posix" and os.geteuid() != 0:
        raise PermissionError("kernel mutation requires root")


def _restore(root: Path, directory: Path, backup: Path) -> dict:
    transaction = host.load_json(backup / "transaction.json")
    prior = host.load_json(backup / "runtime.json")
    if (transaction.get("schema") != 1 or set(transaction.get("files", {})) != {host.SYSCTL_FILE, host.MODULE_FILE}
            or not prior or any(k not in host.TARGETS or v not in {"0", "1", "2"} for k, v in prior.items())):
        raise ValueError("invalid kernel backup")
    if transaction.get("status") == "rolled_back":
        return {"status": "rolled_back", "backup": str(backup), "reboot_required": False, "errors": []}
    errors, pending = [], {}
    for name in (host.SYSCTL_FILE, host.MODULE_FILE):
        try:
            meta = transaction["files"][name]
            target = host.path(root, name)
            host.no_symlinks(target)
            if meta["exists"]:
                saved = backup / Path(name).name
                host.no_symlinks(saved)
                host.atomic_write(target, saved.read_bytes(), meta["mode"])
            else:
                target.unlink(missing_ok=True)
        except (KeyError, TypeError, *host.ERRORS) as exc:
            errors.append(f"{name}: {exc}")
    for key, value in prior.items():
        try:
            current = host.path(root, "/proc/sys/" + key.replace(".", "/")).read_text().strip()
            if current == value:
                continue
            if key == host.BPF_KEY and current == "1" and value != "1":
                pending[key] = value
            else:
                host.set_sysctl(root, key, value)
        except host.ERRORS as exc:
            errors.append(f"{key}: {exc}")
    # Stop monitoring the removed hardening policy, including pending-reboot rollback.
    baseline_path = directory / "baseline.json"
    try:
        host.no_symlinks(baseline_path)
        previous = backup / "baseline-before.json"
        if previous.exists():
            host.no_symlinks(previous)
            host.atomic_write(baseline_path, previous.read_bytes())
        else:
            baseline_path.unlink(missing_ok=True)
    except host.ERRORS as exc:
        errors.append(str(exc))
    status = "rollback_incomplete" if errors else "pending_reboot" if pending else "rolled_back"
    transaction["status"] = status
    host.save_json(backup / "transaction.json", transaction)
    return {"status": status, "backup": str(backup), "reboot_required": bool(pending),
            "restore_after_reboot": pending, "errors": errors}


def harden(root: Path = Path("/"), *, dry_run: bool = False, allow_userns: bool = False,
           backup_dir: Path | None = None) -> dict:
    if result := host.unsupported():
        return result
    try:
        if dry_run:
            return {"status": "dry_run", "plan": build_plan(root, allow_userns=allow_userns)}
        require_root()
        directory = host.state_dir(root, backup_dir)
        with host.locked(directory):
            try:
                previous = host.load_json(latest(directory) / "transaction.json")
            except FileNotFoundError:
                previous = None
            if previous and previous.get("status") != "rolled_back":
                raise ValueError("existing kernel transaction: rollback before hardening again")
            plan = build_plan(root, allow_userns=allow_userns)
            if not plan["sysctls"]:
                raise ValueError("no supported kernel sysctls")
            backup = directory / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
            transaction = {"schema": 1, "status": "prepared", "files": {}, "target": plan["sysctls"]}
            for name in plan["files"]:
                target = host.path(root, name)
                host.no_symlinks(target)
                exists = target.exists()
                mode = (target.stat().st_mode & 0o777) if exists else 0o644
                transaction["files"][name] = {"exists": exists, "mode": mode}
                if exists:
                    host.atomic_write(backup / Path(name).name, target.read_bytes())
            old_baseline = directory / "baseline.json"
            if old_baseline.exists():
                host.no_symlinks(old_baseline)
                host.atomic_write(backup / "baseline-before.json", old_baseline.read_bytes())
            host.save_json(backup / "runtime.json", plan["runtime_before"])
            host.save_json(backup / "transaction.json", transaction)
            try:
                # Recheck before writing: do not newly blacklist a module loaded during preflight.
                now_loaded = set(host.loaded_modules(root))
                if now_loaded & set(plan["blacklisted_modules"]):
                    raise OSError("module state changed during preflight; retry")
                for name, content in plan["files"].items():
                    host.atomic_write(host.path(root, name), content.encode(), 0o644)
                host.run("sysctl", "-p", str(host.path(root, host.SYSCTL_FILE)))
                current, _ = host.read_sysctls(root)
                if any(current.get(k) != v for k, v in plan["sysctls"].items()):
                    raise OSError("runtime sysctl verification failed after apply")
                snapshot = baseline.capture(root, managed=plan["sysctls"], blacklist=plan["blacklisted_modules"])
                host.save_json(directory / "baseline.json", snapshot)
                transaction["status"] = "active"
                host.save_json(backup / "transaction.json", transaction)
                return {"status": "applied", "backup": str(backup), "plan": plan, "baseline": snapshot}
            except host.ERRORS as exc:
                return {"status": "error", "message": str(exc), "backup": str(backup),
                        "rollback": _restore(root, directory, backup)}
    except host.ERRORS as exc:
        return {"status": "error", "message": str(exc)}


def rollback(root: Path = Path("/"), *, backup_dir: Path | None = None) -> dict:
    if result := host.unsupported():
        return result
    try:
        require_root()
        directory = host.state_dir(root, backup_dir)
        with host.locked(directory):
            return _restore(root, directory, latest(directory))
    except host.ERRORS as exc:
        return {"status": "error", "message": str(exc)}
