"""JSON baseline kept with the kernel transaction, outside the findings schema."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from . import host


def sysctl_hash(values: dict) -> str:
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def capture(root: Path = Path("/"), *, managed: dict | None = None,
            blacklist: list[str] | None = None) -> dict:
    values, unavailable = host.read_sysctls(root)
    bpf_error = None
    try:
        bpf = json.loads(host.run("bpftool", "prog", "show", "-j"))
        if not isinstance(bpf, list):
            raise ValueError("bpftool did not return a list")
        source = "bpftool"
    except host.ERRORS as exc:
        bpf_error = str(exc)
        directory = host.path(root, "/sys/fs/bpf")
        bpf = sorted(p.name for p in directory.iterdir()) if directory.exists() else []
        source = "pinned_entries"  # Only immediate entries, not a recursive BPF scan.
    if managed is None:
        managed = {}
        config = host.path(root, host.SYSCTL_FILE)
        if config.exists():
            for line in config.read_text().splitlines():
                key, sep, value = line.partition("=")
                key, value = key.strip(), value.split("#", 1)[0].strip()
                if sep and key in host.TARGETS and value == host.TARGETS[key]:
                    managed[key] = value
    return {"schema": 1, "created_at": datetime.now(timezone.utc).isoformat(),
            "sysctls": values, "sysctl_sha256": sysctl_hash(values), "unavailable": unavailable,
            "managed_sysctls": managed, "modules": host.loaded_modules(root),
            "blacklisted_modules": (blacklist if blacklist is not None else
                                    sorted(set(host.blacklisted_modules(root)) & set(host.MODULES))),
            "bpf": bpf, "bpf_source": source, "bpf_error": bpf_error}


def load(root: Path = Path("/"), *, backup_dir: Path | None = None) -> dict:
    value = host.load_json(host.state_dir(root, backup_dir) / "baseline.json")
    values = value.get("sysctls")
    managed = value.get("managed_sysctls")
    modules = value.get("modules")
    blacklist = value.get("blacklisted_modules")
    if (value.get("schema") != 1 or not isinstance(values, dict) or not isinstance(managed, dict)
            or value.get("sysctl_sha256") != sysctl_hash(values)
            or any(k not in host.TARGETS or v not in {"0", "1", "2"} for k, v in values.items())
            or any(k not in host.TARGETS or v != host.TARGETS[k] or values.get(k) != v
                   for k, v in managed.items())
            or not isinstance(modules, list) or not all(isinstance(m, str) for m in modules)
            or not isinstance(blacklist, list) or any(m not in host.MODULES for m in blacklist)):
        raise ValueError("invalid kernel baseline schema, hash or managed values")
    return value


def baseline(root: Path = Path("/"), *, save: bool = True, backup_dir: Path | None = None) -> dict:
    if result := host.unsupported():
        return result
    try:
        directory = host.state_dir(root, backup_dir)
        if save:
            with host.locked(directory):
                value = capture(root)
                if any(value["sysctls"].get(k) != v for k, v in value["managed_sysctls"].items()):
                    raise ValueError("managed sysctls have drifted; baseline not overwritten")
                host.save_json(directory / "baseline.json", value)
        else:
            value = load(root, backup_dir=backup_dir)
        return {"status": "ok", "baseline": value}
    except FileNotFoundError:
        return {"status": "missing", "message": "kernel baseline not found"}
    except host.ERRORS as exc:
        return {"status": "error", "message": str(exc)}
