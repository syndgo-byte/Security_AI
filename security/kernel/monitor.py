"""Bounded sysctl/module drift checks and incremental auditd threat events."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shlex
import stat
import threading
import time
from pathlib import Path

from . import baseline, harden, host

# Exact trusted paths: an executable such as /tmp/sudo must not bypass detection.
ROOT_WHITELIST = frozenset({
    "/usr/bin/sudo", "/bin/sudo", "/usr/bin/su", "/bin/su",
    "/usr/sbin/sshd", "/sbin/sshd", "/usr/bin/login", "/bin/login",
    "/usr/lib/systemd/systemd", "/lib/systemd/systemd", "/sbin/init",
    "/usr/sbin/cron", "/usr/sbin/crond", "/sbin/crond",
    "/usr/lib/polkit-1/polkitd", "/usr/libexec/polkitd", "/usr/bin/pkexec",
})
SYSCALLS = {
    "c000003e": {"321": "bpf", "425": "io_uring_setup", "272": "unshare",
                 "105": "setuid", "113": "setreuid", "117": "setresuid", "59": "execve", "322": "execveat"},
    "40000003": {"357": "bpf", "425": "io_uring_setup", "310": "unshare", "23": "setuid",
                 "70": "setreuid", "164": "setresuid", "213": "setuid", "203": "setreuid",
                 "208": "setresuid", "11": "execve", "358": "execveat"},
    "c00000b7": {"280": "bpf", "425": "io_uring_setup", "97": "unshare", "146": "setuid",
                 "145": "setreuid", "147": "setresuid", "221": "execve", "281": "execveat"},
}
FIELD_RE = re.compile(r'(?:^|\s)([a-zA-Z0-9_]+)=("[^"]*"|\S+)')
ID_RE = re.compile(r"msg=audit\(([^)]+)\)")


def _nonroot(value: str) -> bool:
    return value.isdecimal() and 0 < int(value) < 4294967295


def parse_audit_line(line: str) -> dict | None:
    fields = {k: v.strip('"') for k, v in FIELD_RE.findall(line)}
    if fields.get("type") != "SYSCALL":
        return None
    serial = ID_RE.search(line)
    if not serial:
        return None
    raw_call = fields.get("syscall", "")
    call = SYSCALLS.get(fields.get("arch", ""), {}).get(raw_call)
    if call is None and raw_call in set().union(*(set(m.values()) for m in SYSCALLS.values())):
        call = raw_call
    if call is None:
        return None
    uid, euid, auid = (fields.get(k, "") for k in ("uid", "euid", "auid"))
    executable = fields.get("exe", "")
    if executable and not executable.startswith("/"):
        try:
            executable = bytes.fromhex(executable).decode("utf-8")
        except (ValueError, UnicodeError):
            pass
    kind = None
    if call in {"bpf", "io_uring_setup", "unshare"} and _nonroot(uid):
        if call == "unshare":
            try:
                # Raw audit syscall arguments are hexadecimal, even without 0x.
                if not int(fields.get("a0", "0"), 16) & 0x10000000:
                    return None
            except ValueError:
                return None
        kind = "kernel_high_risk_syscall"
    elif (call in {"setuid", "setreuid", "setresuid", "execve", "execveat"}
          and fields.get("success") in {"yes", "1"} and euid == "0"
          and (_nonroot(uid) or (_nonroot(auid) and call.startswith("set")))
          and executable not in ROOT_WHITELIST):
        # A successful set*uid must actually request a root credential, not just run as root.
        args = ("a0",) if call == "setuid" else ("a0", "a1") if call == "setreuid" else ("a0", "a1", "a2")
        if call.startswith("set"):
            try:
                if not any(int(fields.get(a, "-1"), 16) == 0 for a in args):
                    return None
            except ValueError:
                return None
        kind = "kernel_root_transition"
    if kind is None:
        return None
    return {"id": serial[1], "kind": kind, "syscall": call, "uid": uid, "euid": euid,
            "auid": auid, "exe": executable, "pid": fields.get("pid", ""),
            "success": fields.get("success") in {"yes", "1"}}


def audit_rules(arch: str) -> list[str]:
    if arch not in {"x86_64", "aarch64"}:
        raise ValueError(f"audit rules support x86_64/aarch64 only: {arch}")
    rules = []
    for abi in (["b64", "b32"] if arch == "x86_64" else ["b64"]):
        prefix = f"-a always,exit -F arch={abi}"
        creds = "setuid,setreuid,setresuid" + (",setuid32,setreuid32,setresuid32" if abi == "b32" else "")
        rules.extend([
            prefix + " -S bpf,io_uring_setup -F uid!=0 -k kg_risk",
            prefix + " -S unshare -F a0&=0x10000000 -F uid!=0 -k kg_risk",
            prefix + f" -S {creds} -F success=1 -F euid=0 -F auid!=0 -k kg_uid",
            prefix + " -S execve,execveat -F success=1 -F euid=0 -C uid!=euid -k kg_uid",
            prefix + " -S init_module,finit_module -F success=1 -k kg_module",
        ])
    return rules


def canonical_rule(line: str) -> tuple:
    fields = shlex.split(line)
    parts = []
    for i in range(0, len(fields) - 1, 2):
        flag, value = fields[i:i + 2]
        if flag == "-k":
            flag, value = "-F", "key=" + value
        if flag == "-S":
            parts.extend((flag, name) for name in value.split(","))
            continue
        value = {"exit,always": "always,exit", "success=yes": "success=1",
                 "a0&=0x10000000": "a0&=268435456"}.get(value, value)
        parts.append((flag, value))
    return tuple(sorted(parts))


def ensure_rules() -> None:
    health = dict(line.split(None, 1) for line in host.run("auditctl", "-s").splitlines()
                  if len(line.split(None, 1)) == 2)
    if health.get("enabled") not in {"1", "2"} or health.get("pid", "0") == "0":
        raise OSError("auditd missing or not running")
    if health.get("lost", "0") != "0":
        raise OSError("auditd reports lost records; coverage incomplete")
    want = audit_rules(host.run("uname", "-m"))
    have = {canonical_rule(line) for line in host.run("auditctl", "-l").splitlines()}
    added = []
    try:
        for rule in want:
            if canonical_rule(rule) not in have:
                host.run("auditctl", *shlex.split(rule))
                added.append(rule)
    except host.ERRORS:
        for rule in reversed(added):
            try:
                host.run("auditctl", "-d", *shlex.split(rule)[1:])
            except host.ERRORS:
                pass
        raise


class AuditTail:
    """Start at EOF, retain partial lines and drain the old inode on rotation."""

    def __init__(self, path: Path, cursor: dict | None = None):
        self.path = path
        self.stream = None
        self.partial = b""
        self._open()
        info = os.fstat(self.stream.fileno())
        if cursor and cursor.get("inode") == [info.st_dev, info.st_ino] and 0 <= cursor.get("offset", -1) <= info.st_size:
            self.stream.seek(cursor["offset"])
            self.partial = cursor.get("partial", "").encode("utf-8")
        else:
            self.stream.seek(0, os.SEEK_END)

    def _open(self):
        host.no_symlinks(self.path)
        if not stat.S_ISREG(self.path.stat().st_mode):
            raise OSError("audit log must be a regular file")
        self.stream = self.path.open("rb")

    def close(self):
        if self.stream:
            self.stream.close()

    def cursor(self) -> dict:
        info = os.fstat(self.stream.fileno())
        return {"inode": [info.st_dev, info.st_ino], "offset": self.stream.tell(),
                "partial": self.partial.decode("utf-8", errors="replace")}

    def poll(self) -> list[str]:
        info = os.fstat(self.stream.fileno())
        if info.st_size < self.stream.tell():
            self.stream.seek(0)
            self.partial = b""
        data = self.partial + self.stream.read(256 * 1024)
        lines = data.split(b"\n")
        self.partial = lines.pop()
        if len(self.partial) > 1024 * 1024:
            raise OSError("audit record exceeds 1 MiB")
        try:
            current = self.path.stat()
        except FileNotFoundError:
            current = info
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino) and self.stream.tell() >= info.st_size:
            self.close()
            self._open()
            self.partial = b""
        return [line.decode("utf-8", errors="replace") for line in lines]


def report_event(event: dict) -> None:
    from .. import alerts, store
    con = store.connect()
    try:
        alerts.emit(con, "host", event["kind"], "high", event["title"],
                    json.dumps(event, ensure_ascii=False))
    finally:
        con.close()


class Monitor:
    def __init__(self, root: Path = Path("/"), *, interval: float = 60,
                 backup_dir: Path | None = None, emit=None):
        if interval < 1:
            raise ValueError("monitor interval must be at least 1 second")
        self.root = Path(root)
        self.directory = host.state_dir(root, backup_dir)
        self.interval = interval
        self.emit = emit or report_event
        self.tail = None
        self.state = {"seen": {}, "diagnosed": [], "cursor": None}
        self.current = {"status": "idle", "running": False, "interval": interval}
        self.stop_event = threading.Event()
        self.thread = None
        self.next_drift = 0
        self.next_health = 0

    def _diagnose(self, message: str, diagnostics: list):
        if message not in self.state["diagnosed"]:
            diagnostics.append(message)
            self.state["diagnosed"].append(message)
            self.state["diagnosed"] = self.state["diagnosed"][-32:]

    def _emit(self, event: dict, events: list):
        identity = {k: v for k, v in event.items() if k not in {"id", "pid", "restored", "errors"}}
        key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        now = time.time()
        self.state["seen"] = {k: ts for k, ts in self.state["seen"].items() if now - ts < 300}
        if key in self.state["seen"]:
            return
        self.emit(event)
        events.append(event)
        self.state["seen"][key] = now
        if len(self.state["seen"]) > 4096:
            del self.state["seen"][next(iter(self.state["seen"]))]

    def _drift(self, events: list, diagnostics: list):
        try:
            target = baseline.load(self.root, backup_dir=self.directory)
            transaction = host.load_json(harden.latest(self.directory) / "transaction.json")
            if transaction.get("status") != "active":
                self._diagnose("drift monitoring inactive: no active hardening transaction", diagnostics)
                return
            if target["managed_sysctls"] != transaction.get("target"):
                raise ValueError("baseline conflicts with active hardening transaction")
        except FileNotFoundError:
            self._diagnose("drift monitoring unavailable: harden and save a baseline first", diagnostics)
            return
        values, unavailable = host.read_sysctls(self.root)
        changes, restored, errors = {}, [], []
        for key, wanted in target["managed_sysctls"].items():
            actual = values.get(key)
            if actual is None:
                self._diagnose(f"sysctl read unavailable: {key}: {unavailable.get(key)}", diagnostics)
                continue
            if actual != wanted:
                changes[key] = {"expected": wanted, "actual": actual}
                try:
                    host.set_sysctl(self.root, key, wanted)
                    restored.append(key)
                except host.ERRORS as exc:
                    errors.append(str(exc))
        loaded = set(host.loaded_modules(self.root))
        blocked = set(target["blacklisted_modules"])
        new_modules = sorted((loaded - set(target["modules"])) & blocked)
        missing_blacklist = sorted(blocked - set(host.blacklisted_modules(self.root)))
        if changes or new_modules or missing_blacklist:
            self._emit({"kind": "kernel_drift", "title": "커널 하드닝 기준선 변경 감지",
                        "sysctls": changes, "loaded_blacklisted_modules": new_modules,
                        "removed_blacklist": missing_blacklist, "restored": restored, "errors": errors}, events)

    def tick(self, *, force: bool = True) -> dict:
        if result := host.unsupported():
            return result
        events, diagnostics = [], []
        try:
            harden.require_root()
            with host.locked(self.directory):
                saved = self.directory / "monitor.json"
                if saved.exists():
                    state = host.load_json(saved)
                    if (not isinstance(state.get("seen"), dict) or not isinstance(state.get("diagnosed"), list)
                            or any(not isinstance(ts, (int, float)) for ts in state["seen"].values())):
                        raise ValueError("invalid kernel monitor state")
                    self.state = state
                now = time.monotonic()
                if force or now >= self.next_drift:
                    self._drift(events, diagnostics)
                    self.next_drift = now + self.interval
                capability = self.current.get("audit_capability", "degraded")
                if force or now >= self.next_health:
                    try:
                        # Establish EOF before installing rules so setup events are retained.
                        if self.tail is None:
                            self.tail = AuditTail(host.path(self.root, "/var/log/audit/audit.log"), self.state.get("cursor"))
                        ensure_rules()
                        capability = "available"
                    except host.ERRORS as exc:
                        capability = "degraded"
                        self._diagnose("monitor capability degraded: auditd/syscall coverage unavailable", diagnostics)
                        self.current["capability_reason"] = str(exc)
                    self.next_health = now + 30
                if self.tail is not None:
                    try:
                        for line in self.tail.poll():
                            if event := parse_audit_line(line):
                                event["title"] = ("비특권 고위험 syscall 감지" if event["kind"] == "kernel_high_risk_syscall"
                                                  else "허용되지 않은 root 권한 전환 감지")
                                self._emit(event, events)
                        self.state["cursor"] = self.tail.cursor()
                    except host.ERRORS as exc:
                        capability = "degraded"
                        self._diagnose("monitor capability degraded: auditd/syscall coverage unavailable", diagnostics)
                        self.current["capability_reason"] = str(exc)
                        self.tail.close()
                        self.tail = None
                self.current.update(status="ok", audit_capability=capability, events=events,
                                    diagnostics=diagnostics, last_check=time.time())
                self.state["last_status"] = self.current
                host.save_json(saved, self.state)
        except host.ERRORS as exc:
            self.current.update(status="error", message=str(exc), events=events, diagnostics=diagnostics)
        return dict(self.current)

    def once(self) -> dict:
        try:
            return self.tick()
        finally:
            self.close()

    def close(self):
        if self.tail:
            self.tail.close()
            self.tail = None

    def loop(self, callback=None):
        if result := host.unsupported():
            if callback:
                callback(result)
            return result
        self.current["running"] = True
        try:
            while not self.stop_event.is_set():
                result = self.tick(force=False)
                if callback and (result.get("events") or result.get("diagnostics") or result["status"] != "ok"):
                    callback(result)
                self.stop_event.wait(1)
        finally:
            self.current["running"] = False
            self.close()

    def start(self):
        if host.unsupported() or (self.thread and self.thread.is_alive()):
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self.loop, name="kernel-monitor", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=15)

    def status(self) -> dict:
        if result := host.unsupported():
            return result
        result = dict(self.current)
        result["running"] = bool(self.thread and self.thread.is_alive())
        try:
            saved = host.load_json(self.directory / "monitor.json").get("last_status", {})
            return {"last_check_result": saved, **result}
        except FileNotFoundError:
            return result
        except host.ERRORS as exc:
            return {**result, "status": "error", "message": str(exc)}
