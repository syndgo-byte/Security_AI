"""Low-noise sysctl drift and auditd event monitoring."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from .baseline import load_baseline
from .host import SERVICE, Host, _now, _unsupported

CRED_WHITELIST = {"sudo", "su", "sshd", "login", "systemd", "cron", "crond", "polkitd", "pkexec", "sudo-rs",
                  "systemd-logind", "gdm-session-worker", "lightdm", "sddm-helper", "runuser", "newgrp", "doas"}
AUDIT_KEYS = {"kh_bpf": "bpf()", "kh_iouring": "io_uring_setup()", "kh_userns": "unshare(CLONE_NEWUSER)", "kh_cred": "root 전환"}
AUDIT_RULES = [
    "-a always,exit -F arch=b64 -S bpf -F uid!=0 -k kh_bpf",
    "-a always,exit -F arch=b64 -S io_uring_setup -F uid!=0 -k kh_iouring",
    "-a always,exit -F arch=b64 -S unshare -F a0&0x10000000 -F uid!=0 -k kh_userns",
    "-a always,exit -F arch=b64 -S setuid,setreuid,setresuid -F success=1 -F euid=0 -F auid>=1000 -F auid!=unset -k kh_cred",
]
AUDIT_FIELD = re.compile(r'(\w+)=("[^"]*"|\S+)')


def check_drift(h: Host, restore: bool = True) -> list[dict]:
    base = load_baseline(h)
    if not base:
        return []
    events = []
    for key, want in base["sysctl"].items():
        cur = h.sysctl(key)
        if cur is not None and cur != want:
            fixed = restore and h.set_sysctl(key, want)
            events.append({"kind": "drift", "level": "high", "title": f"sysctl 변경 감지: {key}",
                           "detail": f"{cur} → 기준 {want}" + (" (자동 복구)" if fixed else " (복구 실패)")})
    loaded = set(h.modules())
    for mod in base["blacklist"]:
        if mod in loaded:
            removed = False
            if restore and h.real and shutil.which("modprobe"):
                removed = subprocess.run(["modprobe", "-r", mod], capture_output=True).returncode == 0
            events.append({"kind": "module", "level": "critical", "title": f"차단 모듈 로드됨: {mod}",
                           "detail": "블랙리스트 우회 로드(init_module/finit_module)" + (" — 언로드함" if removed else " — 수동 확인 필요")})
    return events


def parse_audit(lines) -> list[dict]:
    events, seen = [], set()
    for ln in lines:
        if not ln.startswith("type=SYSCALL"):
            continue
        f = {k: v.strip('"') for k, v in AUDIT_FIELD.findall(ln)}
        key = f.get("key", "")
        if key not in AUDIT_KEYS:
            continue
        exe = f.get("exe", "?")
        if key == "kh_cred":
            if os.path.basename(exe) in CRED_WHITELIST:
                continue
            title = f"미인가 root 전환: {exe}"
        else:
            if f.get("uid") == "0":
                continue
            title = f"비특권 {AUDIT_KEYS[key]} 호출: {exe}"
        sig = (key, exe, f.get("uid"))
        if sig in seen:
            continue
        seen.add(sig)
        events.append({"kind": key, "level": "critical" if key == "kh_cred" else "high", "title": title,
                       "detail": f"uid={f.get('uid')} euid={f.get('euid')} auid={f.get('auid')} pid={f.get('pid')} comm={f.get('comm')}"})
    return events


def read_audit_log(h: Host) -> list[dict]:
    """마지막으로 읽은 위치부터만 읽는다. 로그가 교체(inode 변경 · 크기 감소)되면 처음부터."""
    log = h.p("var/log/audit/audit.log")
    if not log.exists():
        return []
    pos_f = h.state / "audit_pos.json"
    st = log.stat()
    pos = json.loads(pos_f.read_text()) if pos_f.exists() else {}
    off = pos.get("offset", 0) if pos.get("inode") == st.st_ino and pos.get("offset", 0) <= st.st_size else 0
    with log.open("r", errors="replace") as fh:
        fh.seek(off)
        lines = fh.readlines()
        off = fh.tell()
    h.state.mkdir(parents=True, exist_ok=True)
    pos_f.write_text(json.dumps({"inode": st.st_ino, "offset": off}))
    return parse_audit(lines)


def install_audit_rules(h: Host) -> dict:
    if not (h.real and shutil.which("auditctl")):
        return {"ok": False, "reason": "auditd 없음 — 시스템콜 · 권한 상승 감시는 비활성 (drift 감시만 동작)"}
    current = subprocess.run(["auditctl", "-l"], capture_output=True, text=True).stdout
    errors = []
    for rule in AUDIT_RULES:
        if rule.split("-k ")[1] in current:
            continue
        r = subprocess.run(["auditctl", *rule.split()], capture_output=True, text=True)
        if r.returncode:
            errors.append(f"{rule}: {r.stderr.strip()}")
    return {"ok": not errors, "errors": errors}


def monitor_once(h: Host, con=None, restore: bool = True) -> dict:
    if not h.supported:
        return _unsupported()
    if not load_baseline(h):
        return {"supported": True, "ok": False, "reason": "베이스라인 없음 — harden 먼저"}
    events = check_drift(h, restore) + read_audit_log(h)
    if events and con is not None:
        from .. import alerts
        for e in events:
            alerts.emit(con, SERVICE, "kernel." + e["kind"], e["level"], e["title"], e["detail"])
    return {"supported": True, "ok": True, "at": _now(), "events": events}


def simulate_threat(h: Host, kind: str = "drift_sysctl") -> dict:
    """Write synthetic drift or audit events only to a fake host."""
    if h.real or h.root.resolve() == Path(h.root.resolve().anchor):
        return {"ok": False, "reason": "sandbox host required"}
    if kind == "drift_sysctl":
        return {"ok": h.set_sysctl("kernel.kptr_restrict", "0"), "kind": kind}
    if kind not in AUDIT_KEYS:
        return {"ok": False, "reason": f"unknown simulation: {kind}"}
    log = h.p("var/log/audit/audit.log")
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as stream:
        stream.write(f'type=SYSCALL msg=audit(0:1): uid=1000 euid=0 auid=1000 pid=42 '
                     f'comm="sandbox" exe="/tmp/sandbox" key="{kind}"\n')
    return {"ok": True, "kind": kind}
