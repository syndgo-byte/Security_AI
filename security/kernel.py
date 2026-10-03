"""호스트 커널 하드닝 — 선(先) 조치 → 후(後) 핵심 징후 감시.

audit    : 커널 버전 CVE 노출 · sysctl · 위험 모듈 읽기 전용 점검
harden   : 백업 후 sysctl.d · modprobe.d 설정 작성 + 런타임 적용 (dry_run 기본)
rollback : 마지막 백업으로 원복
baseline : 조치 후 상태 스냅샷 (sysctl 해시 · 모듈 · BPF 프로그램)
monitor  : 저소음 감시 — 설정 drift 복구, 비특권 bpf/io_uring/userns 호출, 미인가 root 전환
/proc · /sys · /dev · /run 은 정해진 파일만 읽고 절대 훑지 않는다.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import ROOT as PKG_ROOT
from .findings import Finding, Fix

SERVICE = "host"
SYSCTL_CONF = "etc/sysctl.d/99-kernel-hardening.conf"
MODPROBE_CONF = "etc/modprobe.d/blacklist-security.conf"
USERNS_KEY = "kernel.unprivileged_userns_clone"
TARGETS = {
    "kernel.unprivileged_bpf_disabled": ("1", "critical", "비특권 eBPF 허용", "일반 유저가 bpf() 로 커널 검증기 취약점을 노릴 수 있습니다."),
    "net.core.bpf_jit_harden": ("2", "medium", "BPF JIT 하드닝 꺼짐", "JIT 스프레이 공격 완화가 꺼져 있습니다."),
    "kernel.io_uring_disabled": ("2", "high", "io_uring 허용", "io_uring 은 최근 커널 권한 상승 취약점의 주요 통로입니다."),
    "kernel.kptr_restrict": ("2", "medium", "커널 포인터 노출", "/proc/kallsyms 등으로 커널 주소가 새어 KASLR 우회에 쓰입니다."),
    "kernel.dmesg_restrict": ("1", "low", "dmesg 비특권 열람 가능", "커널 로그로 주소 · 장치 정보가 샙니다."),
    USERNS_KEY: ("0", "high", "비특권 user namespace 허용", "unshare(CLONE_NEWUSER) 로 netfilter 등 커널 공격면이 열립니다."),
}
BLACKLIST = ("tipc", "sctp", "rds", "dccp", "cramfs", "freevxfs")
CONTAINER_MARKERS = ("run/docker.sock", "var/run/docker.sock", "run/containerd/containerd.sock",
                     "run/podman/podman.sock", "var/lib/kubelet", "etc/kubernetes")
CRED_WHITELIST = {"sudo", "su", "sshd", "login", "systemd", "cron", "crond", "polkitd", "pkexec", "sudo-rs",
                  "systemd-logind", "gdm-session-worker", "lightdm", "sddm-helper", "runuser", "newgrp", "doas"}
AUDIT_KEYS = {"kh_bpf": "bpf()", "kh_iouring": "io_uring_setup()", "kh_userns": "unshare(CLONE_NEWUSER)", "kh_cred": "root 전환"}
AUDIT_RULES = [
    "-a always,exit -F arch=b64 -S bpf -F uid!=0 -k kh_bpf",
    "-a always,exit -F arch=b64 -S io_uring_setup -F uid!=0 -k kh_iouring",
    "-a always,exit -F arch=b64 -S unshare -F a0&0x10000000 -F uid!=0 -k kh_userns",
    "-a always,exit -F arch=b64 -S setuid,setreuid,setresuid -F success=1 -F euid=0 -F auid>=1000 -F auid!=unset -k kh_cred",
]
# (도입 버전, 메인라인 수정 버전, {브랜치: 수정 패치})
CVES = {
    "CVE-2022-0847": ("Dirty Pipe", (5, 8, 0), (5, 16, 11), {(5, 10): 102, (5, 15): 25, (5, 16): 11}),
    "CVE-2024-1086": ("netfilter nf_tables UAF", (3, 15, 0), (6, 8, 0),
                      {(5, 4): 269, (5, 10): 209, (5, 15): 149, (6, 1): 76, (6, 6): 15, (6, 7): 3}),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Host:
    """root 를 바꿔 끼우면 가짜 파일 트리로 테스트할 수 있다. 실제 명령(auditctl · modprobe)은 root == / 일 때만."""

    def __init__(self, root: Path | str = "/", state: Path | str | None = None):
        self.root = Path(root)
        self.state = Path(state) if state else PKG_ROOT / ".backups" / "kernel"
        self.real = str(self.root) in ("/", "\\")

    @property
    def supported(self) -> bool:
        return not self.real or sys.platform.startswith("linux")

    def p(self, rel: str) -> Path:
        return self.root / rel

    def kernel(self) -> str:
        f = self.p("proc/sys/kernel/osrelease")
        return f.read_text().strip() if f.exists() else ""

    def os_release(self) -> dict:
        f = self.p("etc/os-release")
        if not f.exists():
            return {}
        out = {}
        for ln in f.read_text(errors="replace").splitlines():
            if "=" in ln:
                k, v = ln.split("=", 1)
                out[k.strip()] = v.strip().strip('"')
        return out

    def containers(self) -> list[str]:
        return [m for m in CONTAINER_MARKERS if self.p(m).exists()]

    def _sysctl_path(self, key: str) -> Path:
        return self.p("proc/sys/" + key.replace(".", "/"))

    def sysctl(self, key: str) -> str | None:
        f = self._sysctl_path(key)
        return f.read_text().strip() if f.exists() else None

    def set_sysctl(self, key: str, value: str) -> bool:
        try:
            self._sysctl_path(key).write_text(value + "\n")
            return True
        except OSError:
            return False

    def modules(self) -> list[str]:
        f = self.p("proc/modules")
        return [ln.split()[0] for ln in f.read_text().splitlines() if ln.strip()] if f.exists() else []

    def blacklisted(self) -> set[str]:
        d = self.p("etc/modprobe.d")
        out = set()
        for f in sorted(d.glob("*.conf")) if d.is_dir() else []:
            for ln in f.read_text(errors="replace").splitlines():
                m = re.match(r"\s*(?:blacklist\s+(\S+)|install\s+(\S+)\s+/bin/(?:false|true))", ln)
                if m:
                    out.add(m.group(1) or m.group(2))
        return out

    def bpf_programs(self) -> list:
        if self.real and shutil.which("bpftool"):
            try:
                r = subprocess.run(["bpftool", "prog", "show", "-j"], capture_output=True, text=True, timeout=10)
                return [{"id": x.get("id"), "type": x.get("type"), "name": x.get("name")} for x in json.loads(r.stdout or "[]")]
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
        d = self.p("sys/fs/bpf")
        return sorted(x.name for x in d.iterdir()) if d.is_dir() else []


def _ver(s: str) -> tuple[int, int, int] | None:
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", s)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)) if m else None


def _exposed(v, introduced, mainline, branches) -> bool:
    if v < introduced or v >= mainline:
        return False
    fix = branches.get(v[:2])
    return not (fix is not None and v[2] >= fix)


def _unsupported() -> dict:
    return {"supported": False, "reason": f"리눅스 호스트에서만 동작합니다 (현재 {sys.platform})"}


def _keys(h: Host, userns: bool | None) -> dict[str, str]:
    """적용할 sysctl. 커널에 없는 키는 빼고, 컨테이너가 돌면 userns 차단은 기본 제외."""
    block_userns = (not h.containers()) if userns is None else userns
    return {k: v[0] for k, v in TARGETS.items()
            if h.sysctl(k) is not None and (k != USERNS_KEY or block_userns)}


def audit(h: Host) -> dict:
    if not h.supported:
        return _unsupported()
    kver = h.kernel()
    v = _ver(kver)
    cont = h.containers()
    out: list[Finding] = []
    for cve, (name, intro, main, br) in CVES.items():
        if v and _exposed(v, intro, main, br):
            out.append(Finding(SERVICE, "kernel", f"KERN-{cve}", "high", f"{name} ({cve}) 노출 가능 — 배포판 백포트 확인 필요",
                               "proc/sys/kernel/osrelease", 0, f"커널 {kver} 는 업스트림 기준 취약 범위입니다. "
                               "배포판이 패치를 백포트했는지 확인하고 커널을 업데이트하세요.", kver, Fix("수동 조치: 커널 업데이트")))
    if v and v >= (5, 1, 0) and h.sysctl("kernel.io_uring_disabled") is None:
        out.append(Finding(SERVICE, "kernel", "KERN-IOURING-NOSWITCH", "medium", "io_uring 끄는 sysctl 없음", "", 0,
                           "6.6 미만 커널이라 kernel.io_uring_disabled 가 없습니다. seccomp 로 io_uring_setup 을 막거나 커널을 올리세요.",
                           kver, Fix("수동 조치: seccomp / 커널 업데이트")))
    for key, (want, sev, title, detail) in TARGETS.items():
        cur = h.sysctl(key)
        if cur is None or cur == want:
            continue
        if key == USERNS_KEY and cont:
            out.append(Finding(SERVICE, "kernel", "KERN-USERNS-CONTAINER", "low", "user namespace 허용 (컨테이너 사용 중이라 유지)",
                               "", 0, f"컨테이너 런타임 감지({', '.join(cont)}) — 차단하면 rootless 컨테이너가 깨질 수 있어 제외합니다.",
                               f"{key} = {cur}", Fix("harden --block-userns 로 강제 가능")))
            continue
        out.append(Finding(SERVICE, "kernel", "KERN-SYSCTL-" + key.split(".")[-1].upper(), sev, title,
                           "proc/sys/" + key.replace(".", "/"), 0, detail + f" 권장 {key} = {want}",
                           f"{key} = {cur}", Fix("harden 으로 적용")))
    loaded, black = set(h.modules()), h.blacklisted()
    for mod in BLACKLIST:
        if mod in black:
            continue
        if mod in loaded:
            out.append(Finding(SERVICE, "kernel", "KERN-MOD-LOADED", "medium", f"위험 모듈 {mod} 로드됨", "proc/modules", 0,
                               "사용 중인 모듈이라 자동 차단하지 않습니다. 쓰는 곳이 없으면 언로드 후 블랙리스트하세요.",
                               mod, Fix("수동 조치: 사용처 확인 후 modprobe -r")))
        else:
            out.append(Finding(SERVICE, "kernel", "KERN-MOD-BLACKLIST", "low", f"미사용 위험 모듈 {mod} 미차단", MODPROBE_CONF, 0,
                               "자동 로드로 공격면이 열릴 수 있습니다.", mod, Fix("harden 으로 블랙리스트")))
    return {"supported": True, "kernel": kver, "os": h.os_release().get("PRETTY_NAME", ""), "containers": cont,
            "findings": [f.to_dict() for f in out]}


def _plan(h: Host, userns: bool | None) -> dict:
    keys = _keys(h, userns)
    loaded = set(h.modules())
    mods = [m for m in BLACKLIST if m not in loaded]
    sysctl_txt = "# kernel hardening (security ops)\n" + "".join(f"{k} = {v}\n" for k, v in keys.items())
    mod_txt = "# kernel hardening (security ops)\n" + "".join(f"blacklist {m}\ninstall {m} /bin/false\n" for m in mods)
    return {"sysctl": keys, "modules": mods, "skipped_loaded": sorted(loaded & set(BLACKLIST)),
            "files": {SYSCTL_CONF: sysctl_txt, MODPROBE_CONF: mod_txt}}


def _diff(h: Host, files: dict[str, str]) -> str:
    out = []
    for rel, new in files.items():
        f = h.p(rel)
        old = f.read_text().splitlines() if f.exists() else []
        out.extend(difflib.unified_diff(old, new.splitlines(), f"a/{rel}", f"b/{rel}", lineterm=""))
    return "\n".join(out)


def harden(h: Host, dry_run: bool = True, userns: bool | None = None) -> dict:
    if not h.supported:
        return _unsupported()
    plan = _plan(h, userns)
    runtime = {k: h.sysctl(k) for k in plan["sysctl"] if h.sysctl(k) != plan["sysctl"][k]}
    result = {"supported": True, "dry_run": dry_run, "sysctl": plan["sysctl"], "runtime_changes": runtime,
              "modules": plan["modules"], "skipped_loaded": plan["skipped_loaded"], "diff": _diff(h, plan["files"])}
    if dry_run:
        return result
    bdir = h.state / datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    bdir.mkdir(parents=True)
    saved = {}
    for rel, content in plan["files"].items():
        f = h.p(rel)
        saved[rel] = f.read_text() if f.exists() else None
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content)
    (bdir / "backup.json").write_text(json.dumps({"at": _now(), "files": saved, "runtime": runtime}, ensure_ascii=False, indent=1))
    result["failed"] = [k for k, v in plan["sysctl"].items() if k in runtime and not h.set_sysctl(k, v)]
    result["backup"] = str(bdir)
    result["baseline"] = baseline(h)
    return result


def rollback(h: Host) -> dict:
    if not h.supported:
        return _unsupported()
    dirs = sorted(d for d in h.state.glob("*") if (d / "backup.json").exists()) if h.state.is_dir() else []
    if not dirs:
        return {"supported": True, "ok": False, "reason": "백업 없음"}
    data = json.loads((dirs[-1] / "backup.json").read_text())
    for rel, content in data["files"].items():
        f = h.p(rel)
        if content is None:
            f.unlink(missing_ok=True)
        else:
            f.write_text(content)
    restored = {k: v for k, v in data["runtime"].items() if v is not None and h.set_sysctl(k, v)}
    (h.state / "baseline.json").unlink(missing_ok=True)
    (dirs[-1] / "backup.json").rename(dirs[-1] / "backup.restored.json")
    return {"supported": True, "ok": True, "backup": str(dirs[-1]), "runtime_restored": restored}


def baseline(h: Host) -> dict:
    conf = h.p(SYSCTL_CONF)
    keys = {}
    if conf.exists():
        for ln in conf.read_text().splitlines():
            if "=" in ln and not ln.lstrip().startswith("#"):
                k, v = ln.split("=", 1)
                keys[k.strip()] = v.strip()
    snap = {"at": _now(), "kernel": h.kernel(), "sysctl": keys,
            "sysctl_sha256": hashlib.sha256(json.dumps(keys, sort_keys=True).encode()).hexdigest(),
            "blacklist": sorted(h.blacklisted() & set(BLACKLIST)), "modules": sorted(h.modules()), "bpf": h.bpf_programs()}
    h.state.mkdir(parents=True, exist_ok=True)
    (h.state / "baseline.json").write_text(json.dumps(snap, ensure_ascii=False, indent=1))
    return snap


def load_baseline(h: Host) -> dict | None:
    f = h.state / "baseline.json"
    return json.loads(f.read_text()) if f.exists() else None


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


AUDIT_FIELD = re.compile(r'(\w+)=("[^"]*"|\S+)')


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
        from . import alerts
        for e in events:
            alerts.emit(con, SERVICE, "kernel." + e["kind"], e["level"], e["title"], e["detail"])
    return {"supported": True, "ok": True, "at": _now(), "events": events}
