"""Host reads and injectable real or sandbox filesystem roots."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from .. import ROOT as PKG_ROOT

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


def state_dir(root: Path, backup_dir: Path | None = None) -> Path:
    if backup_dir is not None:
        return Path(backup_dir)
    return (PKG_ROOT if Path(root) == Path("/") else Path(root)) / ".backups" / "kernel"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Host:
    """root 를 바꿔 끼우면 가짜 파일 트리로 테스트할 수 있다. 실제 명령(auditctl · modprobe)은 root == / 일 때만."""

    def __init__(self, root: Path | str = "/", state: Path | str | None = None):
        self.root = Path(root)
        self.state = Path(state) if state else state_dir(self.root)
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


def _unsupported() -> dict:
    return {"supported": False, "reason": f"리눅스 호스트에서만 동작합니다 (현재 {sys.platform})"}


def sandbox_host(root: Path | str | None = None) -> Host:
    """Initialize a persistent fake Linux host without resetting existing state."""
    root = Path(root) if root is not None else PKG_ROOT / ".backups" / "kernel-sandbox"
    h = Host(root.resolve())
    if h.real or h.root == Path(h.root.anchor):
        raise ValueError("sandbox root must not be the filesystem root")
    files = {
        "proc/sys/kernel/osrelease": "5.10.50\n",
        "etc/os-release": 'ID=sandbox\nPRETTY_NAME="Sandbox Linux"\n',
        "proc/modules": "sctp 1 0 - Live 0x0\n",
    }
    for key in TARGETS:
        files["proc/sys/" + key.replace(".", "/")] = "1\n" if key == USERNS_KEY else "0\n"
    for rel, content in files.items():
        path = h.p(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with path.open("x", encoding="utf-8") as stream:
                stream.write(content)
        except FileExistsError:
            pass
    return h
