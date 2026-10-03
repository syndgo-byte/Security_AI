"""Bounded host reads and injectable filesystem roots."""
from __future__ import annotations

import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .. import ROOT

SYSCTL_FILE = "/etc/sysctl.d/99-kernel-hardening.conf"
MODULE_FILE = "/etc/modprobe.d/blacklist-security.conf"
BPF_KEY = "kernel.unprivileged_bpf_disabled"
USERNS_KEY = "kernel.unprivileged_userns_clone"
TARGETS = {
    BPF_KEY: "1", "net.core.bpf_jit_harden": "2",
    "kernel.io_uring_disabled": "2", "kernel.kptr_restrict": "2",
    "kernel.dmesg_restrict": "1", USERNS_KEY: "0",
}
MODULES = ("tipc", "sctp", "rds", "dccp", "cramfs", "freevxfs")
SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


def unsupported() -> dict | None:
    if platform.system() != "Linux":
        return {"status": "unsupported", "message": "unsupported platform: Linux host required",
                "platform": platform.system()}
    return None


def path(root: Path, name: str) -> Path:
    return Path(root) / name.lstrip("/")


def state_dir(root: Path, backup_dir: Path | None = None) -> Path:
    if backup_dir is not None:
        return Path(backup_dir)
    return (ROOT if Path(root) == Path("/") else Path(root)) / ".backups" / "kernel"


def run(*args: str) -> str:
    # Do not run privileged commands from a user-controlled PATH/current directory.
    executable = shutil.which(args[0], path=SYSTEM_PATH)
    if executable is None:
        raise OSError(f"required command unavailable: {args[0]}")
    result = subprocess.run([executable, *args[1:]], capture_output=True, text=True,
                            timeout=10, check=True, env={"PATH": SYSTEM_PATH, "LC_ALL": "C"})
    return result.stdout.strip()


def parse_version(release: str) -> tuple[int, int, int] | None:
    match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", release)
    return tuple(int(v or 0) for v in match.groups()) if match else None


def parse_os(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and re.fullmatch(r"[A-Z_0-9]+", key):
            try:
                result[key] = " ".join(shlex.split(value, comments=True))
            except ValueError:
                result[key] = value.strip()
    return result


def detect_runtimes(root: Path = Path("/")) -> list[str]:
    found = set()
    sockets = {
        "docker": ("/run/docker.sock", "/var/run/docker.sock"),
        "containerd": ("/run/containerd/containerd.sock",),
        "kubelet": ("/var/lib/kubelet", "/run/kubelet.sock"),
        "podman": ("/run/podman/podman.sock",),
        "container": ("/.dockerenv", "/run/.containerenv"),
    }
    for name, paths in sockets.items():
        if any(path(root, p).exists() for p in paths):
            found.add(name)
    names = {"dockerd": "docker", "docker": "docker", "containerd": "containerd",
             "kubelet": "kubelet", "podman": "podman", "conmon": "podman"}
    # One level of PID directories, only comm. Never recursively walk proc/sys/run.
    for entry in path(root, "/proc").iterdir():
        if entry.name.isdecimal() and not entry.is_symlink():
            try:
                name = (entry / "comm").read_text().strip()
                if name in names:
                    found.add(names[name])
            except (FileNotFoundError, ProcessLookupError):
                pass  # Process exited during the bounded read.
    return sorted(found)


def read_sysctls(root: Path = Path("/")) -> tuple[dict, dict]:
    values, unavailable = {}, {}
    for key in TARGETS:
        try:
            values[key] = path(root, "/proc/sys/" + key.replace(".", "/")).read_text().strip()
        except OSError as exc:
            unavailable[key] = str(exc)
    return values, unavailable


def loaded_modules(root: Path = Path("/")) -> list[str]:
    return sorted({line.split()[0] for line in path(root, "/proc/modules").read_text().splitlines()
                   if line.strip()})


def blacklisted_modules(root: Path = Path("/")) -> list[str]:
    found = set()
    # modprobe configuration precedence: first directory wins for identical basenames.
    seen = set()
    for directory in ("/etc/modprobe.d", "/run/modprobe.d", "/usr/local/lib/modprobe.d",
                      "/usr/lib/modprobe.d", "/lib/modprobe.d"):
        for conf in sorted(path(root, directory).glob("*.conf")):
            if conf.name in seen:
                continue
            seen.add(conf.name)
            for line in conf.read_text().splitlines():
                fields = line.split("#", 1)[0].split()
                if len(fields) >= 2 and fields[0] == "blacklist":
                    found.add(fields[1].replace("-", "_"))
    return sorted(found)


def inspect(root: Path = Path("/")) -> dict:
    if result := unsupported():
        return result
    release = run("uname", "-r")
    values, unavailable = read_sysctls(root)
    return {"status": "ok", "kernel": release, "version": parse_version(release),
            "os": parse_os(path(root, "/etc/os-release").read_text()),
            "runtimes": detect_runtimes(root), "sysctls": values, "unavailable": unavailable,
            "modules": loaded_modules(root), "blacklisted_modules": blacklisted_modules(root)}


def no_symlinks(target: Path) -> None:
    for part in (target.absolute(), *target.absolute().parents):
        if part.is_symlink():
            raise OSError(f"refusing symlink: {part}")


def atomic_write(target: Path, data: bytes, mode: int = 0o600) -> None:
    no_symlinks(target)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".kernel-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)


def save_json(target: Path, value: dict) -> None:
    atomic_write(target, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def load_json(target: Path) -> dict:
    no_symlinks(target)
    if target.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("kernel state file too large")
    result = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(result, dict):
        raise ValueError("invalid kernel state")
    return result


@contextmanager
def locked(directory: Path):
    no_symlinks(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = directory / "lock"
    no_symlinks(lock)
    # flock is released even after a crash; fake-root tests also run on Windows.
    with lock.open("a+b") as stream:
        if os.name == "posix":
            import fcntl
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        else:
            import msvcrt
            stream.write(b"\0")
            stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        try:
            yield
        finally:
            if os.name == "posix":
                fcntl.flock(stream, fcntl.LOCK_UN)
            else:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


def set_sysctl(root: Path, key: str, value: str) -> None:
    if key not in TARGETS or value not in {"0", "1", "2"}:
        raise ValueError("invalid managed sysctl")
    run("sysctl", "-w", f"{key}={value}")
    actual = path(root, "/proc/sys/" + key.replace(".", "/")).read_text().strip()
    if actual != value:
        raise OSError(f"sysctl verification failed: {key}: expected {value}, got {actual}")


ERRORS = (OSError, ValueError, subprocess.SubprocessError)
