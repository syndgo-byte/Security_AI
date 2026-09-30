"""조치안 동작 검증 — 서비스를 임시 폴더에 복사해 수정안을 적용하고 설치 · 테스트 · 기동을 확인한다.

원본 서비스 폴더는 읽기만 한다. 실패하면 수정 전 복사본에서도 같은 단계를 돌려,
원래부터 깨져 있던 것(기존 실패)과 이번 수정 때문에 깨진 것(새 실패)을 나눈다.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .findings import Edit
from .store import now

IGNORE = shutil.ignore_patterns(".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", "dist",
                                "build", ".worktrees", ".backups", "*.pyc")
ENTRY = ("app.py", "main.py", "server.py")   # 기동 확인: import 만 해 본다 (서버는 띄우지 않음)
FAIL_RX = re.compile(r"^(?:FAILED|ERROR) (\S+)", re.M)
LOG_TAIL = 3000


def _timeout(name: str, default: int) -> int:
    return int(os.environ.get(f"SECURITY_VERIFY_{name}_SEC", default))


def _rmtree(path: Path) -> None:
    def onerror(fn, p, _exc):   # Windows 읽기 전용 파일 (git 객체 등)
        os.chmod(p, stat.S_IWRITE)
        fn(p)
    shutil.rmtree(path, onerror=onerror)


def _run(cmd: list[str], cwd: Path, timeout: int) -> tuple[int, str, float]:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "utf-8", "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
    start = time.monotonic()
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, env=env)
        return r.returncode, (r.stdout + r.stderr), time.monotonic() - start
    except subprocess.TimeoutExpired as e:
        out = "".join(s for s in (e.stdout, e.stderr) if isinstance(s, str))
        return -1, out + f"\n시간 초과 ({timeout}초)", time.monotonic() - start


def _step(name: str, code: int, log: str, secs: float, ok: bool | None = None, note: str = "") -> dict:
    return {"name": name, "ok": code == 0 if ok is None else ok, "seconds": round(secs, 1),
            "note": note, "log": log[-LOG_TAIL:]}


def _python_in(venv: Path) -> str:
    return str(venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))


def _requirements(work: Path, edits: list[Edit]) -> list[str]:
    files = {"requirements.txt"} if (work / "requirements.txt").exists() else set()
    files |= {e.file for e in edits if Path(e.file).name.startswith("requirements") and e.file.endswith(".txt")}
    return sorted(files)


def _tests(py: str, work: Path) -> tuple[dict, set[str]]:
    code, log, secs = _run([py, "-m", "pytest", "-q", "-rfE", "-p", "no:cacheprovider", "tests"], work,
                           _timeout("TEST", 900))
    if code == 5:   # 수집된 테스트 없음
        return _step("테스트", 0, log, secs, note="테스트 없음"), set()
    return _step("테스트", code, log, secs), set(FAIL_RX.findall(log))


def _boot(py: str, work: Path) -> dict | None:
    entry = next((n for n in ENTRY if (work / n).exists()), None)
    if not entry:
        return None
    mod = entry[:-3]
    code, log, secs = _run([py, "-c", f"import sys; sys.path.insert(0, '.'); import {mod}"], work, _timeout("BOOT", 120))
    return _step(f"기동 ({entry} import)", code, log, secs)


def run(root: Path, edits: list[Edit]) -> dict:
    """임시 복사본에서 수정안을 검증한다. 반환: {ok, state, steps, at}. 원본은 건드리지 않는다."""
    from .remediate import write_edits
    tmp = Path(tempfile.mkdtemp(prefix="secverify-"))
    steps: list[dict] = []
    try:
        work = tmp / "patched"
        shutil.copytree(root, work, ignore=IGNORE)
        try:
            write_edits(work, edits)
        except ValueError as e:
            return {"ok": False, "state": "failed", "at": now(),
                    "steps": [_step("수정안 적용", 1, str(e), 0)]}
        steps.append(_step("수정안 적용", 0, "", 0))

        py = sys.executable
        reqs = _requirements(work, edits)
        if reqs:   # 지금 쓰는 전역 패키지 위에 수정된 요구사항만 덧설치 — 서비스의 실제 실행 환경과 가깝게
            venv = tmp / "venv"
            code, log, secs = _run([sys.executable, "-m", "venv", "--system-site-packages", str(venv)], tmp, 120)
            if code != 0:
                steps.append(_step("설치", code, log, secs, note="가상환경 생성 실패"))
                return {"ok": False, "state": "failed", "steps": steps, "at": now()}
            py = _python_in(venv)
            cmd = [py, "-m", "pip", "install", "-q"]
            for r in reqs:
                cmd += ["-r", r]
            code, log, s2 = _run(cmd, work, _timeout("INSTALL", 600))
            steps.append(_step("설치", code, log, secs + s2, note=", ".join(reqs)))
            if code != 0:
                return {"ok": False, "state": "failed", "steps": steps, "at": now()}

        test, failed = _tests(py, work) if (work / "tests").is_dir() else (None, set())
        boot = _boot(py, work)
        if (test and not test["ok"]) or (boot and not boot["ok"]):
            base = tmp / "original"   # 수정 전에도 실패하는지 비교
            shutil.copytree(root, base, ignore=IGNORE)
            if test and not test["ok"]:
                btest, bfailed = _tests(sys.executable, base)
                new = sorted(failed - bfailed)
                if not btest["ok"] and failed and not new:
                    test.update(ok=True, note=f"기존 실패 {len(bfailed)}건 (수정 전에도 실패) · 새 실패 없음")
                elif new:
                    test["note"] = "이번 수정으로 새로 실패: " + ", ".join(new[:10])
            if boot and not boot["ok"]:
                bboot = _boot(sys.executable, base)
                if bboot and not bboot["ok"]:
                    boot.update(ok=True, note="수정 전에도 import 실패 — 이번 수정과 무관")
        steps += [s for s in (test, boot) if s]
        if not test and not boot:
            steps.append(_step("테스트", 0, "", 0, note="tests/ 와 진입 파일이 없어 설치만 확인"))
        ok = all(s["ok"] for s in steps)
        return {"ok": ok, "state": "passed" if ok else "failed", "steps": steps, "at": now()}
    finally:
        _rmtree(tmp)
