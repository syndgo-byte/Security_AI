"""상시 진단 — 허브에 연결된 서비스는 계속 진단 · 간단한 건 자동 조치, 웹은 가볍게 드문드문.

주기 (분): SECURITY_WATCH_CODE_MIN=30 (코드 · 설정 · 비밀값 · 의존성)
           SECURITY_WATCH_WEB_MIN=360 (웹 가벼운 점검)
           SECURITY_WATCH_INTEL_MIN=1440 (최신 위협 수집, AI 사용)
자동 조치: SECURITY_AUTO_FIX=0 이면 끔. 기본은 조치안(diff)만 준비해 허브가 관리 — 서비스 파일 · git 은 읽기만.
           SECURITY_AUTO_FIX_MODE=branch 면 서비스 저장소에 브랜치 커밋.
"""
from __future__ import annotations

import os
import threading
import time
from datetime import datetime

from . import engine, remediate, store
from .targets import load_sites, load_targets

JOBS = ("code", "web", "intel")
DEFAULT_MIN = {"code": 30, "web": 360, "intel": 1440}


def _minutes(job: str) -> float:
    try:
        return float(os.environ.get(f"SECURITY_WATCH_{job.upper()}_MIN", DEFAULT_MIN[job]))
    except ValueError:
        return DEFAULT_MIN[job]


def _auto_fix_on() -> bool:
    return os.environ.get("SECURITY_AUTO_FIX", "1") != "0"


def run_job(job: str) -> dict:
    if job == "code":
        targets = load_targets()
        r = engine.run(targets)
        if _auto_fix_on():
            r["auto_fix"] = remediate.auto_remediate(store.connect(), targets)
        return r
    if job == "web":
        return engine.run_web(load_sites())
    from .ai.providers import AIError
    try:
        return engine.run_intel(load_targets())
    except AIError as e:
        return {"errors": [str(e)]}


class Watcher:
    def __init__(self):
        self.last: dict[str, float] = {}
        self.status: dict[str, dict] = {}
        self._stop = threading.Event()

    def due(self, job: str, now: float) -> bool:
        return now - self.last.get(job, 0) >= _minutes(job) * 60

    def tick(self, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        ran = {}
        for job in JOBS:
            if not self.due(job, now):
                continue
            self.last[job] = now
            try:
                ran[job] = run_job(job)
                self.status[job] = {"at": datetime.now().isoformat(timespec="seconds"), "ok": True,
                                    "errors": ran[job].get("errors", [])}
            except Exception as e:   # 한 작업이 죽어도 감시는 계속
                self.status[job] = {"at": datetime.now().isoformat(timespec="seconds"), "ok": False, "errors": [str(e)]}
        return ran

    def loop(self, on_run=None):
        while not self._stop.is_set():
            ran = self.tick()
            if on_run and ran:
                on_run(ran)
            self._stop.wait(30)

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self.loop, name="security-watch", daemon=True)
        t.start()
        return t

    def stop(self):
        self._stop.set()
