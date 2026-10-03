"""보안 진단 API (기본 포트 8200). 허브 웹의 '보안 진단' 탭이 /security 프록시로 호출한다."""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query

from . import alerts, engine, kernel, manifest, remediate, store
from .targets import load_sites, load_targets
from .watch import Watcher

watcher = Watcher()
verifier = ThreadPoolExecutor(max_workers=1, thread_name_prefix="verify")   # 설치 · 테스트가 무거워 한 번에 하나씩


@asynccontextmanager
async def lifespan(_app):
    con = store.connect()   # 서버가 검증 도중 꺼졌으면 running 에 갇힌 것을 풀어 준다
    con.execute("update findings set verify=null where verify like '%\"state\": \"running\"%'")
    con.commit()
    if os.environ.get("SECURITY_WATCH") == "1":   # 허브와 같이 띄울 때 상시 진단 켜기
        watcher.start()
    yield
    watcher.stop()
    verifier.shutdown(wait=False, cancel_futures=True)


app = FastAPI(title="Security", version=manifest()["version"], lifespan=lifespan)


def _con():
    return store.connect()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/manifest")
def get_manifest():
    return manifest()


@app.get("/kernel/audit")
def kernel_audit():
    return kernel.audit(kernel.Host())


@app.post("/kernel/harden")
def kernel_harden(dry_run: bool = True, userns: bool | None = None):
    return kernel.harden(kernel.Host(), dry_run=dry_run, userns=userns)


@app.post("/kernel/rollback")
def kernel_rollback():
    return kernel.rollback(kernel.Host())


@app.get("/kernel/baseline")
def kernel_baseline():
    result = kernel.load_baseline(kernel.Host())
    if result is None:
        raise HTTPException(404, "베이스라인 없음 — harden 먼저")
    return result


@app.post("/kernel/monitor")
def kernel_monitor():
    con = _con()
    try:
        return kernel.monitor_once(kernel.Host(), con)
    finally:
        con.close()


@app.get("/targets")
def targets():
    return {"code": {k: str(v) for k, v in load_targets().items()}, "web": load_sites()}


@app.post("/web/scan")
def web_scan(service: str | None = None):
    s = load_sites()
    if service and service not in s:
        raise HTTPException(404, f"웹 주소가 없는 서비스: {service}")
    return engine.run_web(s, service)


@app.get("/escalations")
def escalations(service: str | None = None):
    """사람에게 넘긴 항목 (심각도 높음 이상, 열린 것)."""
    return store.list_findings(_con(), service=service, status="open", action="escalate")


@app.post("/auto-fix")
def auto_fix(service: str | None = None):
    """정책상 간단한 항목의 조치안 준비 (기본: 허브 관리용 diff, 서비스 파일은 안 건드림)."""
    t = load_targets()
    return _act(remediate.auto_remediate, _con(), {k: v for k, v in t.items() if not service or k == service})


@app.get("/patches")
def patches(service: str | None = None):
    """허브가 가져갈 조치안 (상태 ready). 항목마다 diff 포함."""
    con = _con()
    rows = con.execute("select * from findings where status='ready'" + (" and service=?" if service else ""),
                       (service,) if service else ()).fetchall()
    return [{**store.to_dict(r), "patch": r["patch"]} for r in rows]


@app.post("/findings/{fid}/approve")
def approve(fid: str, approved_by: str = Query(..., min_length=1)):
    """승인한 수정안을 조치안으로 (허브가 관리). 서비스 파일은 안 건드림."""
    return _act(remediate.approve, _con(), load_targets(), fid, approved_by)


@app.post("/findings/{fid}/cancel")
def cancel(fid: str):
    return _act(remediate.cancel, _con(), fid)


@app.post("/findings/{fid}/delivered")
def delivered(fid: str, by: str = Query(..., min_length=1)):
    """허브가 조치안을 서비스에 반영했음을 알림."""
    return _act(remediate.mark_delivered, _con(), fid, by)


@app.post("/findings/{fid}/verify")
def verify(fid: str):
    """조치안 동작 검증 시작 (임시 복사본에서 설치 · 테스트 · 기동). 결과는 /findings/{id} 의 verify 로 확인."""
    root, edits = _act(remediate.start_verify, _con(), load_targets(), fid)
    verifier.submit(lambda: remediate.run_verify(store.connect(), root, fid, edits))
    return {"id": fid, "verify": {"state": "running"}}


@app.get("/events")
def events(service: str | None = None, limit: int = Query(50, ge=1, le=500)):
    """조치 알람 (검증 통과 · 실패, 적용, 되돌림). 허브 모니터링에도 같이 보고된다 (HUB_URL)."""
    return alerts.recent(_con(), service, limit)


@app.get("/watch")
def watch_status():
    return {"running": os.environ.get("SECURITY_WATCH") == "1", "jobs": watcher.status}


@app.post("/scan")
def scan(service: str | None = None, offline: bool = False):
    t = load_targets()
    if service and service not in t:
        raise HTTPException(404, f"대상에 없는 서비스: {service}")
    return engine.run(t, service, offline)


@app.get("/findings")
def findings(service: str | None = None, category: str | None = None, severity: str | None = None,
             status: str | None = None, action: str | None = None):
    return store.list_findings(_con(), service=service, category=category, severity=severity, status=status,
                               action=action)


@app.get("/findings/{fid}")
def finding(fid: str):
    con = _con()
    row = store.get(con, fid)
    if not row:
        raise HTTPException(404, "진단 항목이 없습니다.")
    d = store.to_dict(row)
    d["diff"] = remediate.diff(con, load_targets(), fid)
    return d


def _act(fn, *args):
    try:
        return fn(*args)
    except remediate.RemediationError as e:
        raise HTTPException(409, str(e)) from e


@app.post("/findings/{fid}/apply")
def apply(fid: str, approved_by: str = Query(..., min_length=1)):
    return _act(remediate.apply, _con(), load_targets(), fid, approved_by)


@app.post("/findings/{fid}/rollback")
def rollback(fid: str):
    return _act(remediate.rollback, _con(), fid)


@app.post("/findings/{fid}/dismiss")
def dismiss(fid: str, reason: str = ""):
    return _act(remediate.dismiss, _con(), fid, reason)


@app.get("/summary")
def summary():
    return store.summary(_con())


# ── AI ─────────────────────────────────────────────────────────────
def _ai(fn, *args):
    from .ai.common import ConsentError
    from .ai.providers import AIError
    try:
        return fn(*args)
    except ConsentError as e:
        raise HTTPException(403, str(e)) from e
    except AIError as e:
        raise HTTPException(503, str(e)) from e


def _target_or_404(service: str | None) -> dict:
    t = load_targets()
    if service and service not in t:
        raise HTTPException(404, f"대상에 없는 서비스: {service}")
    return t


@app.get("/ai/status")
def ai_status():
    from .ai import providers
    return providers.status()


@app.post("/ai/intel")
def ai_intel(service: str | None = None, days: int = Query(14, ge=1, le=120)):
    return _ai(engine.run_intel, _target_or_404(service), service, days)


@app.post("/ai/review")
def ai_review(service: str | None = None, allow_code: bool = False, max_files: int = Query(15, ge=1, le=100)):
    return _ai(engine.run_review, _target_or_404(service), service, allow_code, max_files)


@app.post("/ai/triage")
def ai_triage(service: str | None = None, allow_code: bool = False, limit: int = Query(30, ge=1, le=200),
              redo: bool = False):
    from .ai import triage
    return _ai(triage.run, _con(), _target_or_404(service), service, allow_code, limit, redo)
