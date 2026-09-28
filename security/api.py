"""보안 진단 API (기본 포트 8200). 허브 웹의 '보안 진단' 탭이 /security 프록시로 호출한다."""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query

from . import engine, manifest, remediate, store
from .targets import load_targets

app = FastAPI(title="Security", version=manifest()["version"])


def _con():
    return store.connect()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/manifest")
def get_manifest():
    return manifest()


@app.get("/targets")
def targets():
    return {k: str(v) for k, v in load_targets().items()}


@app.post("/scan")
def scan(service: str | None = None, offline: bool = False):
    t = load_targets()
    if service and service not in t:
        raise HTTPException(404, f"대상에 없는 서비스: {service}")
    return engine.run(t, service, offline)


@app.get("/findings")
def findings(service: str | None = None, category: str | None = None, severity: str | None = None,
             status: str | None = None):
    return store.list_findings(_con(), service=service, category=category, severity=severity, status=status)


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
