"""진단 실행 — 대상별로 6개 진단기를 돌리고 저장 · 허브 보고."""
from __future__ import annotations

import os
import urllib.parse
import urllib.request
from pathlib import Path

from . import store
from .scanners import config, deps, hardening, legal, sast, secrets


def scan_service(service: str, root: Path, offline: bool) -> list:
    out = []
    out += sast.scan(service, root)
    out += secrets.scan(service, root)
    out += config.scan(service, root)
    out += hardening.scan(service, root)
    out += legal.scan(service, root)
    out += deps.scan(service, root, offline=offline)
    uniq = {f.id: f for f in out}
    return list(uniq.values())


def report_to_hub(service: str, escalated: list) -> None:
    """이번 진단에 새로 생긴 escalate 항목을 허브 모니터링 이벤트로 넘긴다 (같은 항목은 한 번만)."""
    hub = os.environ.get("HUB_URL")
    if not hub or not escalated:
        return
    crit = sum(r["severity"] == "critical" for r in escalated)
    top = "; ".join(f"{r['title']} ({r['file']}:{r['line']})" for r in escalated[:3])
    q = urllib.parse.urlencode({"event_type": "error", "severity": "critical" if crit else "high",
                                "message": f"[보안] 사람 확인 필요 {len(escalated)}건 — {top}"[:500]})
    try:
        req = urllib.request.Request(f"{hub.rstrip('/')}/monitor/events/{service}?{q}", method="POST")
        urllib.request.urlopen(req, timeout=5).close()
    except OSError:
        pass


def new_escalations(con, scan_id: str, service: str, known: set[str]) -> list:
    from .policy import decide
    rows = con.execute("select * from findings where scan_id=? and service=? and status='open'",
                       (scan_id, service)).fetchall()
    return [r for r in rows if r["id"] not in known and decide(r) == "escalate"]


RULE_CATEGORIES = ("sast", "secrets", "config", "hardening", "legal", "deps")


def _count(findings) -> dict:
    counts = {s: 0 for s in ("critical", "high", "medium", "low")}
    for f in findings:
        counts[f.severity] += 1
    return counts


def _save_all(per_service: dict[str, list], categories: tuple[str, ...], offline: bool = False) -> dict:
    con = store.connect()
    scan_id = store.start_scan(con, list(per_service), offline)
    result = {}
    for service, findings in per_service.items():
        known = {r["id"] for r in con.execute("select id from findings where service=?", (service,))}
        store.save_findings(con, scan_id, service, findings, categories, ("DEPS-CVE",) if offline else ())
        result[service] = _count(findings)
        report_to_hub(service, new_escalations(con, scan_id, service, known))
    store.finish_scan(con, scan_id, result)
    return {"scan_id": scan_id, "services": result}


def run_web(sites: dict[str, list[str]], only: str | None = None) -> dict:
    """웹 가벼운 점검 (헤더 · 쿠키 · CORS · HTTPS · 노출 경로 · 인증서)."""
    from .scanners import web
    per_service, errors = web.scan(sites, only)
    return {**_save_all(per_service, ("web",)), "errors": errors}


def run(targets: dict[str, Path], only: str | None = None, offline: bool = False) -> dict:
    chosen = {k: v for k, v in targets.items() if not only or k == only}
    return _save_all({s: scan_service(s, r, offline) for s, r in chosen.items()}, RULE_CATEGORIES, offline)


def run_intel(targets: dict[str, Path], only: str | None = None, days: int = 14) -> dict:
    """최신 위협 수집 (CISA KEV · NVD → AI 가 서비스 의존성과 대조)."""
    from .ai import intel
    per_service, errors = intel.scan(targets, only, days)
    return {**_save_all(per_service, ("intel",)), "errors": errors}


def run_review(targets: dict[str, Path], only: str | None = None, allow_code: bool = False,
               max_files: int = 15) -> dict:
    """AI 코드 검토 (코드 전송 동의 필요)."""
    from .ai import review
    per_service, errors = {}, []
    for s, r in targets.items():
        if only and s != only:
            continue
        found, errs = review.scan(s, r, allow_code, max_files)
        errors += [f"{s} {e}" for e in errs]
        if found or not errs:   # 모델 호출이 전부 실패했으면 이전 결과를 지우지 않는다
            per_service[s] = found
    return {**_save_all(per_service, ("ai",)), "errors": errors}
