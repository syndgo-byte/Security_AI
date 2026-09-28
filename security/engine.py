"""진단 실행 — 대상별로 4개 진단기를 돌리고 저장 · 허브 보고."""
from __future__ import annotations

import os
import urllib.parse
import urllib.request
from pathlib import Path

from . import store
from .scanners import config, deps, sast, secrets


def scan_service(service: str, root: Path, offline: bool) -> list:
    out = []
    out += sast.scan(service, root)
    out += secrets.scan(service, root)
    out += config.scan(service, root)
    out += deps.scan(service, root, offline=offline)
    uniq = {f.id: f for f in out}
    return list(uniq.values())


def report_to_hub(service: str, counts: dict) -> None:
    hub = os.environ.get("HUB_URL")
    crit, high = counts.get("critical", 0), counts.get("high", 0)
    if not hub or not (crit or high):
        return
    q = urllib.parse.urlencode({"event_type": "error", "severity": "critical" if crit else "high",
                                "message": f"[보안] 심각 {crit} · 높음 {high}"})
    try:
        req = urllib.request.Request(f"{hub.rstrip('/')}/monitor/events/{service}?{q}", method="POST")
        urllib.request.urlopen(req, timeout=5).close()
    except OSError:
        pass


RULE_CATEGORIES = ("sast", "secrets", "config", "deps")


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
        store.save_findings(con, scan_id, service, findings, categories)
        result[service] = _count(findings)
        report_to_hub(service, result[service])
    store.finish_scan(con, scan_id, result)
    return {"scan_id": scan_id, "services": result}


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
