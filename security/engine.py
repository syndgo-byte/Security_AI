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


def run(targets: dict[str, Path], only: str | None = None, offline: bool = False) -> dict:
    chosen = {k: v for k, v in targets.items() if not only or k == only}
    con = store.connect()
    scan_id = store.start_scan(con, list(chosen), offline)
    result = {}
    for service, root in chosen.items():
        findings = scan_service(service, root, offline)
        store.save_findings(con, scan_id, service, findings)
        counts = {s: 0 for s in ("critical", "high", "medium", "low")}
        for f in findings:
            counts[f.severity] += 1
        result[service] = counts
        report_to_hub(service, counts)
    store.finish_scan(con, scan_id, result)
    return {"scan_id": scan_id, "services": result}
