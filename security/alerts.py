"""조치 알람 — 서비스별로 남기고 허브 모니터링(/monitor/events)에 보고한다.

허브는 같은 서비스의 같은 메시지를 5분 안에 다시 받으면 count 만 올리므로, 반복 알람이 쌓여도 한 줄로 합쳐진다.
"""
from __future__ import annotations

import os
import urllib.parse
import urllib.request
import uuid

from .store import now

# kind: verify_passed · verify_failed · applied · apply_failed · rolled_back
HUB_TYPE = {"verify_failed": "error", "apply_failed": "error"}   # 나머지는 변경 기록(change)


def emit(con, service: str, kind: str, level: str, title: str, detail: str = "", finding_id: str | None = None) -> dict:
    ev = {"id": uuid.uuid4().hex[:12], "at": now(), "service": service, "kind": kind, "level": level,
          "title": title, "detail": detail[:2000], "finding_id": finding_id}
    con.execute("insert into events(id, at, service, kind, level, title, detail, finding_id) values(?,?,?,?,?,?,?,?)",
                tuple(ev.values()))
    con.commit()
    _to_hub(service, HUB_TYPE.get(kind, "change"), level, f"[보안 조치] {title}")
    return ev


def _to_hub(service: str, event_type: str, severity: str, message: str) -> None:
    hub = os.environ.get("HUB_URL")
    if not hub:
        return
    q = urllib.parse.urlencode({"event_type": event_type, "severity": severity, "message": message[:500]})
    try:
        req = urllib.request.Request(f"{hub.rstrip('/')}/monitor/events/{service}?{q}", method="POST")
        urllib.request.urlopen(req, timeout=5).close()
    except OSError:
        pass


def recent(con, service: str | None = None, limit: int = 50) -> list[dict]:
    sql = "select * from events" + (" where service=?" if service else "") + " order by at desc limit ?"
    return [dict(r) for r in con.execute(sql, ((service,) if service else ()) + (limit,))]
