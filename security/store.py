"""진단 결과 저장소 (sqlite). 재진단해도 applied/dismissed 상태는 유지한다."""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import ROOT
from .findings import Edit, Finding, Fix

SCHEMA = """
create table if not exists scans(
  id text primary key, started_at text, finished_at text, services text, offline integer, counts text);
create table if not exists findings(
  id text primary key, scan_id text, service text, category text, rule text, severity text, title text,
  file text, line integer, detail text, evidence text, fix text, status text default 'open',
  first_seen text, last_seen text, approved_by text, applied_at text, backup_dir text, applied_hash text);
create index if not exists ix_findings_service on findings(service);
"""
AI_COLUMNS = ("ai_verdict", "ai_note", "ai_models", "ai_fix")   # AI 판정 · 수정안. 재진단해도 유지
EXTRA_COLUMNS = AI_COLUMNS + ("patch",)                          # patch: 허브가 가져갈 조치안(diff)
# 상태: open 열림 · ready 조치안 준비됨(허브 관리) · delivered 허브가 반영 · applied 직접 적용 ·
#       branch 저장소 브랜치 커밋 · rolled_back 되돌림 · dismissed 무시
PENDING = ("open", "ready")   # 다음 진단에서 안 나오면 해결로 보고 지우는 상태


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db_path() -> Path:
    return Path(os.environ.get("SECURITY_DB", ROOT / "security.db"))


def connect() -> sqlite3.Connection:
    con = sqlite3.connect(db_path())
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    have = {r["name"] for r in con.execute("pragma table_info(findings)")}
    for col in EXTRA_COLUMNS:
        if col not in have:
            con.execute(f"alter table findings add column {col} text")
    return con


def start_scan(con, services: list[str], offline: bool) -> str:
    sid = uuid.uuid4().hex[:12]
    con.execute("insert into scans(id, started_at, services, offline) values(?,?,?,?)",
                (sid, now(), json.dumps(services), int(offline)))
    return sid


def save_findings(con, scan_id: str, service: str, findings: list[Finding],
                  categories: tuple[str, ...] | None = None) -> None:
    """이번 진단에 나온 것은 upsert, 이번에 돌린 분류(categories)에서 안 나온 open 항목은 해결된 것으로 보고 지운다."""
    ts = now()
    seen = set()
    for f in findings:
        seen.add(f.id)
        fix = json.dumps({"description": f.fix.description, "edits": [e.__dict__ for e in f.fix.edits]},
                         ensure_ascii=False) if f.fix else None
        con.execute("""insert into findings(id, scan_id, service, category, rule, severity, title, file, line, detail,
                         evidence, fix, first_seen, last_seen) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                       on conflict(id) do update set scan_id=excluded.scan_id, severity=excluded.severity,
                         title=excluded.title, detail=excluded.detail, fix=excluded.fix, last_seen=excluded.last_seen,
                         status=case when findings.status='rolled_back' then 'open' else findings.status end""",
                    (f.id, scan_id, service, f.category, f.rule, f.severity, f.title, f.file, f.line, f.detail,
                     f.evidence, fix, ts, ts))
    rows = con.execute("select id, category from findings where service=? and status in ('open', 'ready', 'delivered')",
                       (service,)).fetchall()
    if categories is not None:
        rows = [r for r in rows if r["category"] in categories]
    stale = [r["id"] for r in rows if r["id"] not in seen]
    con.executemany("delete from findings where id=?", [(i,) for i in stale])


def finish_scan(con, scan_id: str, counts: dict) -> None:
    con.execute("update scans set finished_at=?, counts=? where id=?", (now(), json.dumps(counts), scan_id))
    con.commit()


def _load_fix(raw) -> Fix | None:
    if not raw:
        return None
    d = json.loads(raw)
    return Fix(d["description"], [Edit(**e) for e in d["edits"]])


def row_fix(row) -> Fix | None:
    """적용할 수정: 규칙 기반 자동 수정이 있으면 그것, 없으면 AI 수정안, 둘 다 없으면 안내만."""
    fix = _load_fix(row["fix"])
    if fix and fix.automatic:
        return fix
    return _load_fix(row["ai_fix"]) or fix


def to_dict(row) -> dict:
    d = dict(row)
    fix = row_fix(row)
    d["fix"] = {"description": fix.description, "automatic": fix.automatic, "by_ai": fix.description.startswith("AI 제안"),
                "files": sorted({e.file for e in fix.edits})} if fix else None
    d.pop("ai_fix", None)
    d.pop("patch", None)
    from .policy import decide
    d["action"] = decide(row) if row["status"] in PENDING else None
    return d


def list_findings(con, **filters) -> list[dict]:
    where, args = [], []
    for k in ("service", "category", "severity", "status"):
        if filters.get(k):
            where.append(f"{k}=?")
            args.append(filters[k])
    sql = "select * from findings" + (" where " + " and ".join(where) if where else "")
    sql += (" order by case severity when 'critical' then 0 when 'high' then 1 when 'medium' then 2 else 3 end,"
            " service, file, line")
    out = [to_dict(r) for r in con.execute(sql, args)]
    return [d for d in out if d["action"] == filters["action"]] if filters.get("action") else out


def get(con, fid: str):
    return con.execute("select * from findings where id=?", (fid,)).fetchone()


def summary(con) -> dict:
    out: dict = {}
    from .policy import decide
    for r in con.execute("select * from findings"):
        s = out.setdefault(r["service"], {"critical": 0, "high": 0, "medium": 0, "low": 0, "open": 0, "escalated": 0,
                                           "ready": 0, "delivered": 0, "applied": 0, "branch": 0, "dismissed": 0})
        if r["status"] == "ready":
            s["ready"] += 1
        if r["status"] in PENDING:
            s[r["severity"]] += 1
            s["open"] += 1
            s["escalated"] += decide(r) == "escalate"
        elif r["status"] in s:
            s[r["status"]] += 1
    last = con.execute("select * from scans where finished_at is not null order by finished_at desc limit 1").fetchone()
    return {"services": out, "last_scan": dict(last) if last else None}
