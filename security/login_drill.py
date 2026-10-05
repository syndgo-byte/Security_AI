"""AI 로그인 공격 방어 훈련 — 보안 진단이 공격 패턴을 재현하고, 실시간 방어(Sentinel)가 실제로 막는지 확인한다.

훈련은 auth_core 센서와 같은 형식의 로그인 이벤트를 Sentinel 이벤트 파일에 기록한다.
실시간 방어 데몬은 이를 실제 공격과 같은 경로로 탐지·조치하고, drill 표시 덕분에 실사용자 판단과 섞이지 않으며
훈련 조치는 짧은 TTL(기본 120초) 뒤 자동 만료된다. 계정은 drill_ 접두어, IP는 TEST-NET(RFC 5737) 대역만 쓴다.
"""
from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import random
import re
import time
import uuid

DEFAULT_DIR = Path("D:/Vibe_coding/ops/Security_Responce/data")
SERVICE_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
TEST_NETS = ("192.0.2", "198.51.100", "203.0.113")

# kind: (제목, 설명, 기대 탐지 규칙, 기대 조치)
SCENARIOS = {
    "distributed_grazing": ("분산 IP 끊어치기", "IP 12개 · 계정 3개 × 4회 실패 (잠금 5회 직전)",
                            "THRESHOLD_GRAZING", "계정 잠금 + 서비스 잠금 임계치 5→3 하향"),
    "ip_spray": ("단일 IP 스프레잉", "IP 1개로 계정 6개 1회씩 실패", "IP_SPRAY", "IP 1시간 차단"),
    "canary": ("미끼 계정 접근", "존재하지 않는 관리자 미끼 계정 로그인 시도", "CANARY_TOUCH", "IP 즉시 차단"),
    "cross_service": ("서비스 교차 공격", "같은 IP로 2개 서비스 계정 3개 실패", "CROSS_SERVICE_IP", "IP 차단"),
    "suspicious_success": ("계정 탈취 의심", "4회 실패 후 로그인 성공", "SUSPICIOUS_SUCCESS", "계정 잠금 · 세션 종료 권고"),
}


def data_root(data_dir=None) -> Path:
    return Path(data_dir if data_dir is not None else os.environ.get("SENTINEL_DIR", str(DEFAULT_DIR)))


def scenarios() -> list[dict]:
    return [{"kind": k, "title": t, "description": d, "expects": r, "action": a}
            for k, (t, d, r, a) in SCENARIOS.items()]


def _ips(count: int) -> list[str]:
    net = random.choice(TEST_NETS)   # 매 회차 다른 주소: 같은 IP 재훈련이 Sentinel 중복 억제에 걸리지 않게
    return [f"{net}.{host}" for host in random.sample(range(1, 255), count)]


def _events(kind: str, service: str, run: str) -> list[dict]:
    rows = []

    def add(user, ip, svc=service, result="fail"):
        rows.append({"ts": time.time(), "service": svc, "kind": f"login_{result}",
                     "ip": ip, "username": user, "drill": True, "drill_run": run})

    if kind == "distributed_grazing":
        ips = _ips(12)
        for account in range(3):
            for attempt in range(4):
                add(f"drill_{run}_{account}", ips[account * 4 + attempt])
    elif kind == "ip_spray":
        ip = _ips(1)[0]
        for account in range(6):
            add(f"drill_{run}_{account}", ip)
    elif kind == "canary":
        add("drill_admin_backup", _ips(1)[0])
    elif kind == "cross_service":
        ip = _ips(1)[0]
        for account in range(3):
            add(f"drill_{run}_{account}", ip, service if account == 0 else f"{service}_drill_peer")
    elif kind == "suspicious_success":
        ip = _ips(1)[0]
        for _ in range(4):
            add(f"drill_{run}", ip)
        add(f"drill_{run}", ip, result="ok")
    return rows


def _append(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab", buffering=0) as stream:   # 센서와 같은 한 줄 append — 다른 프로세스와 줄 경계 유지
        stream.write((json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8"))


def _read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def sentinel_running(data_dir=None) -> bool:
    beat = _read_json(data_root(data_dir) / "sentinel_heartbeat.json")
    try:
        return 0 <= time.time() - float(beat.get("last_tick", 0)) <= 15
    except (TypeError, ValueError):
        return False


def run(kind: str, service: str = "EMSv3", data_dir=None) -> dict:
    """훈련 이벤트를 기록하고 회차 정보를 돌려준다. 판정은 check() 로 한다."""
    if kind not in SCENARIOS:
        raise ValueError(f"알 수 없는 훈련: {kind}")
    if not SERVICE_RE.match(service or ""):
        raise ValueError("서비스 이름은 영문·숫자·_·- 만 쓸 수 있습니다.")
    root = data_root(data_dir)
    run_id = uuid.uuid4().hex[:8]
    started = time.time()
    rows = _events(kind, service, run_id)
    for row in rows:
        _append(root / "events" / f"{row['service']}.jsonl", row)
    return {"ok": True, "run_id": run_id, "kind": kind, "service": service, "started": started,
            "events_written": len(rows), "ips": sorted({r["ip"] for r in rows}),
            "accounts": sorted({f"{r['service']}|{r['username']}" for r in rows}),
            "expects": SCENARIOS[kind][2], "sentinel_running": sentinel_running(root)}


def _detections(root: Path):
    try:
        with (root / "detections.jsonl").open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                try:
                    value = json.loads(line)
                except ValueError:
                    continue
                if isinstance(value, dict):
                    yield value
    except OSError:
        return


def _ts(record: dict) -> float:
    try:
        return datetime.fromisoformat(record["timestamp"]).timestamp()
    except (KeyError, TypeError, ValueError):
        return 0.0


def check(kind: str, started: float, ips: list[str], accounts: list[str], data_dir=None) -> dict:
    """회차의 IP·계정과 겹치는 훈련 탐지와 차단 조치를 찾아 방어 성공 여부를 판정한다."""
    if kind not in SCENARIOS:
        raise ValueError(f"알 수 없는 훈련: {kind}")
    root = data_root(data_dir)
    ips, accounts = set(ips), set(accounts)
    found = [d for d in _detections(root) if d.get("drill") is True and _ts(d) >= started - 1
             and (ips & set(d.get("ips") or []) or accounts & set(d.get("accounts") or []))]
    detection_ids = {d.get("detection_id") for d in found}
    blocks, now = _read_json(root / "blocklist.json"), time.time()
    actions = []
    for group in ("ips", "accounts", "services"):
        for target, entry in (blocks.get(group) or {}).items():
            if isinstance(entry, dict) and entry.get("detection_id") in detection_ids and float(entry.get("until", 0)) > now:
                actions.append({"group": group, "target": target, "until": entry["until"],
                                "lockout_threshold": entry.get("lockout_threshold")})
    expected = SCENARIOS[kind][2]
    passed = any(d.get("rule_id") == expected for d in found)
    return {"kind": kind, "expects": expected, "passed": passed,
            "detections": [{k: d.get(k) for k in ("detection_id", "rule_id", "title", "severity", "description", "timestamp")}
                           for d in found],
            "actions": actions, "sentinel_running": sentinel_running(root)}
