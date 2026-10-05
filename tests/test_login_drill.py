"""AI 로그인 공격 방어 훈련: 기록한 이벤트가 실제 Sentinel 데몬에서 탐지·조치되는지 확인한다."""
import json
from pathlib import Path
import sys
import time

import pytest

from security import login_drill

RESPONCE = Path(__file__).resolve().parents[2] / "Security_Responce"


@pytest.fixture
def daemon_cls():
    if not (RESPONCE / "responce" / "daemon.py").exists():
        pytest.skip("Security_Responce 저장소가 없습니다")
    sys.path.insert(0, str(RESPONCE))
    try:
        from responce.daemon import SentinelDaemon
    finally:
        sys.path.remove(str(RESPONCE))
    return SentinelDaemon


@pytest.mark.parametrize("kind", list(login_drill.SCENARIOS))
def test_drill_is_detected_and_blocked_by_real_sentinel(tmp_path, daemon_cls, kind):
    run = login_drill.run(kind, "EMSv3", tmp_path)
    assert run["events_written"] > 0
    assert all(a.split("|")[1].startswith("drill_") for a in run["accounts"])
    assert all(ip.rsplit(".", 1)[0] in login_drill.TEST_NETS for ip in run["ips"])
    before = login_drill.check(kind, run["started"], run["ips"], run["accounts"], tmp_path)
    assert not before["passed"] and not before["sentinel_running"]

    daemon_cls(tmp_path).tick()
    result = login_drill.check(kind, run["started"], run["ips"], run["accounts"], tmp_path)
    assert result["passed"], result
    assert result["sentinel_running"]
    assert any(d["rule_id"] == run["expects"] for d in result["detections"])
    if kind != "cross_service":   # 계정 3개 이상일 때만 IP 차단이 붙는다 — 그 외에는 반드시 조치가 있어야 한다
        assert result["actions"]
    blocks = json.loads((tmp_path / "blocklist.json").read_text(encoding="utf-8"))
    assert all(e["drill"] and e["until"] <= time.time() + 121 for g in blocks.values() if isinstance(g, dict)
               for e in g.values())


def test_repeated_drills_are_not_suppressed(tmp_path, daemon_cls):
    daemon = daemon_cls(tmp_path)
    for _ in range(2):
        run = login_drill.run("canary", "EMSv3", tmp_path)
        daemon.tick()
        assert login_drill.check("canary", run["started"], run["ips"], run["accounts"], tmp_path)["passed"]


def test_other_runs_do_not_count(tmp_path, daemon_cls):
    first = login_drill.run("ip_spray", "EMSv3", tmp_path)
    daemon_cls(tmp_path).tick()
    other = login_drill.check("ip_spray", first["started"], ["192.0.2.255"], ["EMSv3|nobody"], tmp_path)
    assert not other["passed"] and not other["detections"]


@pytest.mark.parametrize("kind,service", [("bad", "EMSv3"), ("canary", "../escape"), ("canary", "")])
def test_invalid_input_writes_nothing(tmp_path, kind, service):
    with pytest.raises(ValueError):
        login_drill.run(kind, service, tmp_path)
    assert not (tmp_path / "events").exists()
