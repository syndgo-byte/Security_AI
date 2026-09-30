"""조치안 동작 검증 → 적용 → 알람."""
import pytest

from security import alerts, remediate, store
from security.findings import Edit, Finding, Fix

APP = "def add(a, b):\n    return a + b\n"
TEST = "from app import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n"


@pytest.fixture
def svc(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_DB", str(tmp_path / "sec.db"))
    monkeypatch.delenv("HUB_URL", raising=False)
    monkeypatch.setattr(remediate, "BACKUPS", tmp_path / "backups")
    root = tmp_path / "svc"
    (root / "tests").mkdir(parents=True)
    (root / "app.py").write_text(APP, encoding="utf-8")
    (root / "conftest.py").write_text("", encoding="utf-8")   # 루트를 import 경로에
    (root / "tests" / "test_app.py").write_text(TEST, encoding="utf-8")
    return root


def finding(con, root, new_line):
    f = Finding("svc", "sast", "TEST-RULE", "medium", "테스트 항목", "app.py", 2, "d", "return a + b",
                Fix("수정", [Edit("app.py", 2, "    return a + b", new_line)]))
    sid = store.start_scan(con, ["svc"], True)
    store.save_findings(con, sid, "svc", [f])
    con.commit()
    return f.id


def verify(con, root, fid):
    _, edits = remediate.start_verify(con, {"svc": root}, fid)
    return remediate.run_verify(con, root, fid, edits)


def test_passing_fix_is_verified_then_applied(svc):
    con = store.connect()
    fid = finding(con, svc, "    return a + b  # checked")
    with pytest.raises(remediate.RemediationError, match="동작 검증"):
        remediate.apply(con, {"svc": svc}, fid, "관리자")
    r = verify(con, svc, fid)
    assert r["state"] == "passed", r
    assert (svc / "app.py").read_text(encoding="utf-8") == APP   # 검증은 복사본에서만
    remediate.apply(con, {"svc": svc}, fid, "관리자")
    assert "# checked" in (svc / "app.py").read_text(encoding="utf-8")
    assert [e["kind"] for e in alerts.recent(con, "svc")] == ["applied", "verify_passed"]


def test_breaking_fix_fails_and_cannot_apply(svc):
    con = store.connect()
    fid = finding(con, svc, "    return a - b")
    r = verify(con, svc, fid)
    assert r["state"] == "failed"
    test = next(s for s in r["steps"] if s["name"] == "테스트")
    assert "새로 실패" in test["note"] and "test_add" in test["note"]
    with pytest.raises(remediate.RemediationError):
        remediate.apply(con, {"svc": svc}, fid, "관리자")
    assert (svc / "app.py").read_text(encoding="utf-8") == APP
    assert alerts.recent(con, "svc")[0]["kind"] == "verify_failed"


def test_preexisting_failure_does_not_block(svc):
    (svc / "tests" / "test_old.py").write_text("def test_old():\n    assert False\n", encoding="utf-8")
    con = store.connect()
    fid = finding(con, svc, "    return a + b  # ok")
    r = verify(con, svc, fid)
    assert r["state"] == "passed", r
    assert "기존 실패" in next(s for s in r["steps"] if s["name"] == "테스트")["note"]


def test_file_changed_after_verify_needs_reverify(svc):
    con = store.connect()
    fid = finding(con, svc, "    return a + b  # ok")
    verify(con, svc, fid)
    (svc / "other.txt").write_text("x", encoding="utf-8")        # 대상 아닌 파일은 상관없음
    (svc / "app.py").write_text(APP + "\n# edited\n", encoding="utf-8")
    with pytest.raises(remediate.RemediationError, match="다시 검증"):
        remediate.apply(con, {"svc": svc}, fid, "관리자")
