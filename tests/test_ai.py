import pytest

from security import remediate, store
from security.ai import common, intel, providers, review, triage
from security.engine import run_review, scan_service
from security.scanners.deps import Dep

APP = '''\
import os
from flask import request, send_file

API_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"


def download():
    name = request.args["name"]
    return send_file("/data/" + name)


def run(cur, q):
    cur.execute("select 1 where x = %s" % q)
'''


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_DB", str(tmp_path / "sec.db"))
    monkeypatch.setattr(remediate, "BACKUPS", tmp_path / "backups")
    monkeypatch.setenv("SECURITY_REQUIRE_VERIFY", "0")   # 적용 동작 자체를 보는 테스트 — 검증 흐름은 test_verify
    root = tmp_path / "svc"
    root.mkdir()
    (root / "app.py").write_text(APP, encoding="utf-8")
    return root


def fake_models(monkeypatch, answers: dict[str, dict]):
    """providers.ask_all 을 모델별 고정 답으로 바꾼다. 받은 프롬프트는 sent 에 쌓인다."""
    sent = []

    def ask_all(system, prompt):
        sent.append(prompt)
        return answers

    monkeypatch.setattr(providers, "ask_all", ask_all)
    monkeypatch.setattr(providers, "available", lambda: list(answers))
    return sent


def test_consent_required(repo, monkeypatch):
    monkeypatch.delenv("SECURITY_AI_SEND_CODE", raising=False)
    with pytest.raises(common.ConsentError):
        review.scan("svc", repo)


def test_redact_hides_secrets():
    out = common.redact('API_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"\npassword = "hunter2secret"')
    assert "abcdefghij" not in out and "hunter2" not in out
    assert out.count("\n") == 1


def test_parse_json_with_fence():
    assert providers.parse_json('```json\n{"a": 1}\n```') == {"a": 1}


def test_review_merge_consensus_and_patch(repo, monkeypatch):
    line = '    return send_file("/data/" + name)'
    fix = '    return send_file(safe_join("/data", name))'
    sent = fake_models(monkeypatch, {
        "claude": {"findings": [{"line": 9, "old": line.strip(), "severity": "high", "cwe": "CWE-22",
                                 "title": "경로 조작", "detail": "..", "new": fix}]},
        "gemini": {"findings": [{"line": 9, "old": line.strip(), "severity": "critical", "cwe": "CWE-22",
                                 "title": "경로 조작", "detail": ".."},
                                {"line": 3, "old": "지어낸 줄", "severity": "high", "title": "환각"}]},
        "openai": {"error": "HTTP 500"},
    })
    found, errors = review.scan("svc", repo, allow_code=True)
    assert "abcdefghij" not in sent[0]           # 비밀값은 가려서 전송
    assert errors == ["app.py: openai HTTP 500"]
    assert len(found) == 1                        # 원문과 안 맞는 줄은 버림
    f = found[0]
    assert f.rule == "AI-REVIEW-CWE-22" and f.severity == "critical" and f.line == 9
    assert f.fix.automatic and f.fix.edits[0].new == fix


def test_review_single_model_among_many_is_downgraded(repo, monkeypatch):
    fake_models(monkeypatch, {
        "claude": {"findings": [{"line": 13, "old": 'cur.execute("select 1 where x = %s" % q)', "severity": "high",
                                 "title": "SQL", "detail": ".."}]},
        "gemini": {"findings": []},
    })
    found, _ = review.scan("svc", repo, allow_code=True)
    assert found[0].severity == "medium"


def test_review_failure_keeps_previous(repo, monkeypatch):
    fake_models(monkeypatch, {"claude": {"findings": [{"line": 9, "old": 'return send_file("/data/" + name)',
                                                       "severity": "high", "title": "x", "detail": ""}]}})
    run_review({"svc": repo}, allow_code=True)
    fake_models(monkeypatch, {"claude": {"error": "timeout"}})
    run_review({"svc": repo}, allow_code=True)
    con = store.connect()
    assert [f["category"] for f in store.list_findings(con)] == ["ai"]


def test_triage_vote_and_ai_patch_apply(repo, monkeypatch):
    con = store.connect()
    sid = store.start_scan(con, ["svc"], True)
    store.save_findings(con, sid, "svc", scan_service("svc", repo, offline=True))
    con.commit()
    sqli = next(f for f in store.list_findings(con) if f["rule"] == "SAST-PY-SQLI")
    assert not sqli["fix"]["automatic"] if sqli["fix"] else True

    new = '    cur.execute("select 1 where x = ?", (q,))'
    fake_models(monkeypatch, {
        "claude": {"verdict": "true_positive", "reason": "외부 입력", "new": new},
        "gemini": {"verdict": "true_positive", "reason": "동의", "new": ""},
        "openai": {"verdict": "false_positive", "reason": "상수"},
    })
    r = triage.run(con, {"svc": repo}, "svc", allow_code=True, limit=100)
    assert r["checked"] >= 1 and r["patched"] >= 1

    f = store.to_dict(store.get(con, sqli["id"]))
    assert f["ai_verdict"] == "true_positive" and f["fix"]["by_ai"] and f["fix"]["automatic"]
    assert "?" in remediate.diff(con, {"svc": repo}, sqli["id"])
    remediate.apply(con, {"svc": repo}, sqli["id"], "tester")
    assert new in (repo / "app.py").read_text(encoding="utf-8")

    # 재진단해도 AI 판정은 유지
    store.save_findings(con, sid, "svc", scan_service("svc", repo, offline=True))
    assert store.get(con, sqli["id"])["ai_verdict"] == "true_positive"


def test_intel_ai_filters_candidates(tmp_path, monkeypatch):
    root = tmp_path / "svc"
    root.mkdir()
    (root / "requirements.txt").write_text("fastapi==0.104.1\nrequests==2.31.0\n", encoding="utf-8")
    monkeypatch.setattr(intel, "fetch_kev", lambda: [
        {"id": "CVE-2026-0001", "source": "KEV", "severity": "critical", "products": {"fastapi"}, "text": "FastAPI RCE"}])
    monkeypatch.setattr(intel, "fetch_nvd", lambda days: [
        {"id": "CVE-2026-0002", "source": "NVD", "severity": "high", "products": {"requests_toolbelt"},
         "text": "requests-toolbelt issue, not the requests library"}])
    fake_models(monkeypatch, {
        "claude": {"relevant": [{"cve": "CVE-2026-0001", "package": "fastapi", "reason": "버전 해당", "action": "0.120 이상"}]},
        "gemini": {"relevant": [{"cve": "cve-2026-0001", "package": "FastAPI", "reason": "해당"}]},
    })
    res, errors = intel.scan({"svc": root})
    assert errors == []
    [f] = res["svc"]
    assert f.rule == "INTEL-KEV" and f.severity == "critical" and f.line == 1
    assert "0.120" in f.fix.description


def test_intel_without_ai_keeps_exact_cpe_only(tmp_path, monkeypatch):
    monkeypatch.setattr(providers, "available", lambda: [])
    deps = [Dep("requests", "2.31.0", "PyPI", "requirements.txt", 1, "requests==2.31.0", True)]
    feed = [{"id": "A", "source": "NVD", "severity": "critical", "products": {"requests"}, "text": "x"},
            {"id": "B", "source": "NVD", "severity": "high", "products": set(), "text": "uses requests internally"}]
    assert [(v["id"], exact) for v, _, exact in intel.match(deps, feed)] == [("A", True), ("B", False)]
