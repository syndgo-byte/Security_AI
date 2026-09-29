import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from security import engine, policy, remediate, store, watch
from security.engine import scan_service
from security.scanners import web

APP = "import yaml\n\n\ndef load(s, cur, q):\n    yaml.load(s)\n    cur.execute('select %s' % q)\n"


# ── 웹 ─────────────────────────────────────────────────────────────
class Site(BaseHTTPRequestHandler):
    env_body = b"<!doctype html><html>app</html>"   # SPA: 모든 경로에 index.html

    def do_GET(self):
        if self.path == "/.env":
            body, ctype = self.env_body, "text/plain"
        elif self.path == "/.git/HEAD":
            body, ctype = b"<!doctype html><html>app</html>", "text/html"
        else:
            body, ctype = b"<!doctype html><html>app</html>", "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Server", "uvicorn/0.30.1")
        self.send_header("Set-Cookie", "session=abc; Path=/")
        if self.headers.get("Origin"):
            self.send_header("Access-Control-Allow-Origin", self.headers["Origin"])
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def site():
    srv = HTTPServer(("127.0.0.1", 0), Site)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_web_passive_checks(site):
    rules = {f.rule: f for f in web.scan_site("svc", site)}
    assert {"WEB-HDR-CSP", "WEB-HDR-NOSNIFF", "WEB-HDR-FRAME", "WEB-HDR-VERSION", "WEB-COOKIE",
            "WEB-CORS-CRED"} <= set(rules)
    assert "WEB-NO-HTTPS" not in rules            # localhost 는 http 허용
    assert "WEB-EXPOSED-ENV" not in rules         # SPA 가 돌려준 index.html 은 노출로 안 봄
    assert "WEB-EXPOSED-GIT" not in rules
    assert "Secure" not in rules["WEB-COOKIE"].title   # http 에서는 Secure 요구 안 함
    assert all(not f.fix.automatic for f in rules.values())


def test_web_real_env_exposure(site, monkeypatch):
    monkeypatch.setattr(Site, "env_body", b"DATABASE_URL=postgres://x\nSECRET_KEY=abc\n")
    f = next(f for f in web.scan_site("svc", site) if f.rule == "WEB-EXPOSED-ENV")
    assert f.severity == "critical" and policy.decide(_row(f)) == "escalate"


def test_web_unreachable_keeps_previous(tmp_path, monkeypatch, site):
    monkeypatch.setenv("SECURITY_DB", str(tmp_path / "sec.db"))
    engine.run_web({"svc": [site]})
    r = engine.run_web({"svc": ["http://127.0.0.1:1"]})
    assert r["errors"] and store.list_findings(store.connect(), category="web")


# ── 정책 ───────────────────────────────────────────────────────────
def _row(f, **kw):
    fix = json.dumps({"description": f.fix.description, "edits": [e.__dict__ for e in f.fix.edits]},
                     ensure_ascii=False) if f.fix else None
    return {"severity": f.severity, "rule": f.rule, "fix": fix, "ai_fix": None, **kw}


def test_policy(tmp_path):
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    (tmp_path / ".env").write_text("X=1\n", encoding="utf-8")
    found = {f.rule: f for f in scan_service("svc", tmp_path, offline=True)}
    assert policy.decide(_row(found["SAST-PY-YAML"])) == "auto"         # high 지만 안전한 자동 수정
    assert policy.decide(_row(found["SAST-PY-SQLI"])) == "escalate"     # high · 수정안 없음 → 넘김
    assert policy.decide(_row(found["SECRET-ENV-NOT-IGNORED"])) == "auto"
    ai = json.dumps({"description": "AI 제안: x", "edits": [{"file": "a", "line": 1, "old": "a", "new": "b"}]})
    assert policy.decide({**_row(found["SAST-PY-SQLI"]), "ai_fix": ai}) == "approve"


def test_policy_env_thresholds(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    yaml_row = _row(next(f for f in scan_service("svc", tmp_path, True) if f.rule == "SAST-PY-YAML"))
    monkeypatch.setenv("SECURITY_AUTO_MAX", "medium")
    assert policy.decide(yaml_row) == "approve"
    monkeypatch.setenv("SECURITY_ESCALATE_MIN", "high")
    assert policy.decide(yaml_row) == "escalate"


# ── 자동 조치 (허브 관리 조치안) ───────────────────────────────────
def test_prepare_patches_reads_only(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_DB", str(tmp_path / "sec.db"))
    svc = tmp_path / "svc"
    svc.mkdir()
    (svc / "app.py").write_text(APP, encoding="utf-8")
    engine.run({"svc": svc}, offline=True)
    con = store.connect()

    r = remediate.auto_remediate(con, {"svc": svc})
    assert r["mode"] == "patch" and len(r["ready"]) == 1
    assert (svc / "app.py").read_text(encoding="utf-8") == APP             # 서비스 파일 그대로
    row = store.get(con, r["ready"][0])
    assert row["status"] == "ready" and "+    yaml.safe_load(s)" in row["patch"]
    assert store.to_dict(row)["action"] == "auto" and "patch" not in store.to_dict(row)

    (svc / "app.py").write_text(APP.replace("yaml.load(s)", "yaml.load(s)  # x"), encoding="utf-8")
    assert remediate.prepare_patches(con, {"svc": svc})["reopened"] == [row["id"]]   # 코드가 바뀌면 다시 열림

    (svc / "app.py").write_text(APP, encoding="utf-8")
    remediate.prepare_patches(con, {"svc": svc})
    remediate.mark_delivered(con, row["id"], "hub-job-1")
    (svc / "app.py").write_text(APP.replace("yaml.load(", "yaml.safe_load("), encoding="utf-8")
    engine.run({"svc": svc}, offline=True)                                  # 반영 후 재진단 → 해결로 정리
    assert store.get(store.connect(), row["id"]) is None


def test_approve_and_cancel(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_DB", str(tmp_path / "sec.db"))
    svc = tmp_path / "svc"
    svc.mkdir()
    (svc / "app.py").write_text(APP, encoding="utf-8")
    engine.run({"svc": svc}, offline=True)
    con = store.connect()
    sqli = next(f for f in store.list_findings(con) if f["rule"] == "SAST-PY-SQLI")
    with pytest.raises(remediate.RemediationError):
        remediate.approve(con, {"svc": svc}, sqli["id"], "홍길동")       # 수정안 없음
    yml = next(f for f in store.list_findings(con) if f["rule"] == "SAST-PY-YAML")
    remediate.approve(con, {"svc": svc}, yml["id"], "홍길동")
    row = store.get(con, yml["id"])
    assert row["status"] == "ready" and row["approved_by"] == "홍길동" and row["patch"]
    assert (svc / "app.py").read_text(encoding="utf-8") == APP
    remediate.cancel(con, yml["id"])
    assert store.get(con, yml["id"])["status"] == "open"


# ── 자동 조치 (브랜치, SECURITY_AUTO_FIX_MODE=branch) ──────────────
def git(cwd, *a):
    return subprocess.run(["git", "-C", str(cwd), *a], capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def gitrepo(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_DB", str(tmp_path / "sec.db"))
    monkeypatch.setattr(remediate, "WORKTREES", tmp_path / "wt")
    root = tmp_path / "repo"
    (root / "svc").mkdir(parents=True)
    (root / "svc" / "app.py").write_text(APP, encoding="utf-8")
    (root / ".gitignore").write_text("*.pyc\n", encoding="utf-8")
    git(root, "init", "-q", "-b", "main")
    git(root, "add", ".")
    git(root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init")
    return root


def test_auto_fix_goes_to_branch_only(gitrepo):
    svc = gitrepo / "svc"                  # 서비스가 저장소 하위 폴더인 경우
    engine.run({"svc": svc}, offline=True)
    before = (svc / "app.py").read_text(encoding="utf-8")

    r = remediate.auto_fix(store.connect(), {"svc": svc})
    b = r["branches"]["svc"]
    assert (svc / "app.py").read_text(encoding="utf-8") == before      # 작업 폴더 그대로
    assert git(gitrepo, "branch", "--show-current") == "main"
    assert git(gitrepo, "status", "--porcelain") == ""
    assert "yaml.safe_load(s)" in git(gitrepo, "show", f"{b['branch']}:svc/app.py")
    assert git(gitrepo, "worktree", "list").count("\n") == 0             # worktree 는 치움

    con = store.connect()
    statuses = {f["rule"]: f["status"] for f in store.list_findings(con)}
    assert statuses["SAST-PY-YAML"] == "branch" and statuses["SAST-PY-SQLI"] == "open"
    assert remediate.auto_fix(con, {"svc": svc})["branches"] == {}      # 같은 건 다시 안 함


def test_auto_fix_skips_uncommitted_lines(gitrepo):
    svc = gitrepo / "svc"
    (svc / "app.py").write_text("\n" + APP, encoding="utf-8")          # 커밋 안 한 변경 → 줄 번호 어긋남
    engine.run({"svc": svc}, offline=True)
    r = remediate.auto_fix(store.connect(), {"svc": svc})
    assert any("커밋된 코드와 달라" in s for s in r["skipped"])
    assert "security/auto" not in git(gitrepo, "branch", "--list") or r["branches"]


def test_auto_fix_ignores_non_git(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_DB", str(tmp_path / "sec.db"))
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "app.py").write_text(APP, encoding="utf-8")
    engine.run({"svc": tmp_path / "svc"}, offline=True)
    r = remediate.auto_fix(store.connect(), {"svc": tmp_path / "svc"})
    assert r["branches"] == {} and "git 저장소가 아니라" in r["skipped"][0]


# ── 허브 보고 · 상시 진단 ──────────────────────────────────────────
def test_escalation_reported_once(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_DB", str(tmp_path / "sec.db"))
    sent = []
    monkeypatch.setattr(engine, "report_to_hub", lambda s, rows: sent.append([r["rule"] for r in rows]))
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "app.py").write_text(APP, encoding="utf-8")
    engine.run({"svc": tmp_path / "svc"}, offline=True)
    engine.run({"svc": tmp_path / "svc"}, offline=True)
    assert "SAST-PY-SQLI" in sent[0] and sent[1] == []


def test_watcher_schedule(monkeypatch):
    calls = []
    monkeypatch.setattr(watch, "run_job", lambda job: calls.append(job) or {})
    w = watch.Watcher()
    w.tick(now=1_000_000)
    assert calls == ["code", "web", "intel"]
    w.tick(now=1_000_000 + 31 * 60)
    assert calls[3:] == ["code"]
    monkeypatch.setattr(watch, "run_job", lambda job: 1 / 0)
    w.tick(now=1_000_000 + 400 * 60)
    assert w.status["web"]["ok"] is False                               # 실패해도 감시는 계속
