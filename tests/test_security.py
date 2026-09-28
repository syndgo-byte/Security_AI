import textwrap

import pytest

from security import manifest, remediate, store
from security.engine import scan_service
from security.scanners import config, deps, sast, secrets

VULN = textwrap.dedent('''\
    import yaml
    import requests
    from sqlalchemy import Column, String

    API_KEY = "a1b2c3d4e5f6g7h8"
    DEBUG = True


    def load(s, cur, uid):
        yaml.load(s)
        cur.execute(f"select * from users where id = {uid}")
        requests.get("https://x", verify=False)
        eval(s)


    class User:
        rrn = Column(String(13))
        rrn_enc = Column(String(64))
    ''')


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_DB", str(tmp_path / "sec.db"))
    monkeypatch.setattr(remediate, "BACKUPS", tmp_path / "backups")
    root = tmp_path / "svc"
    root.mkdir()
    (root / "app.py").write_text(VULN, encoding="utf-8")
    (root / "requirements.txt").write_text("requests==2.19.0\nflask\n", encoding="utf-8")
    (root / ".env").write_text("X=1\n", encoding="utf-8")
    (root / "web.js").write_text("el.innerHTML = q;\n", encoding="utf-8")
    return root


def rules(findings):
    return {f.rule for f in findings}


def test_manifest_contract():
    m = manifest()
    assert m["id"] == "security" and m["kind"] == "module"
    assert m["source"]["entry"] == "security/__init__.py"


def test_sast(repo):
    r = rules(sast.scan("svc", repo))
    assert {"SAST-PY-YAML", "SAST-PY-SQLI", "SAST-PY-TLS-VERIFY", "SAST-PY-EVAL", "SAST-JS-INNERHTML"} <= r


def test_secrets_masked_and_env(repo):
    f = secrets.scan("svc", repo)
    hard = next(x for x in f if x.rule == "SECRET-HARDCODED")
    assert "a1b2c3d4" not in hard.evidence and hard.fix.automatic
    assert "SECRET-ENV-NOT-IGNORED" in rules(f)


def test_config_and_pipa(repo):
    f = config.scan("svc", repo)
    pii = [x for x in f if x.rule == "PIPA-UNIQUE-ID-PLAINTEXT"]
    assert len(pii) == 1 and "rrn " in pii[0].evidence + " "
    assert "CONFIG-DEBUG" in rules(f)


def test_deps_offline(repo):
    f = deps.scan("svc", repo, offline=True)
    assert rules(f) == {"DEPS-UNPINNED"}


def _save(repo):
    con = store.connect()
    sid = store.start_scan(con, ["svc"], True)
    store.save_findings(con, sid, "svc", scan_service("svc", repo, offline=True))
    con.commit()
    return con


def test_apply_and_rollback(repo):
    con = _save(repo)
    targets = {"svc": repo}
    fid = next(f["id"] for f in store.list_findings(con) if f["rule"] == "SAST-PY-YAML")
    original = (repo / "app.py").read_text(encoding="utf-8")
    assert "yaml.safe_load(s)" in remediate.diff(con, targets, fid)

    with pytest.raises(remediate.RemediationError):
        remediate.apply(con, targets, fid, "  ")
    remediate.apply(con, targets, fid, "tester")
    assert "yaml.safe_load(s)" in (repo / "app.py").read_text(encoding="utf-8")

    remediate.rollback(con, fid)
    assert (repo / "app.py").read_text(encoding="utf-8") == original


def test_gitignore_append(repo):
    con = _save(repo)
    fid = next(f["id"] for f in store.list_findings(con) if f["rule"] == "SECRET-ENV-NOT-IGNORED")
    remediate.apply(con, {"svc": repo}, fid, "tester")
    assert (repo / ".gitignore").read_text(encoding="utf-8").strip() == ".env"
    remediate.rollback(con, fid)
    assert not (repo / ".gitignore").exists()


def test_refuse_when_file_changed(repo):
    con = _save(repo)
    fid = next(f["id"] for f in store.list_findings(con) if f["rule"] == "SAST-PY-YAML")
    p = repo / "app.py"
    p.write_text(p.read_text(encoding="utf-8").replace("yaml.load(s)", "yaml.load(s)  # changed"), encoding="utf-8")
    with pytest.raises(remediate.RemediationError):
        remediate.apply(con, {"svc": repo}, fid, "tester")
    assert store.get(con, fid)["status"] == "open"


def test_rollback_refused_after_later_edit(repo):
    con = _save(repo)
    fid = next(f["id"] for f in store.list_findings(con) if f["rule"] == "SAST-PY-YAML")
    remediate.apply(con, {"svc": repo}, fid, "tester")
    (repo / "app.py").write_text("# rewritten\n", encoding="utf-8")
    with pytest.raises(remediate.RemediationError):
        remediate.rollback(con, fid)


def test_status_kept_on_rescan(repo):
    con = _save(repo)
    fid = next(f["id"] for f in store.list_findings(con) if f["rule"] == "SAST-PY-EVAL")
    remediate.dismiss(con, fid, "의도된 코드")
    con = _save(repo)
    assert store.get(con, fid)["status"] == "dismissed"
