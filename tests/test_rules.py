"""오탐 줄이기 · 조치안 늘리기 규칙."""
from security.scanners import config, deps, sast


def rules(findings):
    return [f.rule for f in findings]


def test_cookie_conditional_secure_is_not_flagged(tmp_path):
    (tmp_path / "app.py").write_text(
        "def f(r, resp):\n"
        "    resp.set_cookie('s', 'v', secure=r.url.scheme == 'https', httponly=True)\n"
        "    resp.set_cookie('t', 'v', secure=False, httponly=True)\n"
        "    resp.set_cookie('u', 'v')\n", encoding="utf-8")
    found = [f for f in config.scan("svc", tmp_path) if f.rule == "CONFIG-COOKIE-FLAGS"]
    assert sorted(f.line for f in found) == [3, 4]


def test_sql_placeholders_only_is_not_flagged(tmp_path):
    (tmp_path / "db.py").write_text(
        "def f(cur, ids, where):\n"
        "    cur.execute(f\"select * from t where id in ({','.join('?' * len(ids))})\", ids)\n"
        "    marks = ','.join('?' * len(ids))\n"
        "    cur.execute(f'delete from t where id in ({marks})', ids)\n"
        "    cur.execute(f'select * from t where {where}', ids)\n"
        "    cur.execute(f'select * from t where id = {ids}')\n", encoding="utf-8")
    found = {f.line: f.rule for f in sast.scan("svc", tmp_path)}
    assert found == {5: "SAST-PY-SQL-DYNAMIC", 6: "SAST-PY-SQLI"}


def test_unpinned_grouped_per_file(tmp_path):
    (tmp_path / "requirements.txt").write_text("fastapi\nuvicorn>=0.20\nrequests==2.31.0\n", encoding="utf-8")
    found = deps.scan("svc", tmp_path, offline=True)
    assert rules(found) == ["DEPS-UNPINNED"]
    assert "2개" in found[0].title and "fastapi, uvicorn" in found[0].evidence


def test_floor_is_queried_and_fixed(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("jinja2>=3.0.0\n", encoding="utf-8")
    sent = {}

    def post(url, body):
        sent.update(body)
        return {"results": [{"vulns": [{"id": "GHSA-x"}]}]}

    monkeypatch.setattr(deps, "_post", post)
    monkeypatch.setattr(deps, "_get", lambda url: {
        "id": "GHSA-x", "aliases": ["CVE-2024-1"], "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"name": "jinja2"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.1.4"}]}]}]})
    found = [f for f in deps.scan("svc", tmp_path) if f.rule == "DEPS-CVE-FLOOR"]
    assert sent["queries"][0]["version"] == "3.0.0"
    assert found and found[0].severity == "medium"
    assert found[0].fix.edits[0].new == "jinja2>=3.1.4"
