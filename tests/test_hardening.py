from security.scanners import hardening


def _rules(tmp_path):
    return {f.rule: f for f in hardening.scan("svc", tmp_path)}


def test_no_deploy_config_reported(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    assert set(_rules(tmp_path)) == {"HARD-NO-DEPLOY"}


def test_dockerfile_root_and_nonroot(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nCMD python app.py\n", encoding="utf-8")
    assert "HARD-DOCKER-ROOT" in _rules(tmp_path)
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nUSER app\n", encoding="utf-8")
    assert "HARD-DOCKER-ROOT" not in _rules(tmp_path)


def test_compose_risks(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: x\n    privileged: true\n    network_mode: host\n"
        "    cap_add:\n      - NET_RAW\n    ports:\n      - \"8000:8000\"\n      - \"127.0.0.1:9000:9000\"\n",
        encoding="utf-8")
    r = _rules(tmp_path)
    assert {"HARD-PRIVILEGED", "HARD-HOST-NET", "HARD-CAP-ADD", "HARD-PORT-PUBLIC", "HARD-NO-NEW-PRIV"} <= set(r)
    ports = [f for f in hardening.scan("svc", tmp_path) if f.rule == "HARD-PORT-PUBLIC"]
    assert len(ports) == 1 and "8000" in ports[0].title


def test_systemd_sandbox_fix(tmp_path):
    (tmp_path / "app.service").write_text("[Unit]\nDescription=x\n[Service]\nExecStart=/bin/app\n", encoding="utf-8")
    r = _rules(tmp_path)
    assert "HARD-SYSTEMD-ROOT" in r
    edit = r["HARD-SYSTEMD-SANDBOX"].fix.edits[0]
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6" in edit.new and "~bpf" in edit.new


def test_raw_socket_and_bind_all(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM x\nUSER app\n", encoding="utf-8")
    (tmp_path / "evil.py").write_text("import socket\ns = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)\n", encoding="utf-8")
    (tmp_path / "run.py").write_text("uvicorn.run(app, host=\"0.0.0.0\")\n# host='0.0.0.0'\n", encoding="utf-8")
    fs = hardening.scan("svc", tmp_path)
    assert [f.severity for f in fs if f.rule == "HARD-RAW-SOCKET"] == ["critical"]
    assert len([f for f in fs if f.rule == "HARD-BIND-ALL"]) == 1


def test_offline_scan_keeps_cve_findings(tmp_path, monkeypatch):
    from security import store
    from security.findings import Finding
    monkeypatch.setenv("SECURITY_DB", str(tmp_path / "t.db"))
    con = store.connect()
    cve = Finding("svc", "deps", "DEPS-CVE-FLOOR", "medium", "x", "requirements.txt", 1, "d", "x>=1")
    store.save_findings(con, "s1", "svc", [cve], ("deps",))
    store.save_findings(con, "s2", "svc", [], ("deps",), ("DEPS-CVE",))
    assert con.execute("select count(*) from findings").fetchone()[0] == 1
    store.save_findings(con, "s3", "svc", [], ("deps",))
    assert con.execute("select count(*) from findings").fetchone()[0] == 0
