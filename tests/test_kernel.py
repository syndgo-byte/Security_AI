import json
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from security import alerts, kernel, manifest, store


INSECURE = {
    "kernel.unprivileged_bpf_disabled": "0",
    "net.core.bpf_jit_harden": "0",
    "kernel.io_uring_disabled": "0",
    "kernel.kptr_restrict": "0",
    "kernel.dmesg_restrict": "0",
    "kernel.unprivileged_userns_clone": "1",
}


def write(h, rel, content):
    path = h.p(rel)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


@pytest.fixture
def host(tmp_path):
    h = kernel.Host(root=tmp_path / "r", state=tmp_path / "s")
    write(h, "proc/sys/kernel/osrelease", "5.10.50\n")
    for key, value in INSECURE.items():
        write(h, "proc/sys/" + key.replace(".", "/"), value + "\n")
    write(h, "proc/modules", "sctp 1 0 - Live 0x0\n")
    write(h, "etc/os-release", 'ID=test\nPRETTY_NAME="Test Linux"\n')
    return h


@pytest.mark.parametrize("version,exposed", [("5.10.50", True), ("6.9.1", False)])
def test_audit_cves(host, version, exposed):
    write(host, "proc/sys/kernel/osrelease", version)
    result = kernel.audit(host)
    rules = {f["rule"] for f in result["findings"]}
    for cve in ("KERN-CVE-2022-0847", "KERN-CVE-2024-1086"):
        assert (cve in rules) is exposed
    assert result["os"] == "Test Linux"


def test_audit_modules(host):
    findings = kernel.audit(host)["findings"]
    assert any(f["rule"] == "KERN-MOD-LOADED" and f["evidence"] == "sctp" for f in findings)
    assert any(f["rule"] == "KERN-MOD-BLACKLIST" and f["evidence"] == "tipc" for f in findings)


def test_harden_dry_run_writes_nothing(host):
    before = {p.relative_to(host.root): p.read_bytes() for p in host.root.rglob("*") if p.is_file()}
    result = kernel.harden(host)
    assert result["dry_run"] and result["diff"]
    assert not host.p(kernel.SYSCTL_CONF).exists()
    assert not host.p(kernel.MODPROBE_CONF).exists()
    assert not host.state.exists()
    assert before == {p.relative_to(host.root): p.read_bytes() for p in host.root.rglob("*") if p.is_file()}


def test_harden_apply_and_rollback(host):
    result = kernel.harden(host, dry_run=False)
    assert result["failed"] == []
    conf = host.p(kernel.SYSCTL_CONF).read_text(encoding="utf-8")
    assert len([ln for ln in conf.splitlines() if "=" in ln]) == 6
    for key, (want, *_) in kernel.TARGETS.items():
        assert f"{key} = {want}" in conf
        assert host.sysctl(key) == want
    modconf = host.p(kernel.MODPROBE_CONF).read_text(encoding="utf-8")
    assert "blacklist tipc\ninstall tipc /bin/false" in modconf
    assert "sctp" not in modconf
    assert result["skipped_loaded"] == ["sctp"]
    assert (host.state / "baseline.json").exists()
    assert kernel.load_baseline(host) == result["baseline"]
    restored = kernel.rollback(host)
    assert restored["ok"] and restored["runtime_restored"] == INSECURE
    assert not host.p(kernel.SYSCTL_CONF).exists()
    assert not host.p(kernel.MODPROBE_CONF).exists()
    assert not (host.state / "baseline.json").exists()
    assert {key: host.sysctl(key) for key in INSECURE} == INSECURE


def test_container_userns_policy(host):
    write(host, "run/docker.sock", "")
    assert kernel.USERNS_KEY not in kernel.harden(host)["sysctl"]
    assert "KERN-USERNS-CONTAINER" in {f["rule"] for f in kernel.audit(host)["findings"]}
    assert kernel.harden(host, userns=True)["sysctl"][kernel.USERNS_KEY] == "0"
    assert kernel.USERNS_KEY not in kernel.harden(host, userns=False)["sysctl"]


def test_drift_restores_sysctl_and_detects_module(host):
    kernel.harden(host, dry_run=False)
    assert host.set_sysctl("kernel.kptr_restrict", "0")
    events = kernel.check_drift(host)
    assert len(events) == 1 and events[0]["kind"] == "drift"
    assert host.sysctl("kernel.kptr_restrict") == "2"
    assert kernel.check_drift(host) == []
    write(host, "proc/modules", "sctp 1 0 - Live 0x0\ntipc 1 0 - Live 0x0\n")
    events = kernel.check_drift(host)
    assert len(events) == 1 and events[0]["kind"] == "module"
    assert "tipc" in events[0]["title"]


def audit_line(key="kh_bpf", uid=1000, exe="/tmp/x"):
    return (f'type=SYSCALL msg=audit(123:1): uid={uid} euid=0 auid=1000 pid=42 '
            f'comm="x" exe="{exe}" key="{key}"\n')


def test_parse_audit():
    line = audit_line()
    assert len(kernel.parse_audit([line])) == 1
    assert len(kernel.parse_audit([line, line])) == 1
    assert kernel.parse_audit([audit_line(uid=0)]) == []
    assert kernel.parse_audit([audit_line(key="kh_cred", exe="/usr/bin/sudo")]) == []
    events = kernel.parse_audit([audit_line(key="kh_cred")])
    assert len(events) == 1 and events[0]["level"] == "critical"


def test_read_audit_log_incremental(host):
    log = write(host, "var/log/audit/audit.log", audit_line())
    assert len(kernel.read_audit_log(host)) == 1
    assert kernel.read_audit_log(host) == []
    with log.open("a", encoding="utf-8") as fh:
        fh.write(audit_line(key="kh_iouring"))
    events = kernel.read_audit_log(host)
    assert len(events) == 1 and events[0]["kind"] == "kh_iouring"
    assert kernel.read_audit_log(host) == []


def test_non_linux_unsupported(monkeypatch):
    monkeypatch.setattr(kernel.sys, "platform", "win32")
    assert kernel.audit(kernel.Host(root="/"))["supported"] is False


def test_sandbox_host(tmp_path):
    root = tmp_path / "sandbox"
    h = kernel.sandbox_host(root)
    assert isinstance(h, kernel.Host) and h.supported and not h.real
    assert h.root == root and h.state == root / ".backups" / "kernel"
    assert not h.state.exists()
    assert {key: h.sysctl(key) for key in INSECURE} == INSECURE
    result = kernel.harden(h, dry_run=False)
    again = kernel.sandbox_host(root)
    assert again.sysctl("kernel.kptr_restrict") == "2"
    assert kernel.load_baseline(again) == result["baseline"]
    assert kernel.simulate_threat(again)["ok"]
    assert kernel.check_drift(again)[0]["kind"] == "drift"
    assert kernel.rollback(again)["ok"]
    assert {key: again.sysctl(key) for key in INSECURE} == INSECURE


def test_api_sandbox_audit(tmp_path, monkeypatch):
    from security import api
    from security.kernel import host as host_module

    monkeypatch.setattr(host_module, "PKG_ROOT", tmp_path)
    monkeypatch.setattr(kernel.sys, "platform", "win32")
    client = TestClient(api.app)
    try:
        response = client.get("/kernel/audit?sandbox=true")
        assert response.status_code == 200
        result = response.json()
        assert result["supported"] is True and result["os"] == "Sandbox Linux"
        assert "KERN-SYSCTL-KPTR_RESTRICT" in {f["rule"] for f in result["findings"]}
        assert not kernel.sandbox_host().state.exists()
    finally:
        client.close()


@pytest.mark.parametrize("kind", kernel.AUDIT_KEYS)
def test_sandbox_audit_simulation(host, kind):
    assert kernel.simulate_threat(host, kind)["ok"]
    assert kernel.read_audit_log(host)[0]["kind"] == kind


def test_sandbox_refuses_real_host():
    with pytest.raises(ValueError, match="filesystem root"):
        kernel.sandbox_host("/")
    assert kernel.simulate_threat(kernel.Host(), "kh_bpf")["ok"] is False


def test_api(host, tmp_path, monkeypatch):
    from security import api
    monkeypatch.setattr(kernel, "Host", lambda: host)
    monkeypatch.setenv("SECURITY_DB", str(tmp_path / "api.db"))
    monkeypatch.delenv("HUB_URL", raising=False)
    client = TestClient(api.app)
    response = client.get("/kernel/audit")
    assert response.status_code == 200 and response.json()["supported"]
    assert client.get("/kernel/baseline").status_code == 404
    result = client.post("/kernel/harden").json()
    assert result["dry_run"] and not host.state.exists()
    result = client.post("/kernel/harden?dry_run=true&userns=false").json()
    assert kernel.USERNS_KEY not in result["sysctl"]
    result = client.post("/kernel/harden?dry_run=false&userns=true").json()
    assert not result["dry_run"] and result["failed"] == []
    assert client.get("/kernel/baseline").json() == result["baseline"]
    host.set_sysctl("kernel.kptr_restrict", "0")
    result = client.post("/kernel/monitor").json()
    assert result["events"][0]["kind"] == "drift"
    con = store.connect()
    try:
        assert alerts.recent(con, "host")[0]["kind"] == "kernel.drift"
    finally:
        con.close()
    assert client.post("/kernel/rollback").json()["ok"]
    assert client.get("/kernel/baseline").status_code == 404
    client.close()


@pytest.mark.parametrize("flags,userns", [([], None), (["--block-userns"], True), (["--allow-userns"], False)])
def test_cli_harden_without_database(host, monkeypatch, capfd, flags, userns):
    from security import __main__ as cli
    monkeypatch.setattr(kernel, "Host", lambda: host)
    connect = Mock(side_effect=AssertionError("unexpected database connection"))
    monkeypatch.setattr(store, "connect", connect)
    expected = kernel.harden(host, userns=userns)
    assert cli.main(["kernel", "harden", *flags]) == 0
    assert json.loads(capfd.readouterr().out) == expected
    connect.assert_not_called()


@pytest.mark.parametrize("action", ["audit", "harden", "rollback", "baseline", "monitor"])
def test_cli_unsupported(action, monkeypatch, capfd):
    from security import __main__ as cli
    monkeypatch.setattr(kernel.sys, "platform", "win32")
    monkeypatch.setattr(store, "connect", Mock(side_effect=AssertionError("unexpected database connection")))
    assert cli.main(["kernel", action]) == 2
    assert json.loads(capfd.readouterr().out)["supported"] is False


def test_cli_monitor_low_noise(host, monkeypatch, capfd):
    from security import __main__ as cli
    monkeypatch.setattr(kernel, "Host", lambda: host)
    install = Mock(return_value={"ok": True})
    monkeypatch.setattr(kernel, "install_audit_rules", install)
    con = Mock()
    monkeypatch.setattr(store, "connect", Mock(return_value=con))
    event = {"supported": True, "ok": True, "events": [{"kind": "drift", "title": "변경"}]}
    monitor = Mock(side_effect=[{"supported": True, "ok": True, "events": []}, event])
    monkeypatch.setattr(kernel, "monitor_once", monitor)
    sleep = Mock(side_effect=[None, KeyboardInterrupt])
    monkeypatch.setattr(cli.time, "sleep", sleep)
    assert cli.main(["kernel", "monitor", "--interval", "3"]) == 0
    lines = capfd.readouterr().out.splitlines()
    assert len(lines) == 1 and json.loads(lines[0]) == event
    assert "변경" in lines[0]
    assert [call.args for call in sleep.call_args_list] == [(3,), (3,)]
    install.assert_called_once_with(host)
    monitor.assert_called_with(host, con)
    con.close.assert_called_once()


def test_cli_monitor_once(host, monkeypatch, capfd):
    from security import __main__ as cli
    kernel.harden(host, dry_run=False)
    monkeypatch.setattr(kernel, "Host", lambda: host)
    install = Mock(return_value={"ok": True})
    monkeypatch.setattr(kernel, "install_audit_rules", install)
    con = Mock()
    monkeypatch.setattr(store, "connect", Mock(return_value=con))
    assert cli.main(["kernel", "monitor", "--once"]) == 0
    assert json.loads(capfd.readouterr().out)["events"] == []
    install.assert_called_once_with(host)
    con.close.assert_called_once()


def test_kernel_manifest():
    result = manifest()
    assert "security.kernel" in result["provides"]
    tools = {tool["name"]: tool for tool in result["tools"]}
    for action, auth in (("audit", "service"), ("harden", "user"), ("rollback", "user")):
        tool = tools[f"security.kernel_{action}"]
        assert tool["auth_required"] == auth and tool["billing_model"] == "free"
