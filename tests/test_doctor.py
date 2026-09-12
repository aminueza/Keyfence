import json
from pathlib import Path

from keyfence import doctor, runner
from keyfence.vault import Vault


def test_run_checks_produces_every_check(home, monkeypatch):
    monkeypatch.setattr(runner, "port_open", lambda port: False)
    checks = doctor.run_checks(8888, cwd=home)
    labels = [c.label for c in checks]
    assert labels[:3] == ["keyfence", "mitmdump", "CA certificate"]
    assert "Claude Code hook" in labels and "audit log" in labels
    assert "pi extension" in labels
    assert all(c.status in (doctor.OK, doctor.INFO, doctor.WARN, doctor.FAIL) for c in checks)


def test_render_summarises(home):
    checks = [doctor.Check(doctor.OK, "a", "fine"), doctor.Check(doctor.WARN, "b", "meh")]
    text = doctor.render(checks)
    assert "ok    a: fine" in text and "warn  b: meh" in text
    assert "No blocking problems, 1 warning(s)." in text
    assert "Everything keyfence exec needs is in place." in doctor.render([doctor.Check(doctor.OK, "a", "")])
    text = doctor.render([doctor.Check(doctor.OK, "a", ""), doctor.Check(doctor.INFO, "b", "later")])
    assert "info  b: later" in text and "info lines are optional" in text and "Everything keyfence exec needs" in text
    assert "1 problem(s) to fix" in doctor.render([doctor.Check(doctor.FAIL, "a", "")])


def test_ca_checks(tmp_path, monkeypatch):
    missing = tmp_path / "ca.pem"
    assert doctor.check_ca(missing).status == doctor.INFO
    missing.write_text("cert")
    assert doctor.check_ca(missing).status == doctor.OK
    monkeypatch.setattr(doctor.platform, "system", lambda: "Darwin")
    assert doctor.check_ca_trusted(missing, run=lambda cmd: (0, "")).status == doctor.OK
    assert doctor.check_ca_trusted(missing, run=lambda cmd: (44, "")).status == doctor.INFO
    assert doctor.check_ca_trusted(tmp_path / "none.pem", run=lambda cmd: (0, "")).status == doctor.INFO
    monkeypatch.setattr(doctor.platform, "system", lambda: "Linux")
    assert doctor.check_ca_trusted(missing).status == doctor.INFO


def test_config_and_vault_checks(home, write_config):
    assert doctor.check_config().status == doctor.OK
    assert "defaults" in doctor.check_config().detail
    write_config("mode: nonsense\n")
    assert doctor.check_config().status == doctor.FAIL
    assert doctor.check_vault().status == doctor.WARN
    Vault().add("registered-secret-value")
    assert doctor.check_vault().status == doctor.OK
    (home / "vault.json").write_text("x")
    assert doctor.check_vault().status == doctor.FAIL


def test_proxy_and_environment_checks(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "port_open", lambda port: True)
    assert doctor.check_proxy(8888).status == doctor.OK
    monkeypatch.setattr(runner, "port_open", lambda port: False)
    assert doctor.check_proxy(8888).status == doctor.INFO
    ca = tmp_path / "ca.pem"
    assert doctor.check_environment(8888, {}, ca).status == doctor.INFO
    assert doctor.check_environment(8888, {"HTTPS_PROXY": "http://other:1"}, ca).status == doctor.WARN
    assert doctor.check_environment(8888, {"HTTPS_PROXY": "http://127.0.0.1:8888"}, ca).status == doctor.WARN
    good = {"HTTPS_PROXY": "http://127.0.0.1:8888", "NODE_EXTRA_CA_CERTS": str(ca)}
    assert doctor.check_environment(8888, good, ca).status == doctor.OK


def test_local_mode_check(monkeypatch):
    monkeypatch.setattr(doctor.platform, "system", lambda: "Linux")
    assert doctor.check_local_mode().status == doctor.INFO
    monkeypatch.setattr(doctor.platform, "system", lambda: "Windows")
    assert doctor.check_local_mode().status == doctor.INFO
    monkeypatch.setattr(doctor.platform, "system", lambda: "Darwin")
    assert doctor.check_local_mode(run=lambda cmd: (1, "")).status == doctor.INFO
    waiting = "* * X org.mitmproxy.macos-redirector.network-extension [activated waiting for user]"
    assert doctor.check_local_mode(run=lambda cmd: (0, waiting)).status == doctor.WARN
    enabled = "* * X org.mitmproxy.macos-redirector.network-extension [activated enabled]"
    assert doctor.check_local_mode(run=lambda cmd: (0, enabled)).status == doctor.OK


def test_hook_check(home, tmp_path, monkeypatch):
    monkeypatch.setattr(doctor.hooks.Path, "home", classmethod(lambda cls: tmp_path))
    assert doctor.check_hook(tmp_path / "proj").status == doctor.INFO
    project = tmp_path / "proj" / ".claude"
    project.mkdir(parents=True)
    (project / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "Read", "hooks": [{"type": "command", "command": "keyfence hook claude-code"}]}]}}))
    check = doctor.check_hook(tmp_path / "proj")
    assert check.status == doctor.OK and "project" in check.detail
    (project / "settings.json").write_text("not json")
    assert doctor.check_hook(tmp_path / "proj").status == doctor.INFO


def test_audit_check(home, write_config):
    assert doctor.check_audit().status == doctor.INFO
    (home / "audit.log").write_text('{"a": 1}\n\n{"b": 2}\n')
    check = doctor.check_audit()
    assert check.status == doctor.OK and "2 request(s)" in check.detail
    write_config("mode: nonsense\n")
    assert doctor.check_audit().status == doctor.OK


def test_mitmdump_check(monkeypatch):
    monkeypatch.setattr(runner, "mitmdump_path", lambda: "/x/bin/mitmdump")
    assert doctor.check_mitmdump().status == doctor.OK
    monkeypatch.setattr(runner, "mitmdump_path", lambda: "mitmdump")
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    assert doctor.check_mitmdump().status == doctor.FAIL


def test_run_helper_handles_missing_command():
    code, out = doctor._run(["definitely-not-a-command-xyz"])
    assert code == 1 and out


def test_pi_extension_check(home, tmp_path, monkeypatch):
    from keyfence import pi
    monkeypatch.setattr(pi.Path, "home", classmethod(lambda cls: tmp_path))
    assert doctor.check_pi_extension(tmp_path / "proj").status == doctor.INFO
    assert pi.install(pi.extension_path(True, tmp_path / "proj"), "/bin/keyfence")
    check = doctor.check_pi_extension(tmp_path / "proj")
    assert check.status == doctor.OK and "project" in check.detail
    assert pi.install(pi.extension_path(False), "/bin/keyfence")
    assert "global, project" in doctor.check_pi_extension(tmp_path / "proj").detail
