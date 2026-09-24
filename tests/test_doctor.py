import json
import os
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
    assert "keyfence selftest" not in doctor.render([doctor.Check(doctor.FAIL, "a", "")])
    assert "keyfence selftest sends a throwaway secret" in text
    assert doctor.format_checks(checks) == ["ok    a: fine", "warn  b: meh"]


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
    monkeypatch.setattr(runner, "addon_live", lambda port: True)
    assert doctor.check_proxy(8888).status == doctor.OK
    monkeypatch.setattr(runner, "addon_live", lambda port: False)
    assert doctor.check_proxy(8888).status == doctor.WARN
    assert "not scanned" in doctor.check_proxy(8888).detail
    monkeypatch.setattr(runner, "port_open", lambda port: False)
    assert doctor.check_proxy(8888).status == doctor.INFO
    ca = tmp_path / "ca.pem"
    assert doctor.check_environment(8888, {}, ca).status == doctor.INFO
    assert doctor.check_environment(8888, {"HTTPS_PROXY": "http://other:1"}, ca).status == doctor.WARN
    assert doctor.check_environment(8888, {"HTTPS_PROXY": "http://127.0.0.1:8888"}, ca).status == doctor.WARN
    node_only = {"HTTPS_PROXY": "http://127.0.0.1:8888", "NODE_EXTRA_CA_CERTS": str(ca)}
    partial = doctor.check_environment(8888, node_only, ca)
    assert partial.status == doctor.WARN
    assert "GIT_SSL_CAINFO" in partial.detail and "NODE_EXTRA_CA_CERTS" not in partial.detail
    good = {"HTTPS_PROXY": "http://127.0.0.1:8888", **{name: str(ca) for name in runner.CA_ENV_VARS}}
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


def test_mitmdump_check(tmp_path, monkeypatch):
    binary = tmp_path / "mitmdump"
    binary.write_text("")
    binary.chmod(0o755)
    monkeypatch.setattr(runner, "mitmdump_path", lambda: str(binary))
    assert doctor.check_mitmdump().status == doctor.OK
    if os.name == "posix":
        binary.chmod(0o644)
        check = doctor.check_mitmdump()
        assert check.status == doctor.FAIL and str(binary) in check.detail and "not executable" in check.detail
    binary.unlink()
    check = doctor.check_mitmdump()
    assert check.status == doctor.FAIL and str(binary) in check.detail and "does not exist" in check.detail
    monkeypatch.setattr(runner, "mitmdump_path", lambda: "mitmdump")
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    assert doctor.check_mitmdump().status == doctor.FAIL and "mitmdump not found on PATH" in doctor.check_mitmdump().detail
    monkeypatch.setattr(doctor.shutil, "which", lambda name: "/opt/bin/mitmdump")
    assert doctor.check_mitmdump().status == doctor.OK


def test_command_problem(tmp_path, monkeypatch):
    assert doctor.command_problem(str(tmp_path / "missing")) == "does not exist"
    plain = tmp_path / "plain"
    plain.write_text("")
    if os.name == "posix":
        plain.chmod(0o644)
        assert doctor.command_problem(str(plain)) == "is not executable"
    plain.chmod(0o755)
    assert doctor.command_problem(str(plain)) is None
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    assert doctor.command_problem("keyfence") == "not found on PATH"
    monkeypatch.setattr(doctor.shutil, "which", lambda name: "/usr/local/bin/keyfence")
    assert doctor.command_problem("keyfence") is None


def test_run_helper_handles_missing_command():
    code, out = doctor._run(["definitely-not-a-command-xyz"])
    assert code == 1 and out


def test_pi_extension_check(home, tmp_path, monkeypatch):
    from keyfence import pi
    monkeypatch.setattr(pi.Path, "home", classmethod(lambda cls: tmp_path))
    binary = tmp_path / "bin" / "keyfence"
    binary.parent.mkdir()
    binary.write_text("")
    binary.chmod(0o755)
    assert doctor.check_pi_extension(tmp_path / "proj").status == doctor.INFO
    assert pi.install(pi.extension_path(True, tmp_path / "proj"), str(binary))
    check = doctor.check_pi_extension(tmp_path / "proj")
    assert check.status == doctor.OK and "project" in check.detail and str(binary) in check.detail
    assert pi.install(pi.extension_path(False), str(binary))
    check = doctor.check_pi_extension(tmp_path / "proj")
    assert "global, project" in check.detail and check.detail.count(str(binary)) == 1


def test_pi_extension_check_fails_when_the_baked_command_is_gone(home, tmp_path, monkeypatch):
    from keyfence import pi
    monkeypatch.setattr(pi.Path, "home", classmethod(lambda cls: tmp_path))
    stale = "/home/victor/.local/share/uv/tools/keyfence/bin/keyfence"
    assert pi.install(pi.extension_path(False), stale)
    check = doctor.check_pi_extension(tmp_path / "proj")
    assert check.status == doctor.FAIL
    assert stale in check.detail and "does not exist" in check.detail and "install-hooks pi" in check.detail
    if os.name == "posix":
        plain = tmp_path / "keyfence"
        plain.write_text("")
        plain.chmod(0o644)
        assert pi.install(pi.extension_path(False), str(plain))
        check = doctor.check_pi_extension(tmp_path / "proj")
        assert check.status == doctor.FAIL and "is not executable" in check.detail
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    assert pi.install(pi.extension_path(False), "keyfence")
    assert "not found on PATH" in doctor.check_pi_extension(tmp_path / "proj").detail
    path = pi.extension_path(False)
    path.write_text(path.read_text().replace("const KEYFENCE = ", "const OTHER = "))
    check = doctor.check_pi_extension(tmp_path / "proj")
    assert check.status == doctor.FAIL and "holds no keyfence command" in check.detail


def test_installed_scopes_names_both_locations_for_each_agent(home, tmp_path, monkeypatch):
    from keyfence import pi
    monkeypatch.setattr(doctor.hooks.Path, "home", classmethod(lambda cls: tmp_path))
    project = tmp_path / "proj"
    scopes = doctor.installed_scopes("claude-code", project)
    assert [(scope, path) for scope, path, _ in scopes] == [
        ("global", tmp_path / ".claude" / "settings.json"), ("project", project / ".claude" / "settings.json")]
    assert not any(installed for _, _, installed in scopes)
    assert doctor.hooks.install(tmp_path / ".claude" / "settings.json")
    assert [installed for _, _, installed in doctor.installed_scopes("claude-code", project)] == [True, False]
    scopes = doctor.installed_scopes("pi", project)
    assert [(scope, path) for scope, path, _ in scopes] == [
        ("global", tmp_path / ".pi" / "agent" / "extensions" / "keyfence.ts"),
        ("project", project / ".pi" / "extensions" / "keyfence.ts")]
    assert pi.install(project / ".pi" / "extensions" / "keyfence.ts", "/bin/keyfence")
    assert [installed for _, _, installed in doctor.installed_scopes("pi", project)] == [False, True]
    (tmp_path / ".claude" / "settings.json").write_text("not json")
    assert not doctor.hook_installed(tmp_path / ".claude" / "settings.json")
    assert doctor.check_hook(project).status == doctor.INFO
