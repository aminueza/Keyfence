import json
import os
import socket
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from fakes import CA_PEM
from keyfence import runner
from keyfence.vault import Vault


def test_proxy_command():
    cmd = runner.proxy_command(9000, extra=["--set", "x=1"])
    assert Path(cmd[0]).name.lower() in ("mitmdump", "mitmdump.exe")
    assert "--listen-port" in cmd and "9000" in cmd
    assert cmd[-2:] == ["--set", "x=1"]
    assert str(runner.ADDON_PATH).endswith("addon.py")


def test_proxy_command_keeps_warnings_visible_and_flows_quiet():
    cmd = runner.proxy_command(9000)
    assert "-q" not in cmd and "--quiet" not in cmd
    assert cmd[1:5] == ["--set", "termlog_verbosity=warn", "--set", "flow_detail=0"]
    assert "-v" not in cmd and "--verbose" not in cmd


def test_listen_args():
    assert runner.listen_args(8888, None) == ["--listen-host", "127.0.0.1", "--listen-port", "8888"]
    assert runner.listen_args(8888, "*") == ["--mode", "regular@127.0.0.1:8888", "--mode", "local"]
    assert runner.listen_args(1, "claude,node") == ["--mode", "regular@127.0.0.1:1", "--mode", "local:claude,node"]
    cmd = runner.proxy_command(1, local="claude")
    assert "local:claude" in cmd and "--listen-port" not in cmd


def test_run_local_defaults_to_command_name(home, monkeypatch, tmp_path):
    seen = {}
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    monkeypatch.setattr(runner.subprocess, "Popen",
                        lambda cmd, env, stdout, stderr: seen.update(cmd=cmd) or FakeProxy())
    monkeypatch.setattr(runner, "port_open", lambda port: "cmd" in seen)
    monkeypatch.setattr(runner, "addon_live", lambda port: True)
    monkeypatch.setattr(runner.subprocess, "call", lambda command, env: 0)
    assert runner.run(["/usr/local/bin/claude", "-p"], 8899, ca_cert=ca, timeout=1, local="") == 0
    assert "local:claude" in seen["cmd"]


def test_confdir_is_passed_to_mitmdump(tmp_path):
    assert "confdir=" not in " ".join(runner.proxy_command(1, confdir=None))
    cmd = runner.proxy_command(1, confdir=tmp_path / "conf")
    assert cmd[cmd.index(f"confdir={tmp_path / 'conf'}") - 1] == "--set"


def test_run_record_and_linger(home, monkeypatch, tmp_path, capsys):
    seen = {}
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    proxy = FakeProxy()
    monkeypatch.setattr(runner.subprocess, "Popen",
                        lambda cmd, env, stdout, stderr: seen.update(cmd=cmd) or proxy)
    monkeypatch.setattr(runner, "port_open", lambda port: "cmd" in seen)
    monkeypatch.setattr(runner, "addon_live", lambda port: True)
    monkeypatch.setattr(runner.subprocess, "call", lambda command, env: 0)
    slept = []
    monkeypatch.setattr(runner.time, "sleep", lambda s: slept.append(s))
    assert runner.run(["echo"], 8899, ca_cert=ca, timeout=1, record=tmp_path / "rec" / "s.flows", linger=45) == 0
    assert seen["cmd"][-2:] == ["-w", str(tmp_path / "rec" / "s.flows")]
    if os.name == "posix":
        import stat
        assert stat.S_IMODE((tmp_path / "rec" / "s.flows").stat().st_mode) == 0o600
    assert slept == [45] and "keeping the proxy up for 45s" in capsys.readouterr().out
    assert proxy.terminated


def _wire_fake_proxy(monkeypatch, tmp_path):
    seen = {}
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    monkeypatch.setattr(runner.subprocess, "Popen",
                        lambda cmd, env, stdout, stderr: seen.update(cmd=cmd) or FakeProxy())
    monkeypatch.setattr(runner, "port_open", lambda port: "cmd" in seen)
    monkeypatch.setattr(runner, "addon_live", lambda port: True)
    monkeypatch.setattr(runner.subprocess, "call", lambda command, env: 0)
    return ca


@pytest.mark.parametrize("mode", ["audit", "block"])
def test_run_record_says_on_stderr_when_the_file_will_hold_secrets(home, write_config, monkeypatch, tmp_path, capsys, mode):
    write_config(f"mode: {mode}\n")
    ca = _wire_fake_proxy(monkeypatch, tmp_path)
    record = tmp_path / "rec" / "s.flows"
    assert runner.run(["echo"], 8899, ca_cert=ca, timeout=1, record=record) == 0
    out, err = capsys.readouterr()
    assert err == f"keyfence: mode is {mode}, so {record} will hold {runner.RECORD_NOTICES[mode]} (file mode 0600)\n"
    assert "secrets included, in clear text" in err
    assert out == ""
    assert record.exists()


@pytest.mark.parametrize("config", ["mode: redact\n", "mode: placeholder\n", None])
def test_run_record_stays_quiet_when_the_file_will_not_hold_secrets(home, write_config, monkeypatch, tmp_path, capsys, config):
    if config is not None:
        write_config(config)
    ca = _wire_fake_proxy(monkeypatch, tmp_path)
    assert runner.run(["echo"], 8899, ca_cert=ca, timeout=1, record=tmp_path / "s.flows") == 0
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("config", ["mode: nonsense\n", "mode: [\n"])
def test_run_refuses_an_invalid_config_before_starting_anything(home, write_config, monkeypatch, tmp_path, capsys, config):
    write_config(config)
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *a, **k: pytest.fail("must not start the proxy"))
    monkeypatch.setattr(runner, "port_open", lambda port: False)
    assert runner.run(["echo"], 8899, ca_cert=tmp_path / "ca.pem", timeout=1, record=tmp_path / "s.flows") == 1
    out, err = capsys.readouterr()
    assert out.startswith("error: ") and err == ""
    assert not (tmp_path / "s.flows").exists()


def test_run_without_record_says_nothing_in_audit_mode(home, write_config, monkeypatch, tmp_path, capsys):
    write_config("mode: audit\n")
    ca = _wire_fake_proxy(monkeypatch, tmp_path)
    assert runner.run(["echo"], 8899, ca_cert=ca, timeout=1) == 0
    assert capsys.readouterr().err == ""


def test_record_notice_reads_the_config_keyfence_exec_will_use(home, write_config):
    assert runner.record_notice(Path("s.flows")) is None
    write_config("mode: audit\n")
    notice = runner.record_notice(Path("s.flows"))
    assert notice.startswith("keyfence: mode is audit, so s.flows will hold ")
    assert notice.endswith("(file mode 0600)")
    write_config("mode: redact\n")
    assert runner.record_notice(Path("s.flows")) is None


def test_run_refuses_busy_port(home, monkeypatch, capsys):
    monkeypatch.setattr(runner, "port_open", lambda port: True)
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *a, **k: pytest.fail("must not start"))
    assert runner.run(["echo"], 8899) == 1
    out, err = capsys.readouterr()
    assert out == "Port 8899 is already in use. Pick another one with -p.\n"
    assert err == ""


def test_free_port_returns_a_port_nothing_listens_on():
    port = runner.free_port()
    assert 1024 < port < 65536 and not runner.port_open(port)


def test_pick_port_returns_the_preferred_port_when_free():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    assert runner.pick_port(port) == port
    assert runner.DEFAULT_PORT == 8888


def test_pick_port_returns_another_port_when_the_preferred_one_is_busy():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        busy = s.getsockname()[1]
        chosen = runner.pick_port(busy)
        assert chosen != busy and 1024 < chosen < 65536 and not runner.port_open(chosen)


def _run_without_port(monkeypatch, tmp_path, default_busy):
    seen = {"probed": []}
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    monkeypatch.setattr(runner.subprocess, "Popen",
                        lambda cmd, env, stdout, stderr: seen.update(proxy_cmd=cmd) or FakeProxy())
    monkeypatch.setattr(runner, "port_open",
                        lambda port: (default_busy and port == runner.DEFAULT_PORT) or "proxy_cmd" in seen)
    monkeypatch.setattr(runner, "addon_live", lambda port: seen["probed"].append(port) or True)
    monkeypatch.setattr(runner.subprocess, "call", lambda command, env: seen.update(env=env) or 0)
    assert runner.run(["echo"], ca_cert=ca, timeout=1) == 0
    seen["port"] = int(seen["proxy_cmd"][seen["proxy_cmd"].index("--listen-port") + 1])
    return seen


def test_run_without_a_port_uses_the_default_when_it_is_free(home, monkeypatch, tmp_path, capsys):
    seen = _run_without_port(monkeypatch, tmp_path, default_busy=False)
    assert seen["port"] == 8888
    assert seen["env"]["HTTPS_PROXY"] == "http://127.0.0.1:8888"
    assert seen["probed"] == [8888]
    assert capsys.readouterr().err == ""


def test_run_without_a_port_falls_back_when_the_default_is_busy(home, monkeypatch, tmp_path, capsys):
    seen = _run_without_port(monkeypatch, tmp_path, default_busy=True)
    port = seen["port"]
    assert port != 8888
    assert seen["env"]["HTTPS_PROXY"] == f"http://127.0.0.1:{port}"
    assert seen["env"]["HTTP_PROXY"] == f"http://127.0.0.1:{port}"
    assert seen["probed"] == [port]
    assert capsys.readouterr().err == f"keyfence: port 8888 is busy, using {port}\n"


def test_mitmdump_path_prefers_interpreter_bindir(tmp_path, monkeypatch):
    fake = tmp_path / "mitmdump"
    fake.write_text("")
    monkeypatch.setattr(runner.sys, "executable", str(tmp_path / "python"))
    assert runner.mitmdump_path() == str(fake)


def test_mitmdump_path_falls_back_to_path_then_bare_name(tmp_path, monkeypatch):
    monkeypatch.setattr(runner.sys, "executable", str(tmp_path / "python"))
    monkeypatch.setattr(runner.shutil, "which", lambda _name: "/opt/bin/mitmdump")
    assert runner.mitmdump_path() == "/opt/bin/mitmdump"
    monkeypatch.setattr(runner.shutil, "which", lambda _name: None)
    assert runner.mitmdump_path() == "mitmdump"


def test_port_open_false_on_closed_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    assert runner.port_open(port) is False


def test_port_open_true_on_listening_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        assert runner.port_open(s.getsockname()[1]) is True


def test_wait_for():
    calls = []

    def ready():
        calls.append(1)
        return len(calls) >= 3

    assert runner.wait_for(ready, timeout=2, interval=0.01)
    assert runner.wait_for(lambda: False, timeout=0.05, interval=0.01) is False


def test_child_env(tmp_path):
    ca = tmp_path / "ca.pem"
    bundle = tmp_path / "ca-bundle.pem"
    env = runner.child_env({"KEEP": "1", "HTTPS_PROXY": "old"}, 8888, ca, bundle)
    assert env["KEEP"] == "1"
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
        assert env[name] == "http://127.0.0.1:8888"
    for name in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "CARGO_HTTP_CAINFO"):
        assert env[name] == str(bundle)
    assert env["NODE_EXTRA_CA_CERTS"] == str(ca)
    assert set(runner.CA_ENV_VARS) == {"NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "CARGO_HTTP_CAINFO"}


def test_cargo_gets_the_bundle_in_its_own_variable_because_it_reads_neither_of_the_others(tmp_path):
    ca = tmp_path / "ca.pem"
    bundle = tmp_path / "ca-bundle.pem"
    env = runner.child_env({}, 8888, ca, bundle)
    assert env["CARGO_HTTP_CAINFO"] == str(bundle)
    assert env["CARGO_HTTP_CAINFO"] != str(ca)
    assert "CARGO_HTTP_CAINFO" in runner.BUNDLE_ENV_VARS
    assert "CARGO_HTTP_CAINFO" in runner.CA_ENV_VARS


def test_child_env_tells_git_for_windows_to_use_the_ca(tmp_path):
    ca = tmp_path / "ca.pem"
    bundle = tmp_path / "ca-bundle.pem"
    plain = runner.child_env({}, 8888, ca, bundle, windows=False)
    assert not any(name.startswith("GIT_CONFIG_") for name in plain)
    env = runner.child_env({}, 8888, ca, bundle, windows=True)
    assert env["GIT_CONFIG_COUNT"] == "1"
    assert env["GIT_CONFIG_KEY_0"] == "http.schannelUseSSLCAInfo" and env["GIT_CONFIG_VALUE_0"] == "true"
    env = runner.child_env({"GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "a.b", "GIT_CONFIG_VALUE_0": "1",
                            "GIT_CONFIG_KEY_1": "c.d", "GIT_CONFIG_VALUE_1": "2"}, 8888, ca, bundle, windows=True)
    assert env["GIT_CONFIG_COUNT"] == "3" and env["GIT_CONFIG_KEY_0"] == "a.b" and env["GIT_CONFIG_KEY_1"] == "c.d"
    assert env["GIT_CONFIG_KEY_2"] == "http.schannelUseSSLCAInfo" and env["GIT_CONFIG_VALUE_2"] == "true"
    for broken in ("garbage", "-3"):
        env = runner.child_env({"GIT_CONFIG_COUNT": broken}, 8888, ca, bundle, windows=True)
        assert env["GIT_CONFIG_COUNT"] == "1" and env["GIT_CONFIG_KEY_0"] == "http.schannelUseSSLCAInfo"


def _roots(tmp_path, name="roots.pem", text=CA_PEM):
    path = tmp_path / name
    path.write_text(text)
    return path


def test_bundle_holds_the_system_roots_and_then_the_mitm_ca(home, tmp_path, only_roots):
    roots = _roots(tmp_path)
    only_roots(roots)
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    path, label = runner.ensure_bundle(ca)
    assert path == home / "ca-bundle.pem"
    assert path.read_text() == f"{roots.read_text().rstrip()}\n{ca.read_text().rstrip()}\n"
    assert label == f"{roots} (the OpenSSL default) plus {ca}"


def test_bundle_is_rebuilt_when_the_mitm_ca_changes(home, tmp_path, only_roots):
    only_roots(_roots(tmp_path))
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    path, _ = runner.ensure_bundle(ca)
    stale = path.read_text()
    ca.write_text(CA_PEM.replace("dGVzdC1vbmx5", "bmV3LW1pdG0="))
    again, _ = runner.ensure_bundle(ca)
    assert again == path
    assert path.read_text() != stale
    assert "bmV3LW1pdG0=" in path.read_text() and "dGVzdC1vbmx5" in path.read_text()


def test_bundle_is_left_alone_when_nothing_changed(home, tmp_path, only_roots):
    only_roots(_roots(tmp_path))
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    path, _ = runner.ensure_bundle(ca)
    before = path.stat()
    text = path.read_text()
    runner.ensure_bundle(ca)
    after = path.stat()
    assert (after.st_mtime_ns, after.st_ino) == (before.st_mtime_ns, before.st_ino)
    assert path.read_text() == text


def test_bundle_is_rebuilt_when_the_system_roots_change(home, tmp_path, only_roots):
    roots = _roots(tmp_path)
    only_roots(roots)
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    path, _ = runner.ensure_bundle(ca)
    roots.write_text(CA_PEM.replace("dGVzdC1vbmx5", "cm9vdHMtY2hhbmdlZA=="))
    runner.ensure_bundle(ca)
    assert "cm9vdHMtY2hhbmdlZA==" in path.read_text()


def test_bundle_is_not_world_writable_under_a_permissive_umask(home, tmp_path, only_roots):
    only_roots(_roots(tmp_path))
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    if os.name != "posix":
        pytest.skip("umask modes are not meaningful here")
    previous = os.umask(0)
    try:
        path, _ = runner.ensure_bundle(ca)
    finally:
        os.umask(previous)
    assert stat.S_IMODE(path.stat().st_mode) == 0o644


def test_bundle_left_world_writable_is_tightened_on_the_next_write(home, tmp_path, only_roots):
    roots = _roots(tmp_path)
    only_roots(roots)
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    path = home / runner.BUNDLE_NAME
    path.write_text("left behind by something else")
    path.chmod(0o666)
    runner.ensure_bundle(ca)
    assert path.read_text() != "left behind by something else"
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o644


def test_bundle_refuses_to_be_written_when_there_is_no_system_roots(home, tmp_path, only_roots):
    missing = "/nowhere/ca-bundle.crt"
    only_roots(paths=(missing,))
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    with pytest.raises(runner.BundleError) as raised:
        runner.ensure_bundle(ca)
    message = str(raised.value)
    assert "no system trust store" in message and "certifi" in message
    assert missing in message
    assert not (home / runner.BUNDLE_NAME).exists()
    assert "only the mitmproxy CA" in message


def test_bundle_ignores_a_roots_path_that_is_the_mitm_ca_or_the_bundle(home, tmp_path, only_roots):
    linux = _roots(tmp_path, "linux.pem")
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    only_roots(cafile=ca, paths=(str(linux),))
    assert runner.system_roots((ca,))[0] == linux
    only_roots(cafile=home / runner.BUNDLE_NAME, paths=(str(linux),))
    assert runner.system_roots((home / runner.BUNDLE_NAME,))[0] == linux


def test_bundle_ignores_a_roots_file_without_a_certificate(home, tmp_path, only_roots):
    empty = _roots(tmp_path, "empty.pem", "not a certificate at all")
    real = _roots(tmp_path, "real.pem")
    only_roots(cafile=empty, paths=(str(real),))
    assert runner.system_roots()[0] == real


def test_a_roots_file_keyfence_cannot_read_is_skipped(home, tmp_path, only_roots):
    unreadable = _roots(tmp_path, "unreadable.pem")
    real = _roots(tmp_path, "real.pem")
    only_roots(cafile=unreadable, paths=(str(real),))
    if os.name != "posix" or os.geteuid() == 0:
        pytest.skip("a root user reads a file that has no permissions")
    unreadable.chmod(0o000)
    assert runner.system_roots() == (real, "a system path")


def test_system_roots_prefers_certifi_then_the_openssl_default_then_the_linux_paths(monkeypatch, tmp_path):
    linux = _roots(tmp_path, "linux.pem")
    openssl = _roots(tmp_path, "openssl.pem")
    certifi_roots = _roots(tmp_path, "certifi.pem")
    monkeypatch.setattr(runner.ssl, "get_default_verify_paths",
                        lambda: SimpleNamespace(cafile=str(openssl), capath=None))
    monkeypatch.setattr(runner, "SYSTEM_CA_PATHS", (str(linux),))
    monkeypatch.setitem(sys.modules, "certifi", None)
    assert runner.system_roots() == (openssl, "the OpenSSL default")
    monkeypatch.setitem(sys.modules, "certifi", SimpleNamespace(where=lambda: str(certifi_roots)))
    assert runner.system_roots() == (certifi_roots, "certifi")
    monkeypatch.setitem(sys.modules, "certifi", None)
    monkeypatch.setattr(runner.ssl, "get_default_verify_paths",
                        lambda: SimpleNamespace(cafile=None, capath="/some/capath"))
    assert runner.system_roots() == (linux, "a system path")


def test_bundle_refuses_a_ca_file_that_holds_no_certificate(home, tmp_path, only_roots):
    only_roots(_roots(tmp_path))
    ca = tmp_path / "ca.pem"
    ca.write_text("truncated")
    with pytest.raises(runner.BundleError) as raised:
        runner.ensure_bundle(ca)
    assert "holds no certificate" in str(raised.value)
    assert not (home / runner.BUNDLE_NAME).exists()


def test_bundle_reports_a_roots_file_it_cannot_read(home, monkeypatch, tmp_path, only_roots):
    gone = tmp_path / "removed.pem"
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    only_roots(gone)
    monkeypatch.setattr(runner, "_holds_cert", lambda path: True)
    with pytest.raises(runner.BundleError) as raised:
        runner.ensure_bundle(ca)
    assert "could not be read" in str(raised.value) and str(gone) in str(raised.value)


def test_run_hands_the_child_the_bundle_and_the_single_certificate(home, write_config, monkeypatch, tmp_path):
    write_config("mode: redact\n")
    ca = _wire_fake_proxy(monkeypatch, tmp_path)
    seen = {}
    monkeypatch.setattr(runner.subprocess, "call", lambda command, env: seen.update(env=env) or 0)
    assert runner.run(["echo"], 8899, ca_cert=ca, timeout=1) == 0
    bundle = home / runner.BUNDLE_NAME
    assert bundle.exists() and bundle.read_text().endswith(ca.read_text())
    assert seen["env"]["SSL_CERT_FILE"] == str(bundle)
    assert seen["env"]["NODE_EXTRA_CA_CERTS"] == str(ca)


def test_run_refuses_to_start_the_command_when_the_bundle_cannot_be_built(home, write_config, monkeypatch, tmp_path, capsys, only_roots):
    write_config("mode: redact\n")
    seen = {}
    proxy = FakeProxy()
    monkeypatch.setattr(runner.subprocess, "Popen",
                        lambda cmd, env, stdout, stderr: seen.update(cmd=cmd) or proxy)
    monkeypatch.setattr(runner, "port_open", lambda port: "cmd" in seen)
    monkeypatch.setattr(runner, "addon_live", lambda port: True)
    monkeypatch.setattr(runner.subprocess, "call", lambda *a, **k: pytest.fail("must not start the command"))
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    only_roots(paths=("/nowhere/ca-bundle.crt",))
    assert runner.run(["echo"], 8899, ca_cert=ca, timeout=1) == 1
    out, err = capsys.readouterr()
    assert "no system trust store" in out and err == ""
    assert not (home / runner.BUNDLE_NAME).exists()
    assert proxy.terminated


def test_build_env_vault_shares_salt_with_main(home):
    main = Vault()
    main.add("main-secret-value-1")
    built = runner.build_env_vault({"GITHUB_TOKEN": "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", "HOME": "/x"})
    path = built.path
    assert path.parent == home / "env"
    try:
        data = json.loads(path.read_text())
        assert bytes.fromhex(data["salt"]) == main.salt
        env_vault = Vault(path=path)
        assert env_vault.contains("ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")
        assert not env_vault.contains("main-secret-value-1")
    finally:
        built.remove_files()
    assert not path.exists() and not built.lock_path.exists()


def test_build_env_vault_on_a_fresh_machine_saves_the_salt_the_proxy_will_load(home):
    assert not (home / "vault.json").exists()
    built = runner.build_env_vault({"GITHUB_TOKEN": "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"})
    try:
        assert Vault().salt == Vault(path=built.path).salt
    finally:
        built.remove_files()


def test_build_env_vault_honours_ignore_lists(home, write_config):
    from keyfence.config import Config
    write_config("ignore_keys: [DB_HOST]\nignore_values: [db.internal.example.com]\n")
    environ = {"DB_HOST": "internal-host-value-2026", "OTHER_HOST": "db.internal.example.com",
               "GITHUB_TOKEN": "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"}
    plain = runner.build_env_vault(environ, everything=True)
    try:
        assert plain.count() == 3
    finally:
        plain.remove_files()
    built = runner.build_env_vault(environ, everything=True, config=Config.load())
    try:
        assert built.count() == 1 and built.contains("ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")
        assert not built.contains("internal-host-value-2026") and not built.contains("db.internal.example.com")
    finally:
        built.remove_files()


def test_run_loads_the_config_for_the_env_snapshot(home, write_config, monkeypatch, capsys):
    write_config("ignore_keys: [DB_HOST]\n")
    seen = {}

    def fake_build(environ, everything, config):
        seen["config"] = config
        raise KeyboardInterrupt

    monkeypatch.setattr(runner, "port_open", lambda port: False)
    monkeypatch.setattr(runner, "build_env_vault", fake_build)
    with pytest.raises(KeyboardInterrupt):
        runner.run(["true"], 8899)
    assert seen["config"].ignore_keys == ["DB_HOST"]
    write_config("mode: nonsense\n")
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *a, **k: pytest.fail("must not start the proxy"))
    assert runner.run(["true"], 8899) == 1
    assert "error: invalid mode" in capsys.readouterr().out


def test_stale_env_vaults_are_swept_on_next_exec(home):
    directory = home / "env"
    directory.mkdir()
    old = directory / "keyfence-env-old.json"
    old.write_text("{}")
    os.utime(old, (1, 1))
    fresh = directory / "keyfence-env-fresh.json"
    fresh.write_text("{}")
    other = directory / "unrelated.txt"
    other.write_text("x")
    assert runner.sweep_stale_env_vaults(directory) == 1
    assert not old.exists() and fresh.exists() and other.exists()
    assert runner.sweep_stale_env_vaults(home / "missing") == 0
    built = runner.build_env_vault({"HOME": "/x"})
    assert built.path.parent == directory
    built.remove_files()


class FakeProxy:
    def __init__(self, alive_after_terminate=False):
        self.terminated = False
        self.killed = False
        self.alive_after_terminate = alive_after_terminate

    def poll(self):
        return None if not self.terminated else 0

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        if self.alive_after_terminate:
            raise subprocess.TimeoutExpired("mitmdump", timeout)

    def kill(self):
        self.killed = True


def test_run_success(home, monkeypatch, tmp_path):
    proxy = FakeProxy()
    seen = {}
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    monkeypatch.setattr(runner.subprocess, "Popen",
                        lambda cmd, env, stdout, stderr: seen.update(proxy_cmd=cmd, proxy_env=env, stdout=stdout) or proxy)
    monkeypatch.setattr(runner, "port_open", lambda port: "proxy_cmd" in seen)
    monkeypatch.setattr(runner, "addon_live", lambda port: True)

    def fake_call(command, env):
        seen["command"] = command
        seen["env"] = env
        return 7

    monkeypatch.setattr(runner.subprocess, "call", fake_call)
    code = runner.run(["echo", "hi"], 8899, ca_cert=ca, timeout=1)
    assert code == 7
    assert seen["command"] == ["echo", "hi"]
    assert seen["env"]["HTTPS_PROXY"] == "http://127.0.0.1:8899"
    assert runner.ENV_VAULT_VAR in seen["proxy_env"]
    assert proxy.terminated
    assert seen["stdout"].closed
    assert (home / "proxy.log").exists()


def test_run_when_mitmdump_missing(home, monkeypatch, capsys):
    def missing(*_args, **_kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(runner.subprocess, "Popen", missing)
    assert runner.run(["echo"], 8899) == 1
    assert "mitmdump not found" in capsys.readouterr().out


def test_run_refuses_to_start_the_command_when_the_addon_is_not_answering(home, monkeypatch, tmp_path, capsys):
    proxy = FakeProxy()
    seen = {}
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    monkeypatch.setattr(runner.subprocess, "Popen", lambda cmd, env, stdout, stderr: seen.update(cmd=cmd) or proxy)
    monkeypatch.setattr(runner, "port_open", lambda port: "cmd" in seen)
    monkeypatch.setattr(runner, "addon_live", lambda port: False)
    monkeypatch.setattr(runner.subprocess, "call", lambda command, env: pytest.fail("must not start the command"))
    assert runner.run(["echo"], 8899, ca_cert=ca, timeout=0.05) == 1
    assert "addon is not answering" in capsys.readouterr().out
    assert proxy.terminated


def _serve(status, body):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            payload = body.encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_addon_live_probe_distinguishes_keyfence_from_anything_else():
    servers = {
        "live": _serve(200, '{"keyfence": "0.6.0.dev0", "mode": "redact", "hosts": 9}'),
        "plain_proxy": _serve(200, '{"upstream_received": {}}'),
        "blocked": _serve(403, '{"error": {"type": "keyfence_blocked"}}'),
        "not_json": _serve(200, "<html>bad gateway</html>"),
        "json_list": _serve(200, '["keyfence"]'),
    }
    try:
        assert runner.addon_live(servers["live"].server_port)
        assert runner.probe(servers["live"].server_port) == {"keyfence": "0.6.0.dev0", "mode": "redact", "hosts": 9}
        assert all(not runner.addon_live(servers[name].server_port) for name in servers if name != "live")
        assert all(runner.probe(servers[name].server_port) is None for name in servers if name != "live")
    finally:
        for server in servers.values():
            server.shutdown()
            server.server_close()
    assert not runner.addon_live(servers["live"].server_port)


def test_the_addon_probe_goes_to_the_host_it_is_given():
    server = _serve(200, '{"keyfence": "0.6.0.dev0", "mode": "redact", "hosts": 9}')
    try:
        assert runner.addon_live(server.server_port)
        assert runner.probe(server.server_port) == {"keyfence": "0.6.0.dev0", "mode": "redact", "hosts": 9}
        assert runner.addon_live(server.server_port, "127.0.0.1")
        assert not runner.addon_live(server.server_port, "keyfence.invalid")
        assert runner.probe(server.server_port, "keyfence.invalid") is None
    finally:
        server.shutdown()
        server.server_close()


def test_start_proxy_reports_each_stage_and_stops_what_it_started(monkeypatch, tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    log = (tmp_path / "log").open("w")
    started = []
    monkeypatch.setattr(runner.subprocess, "Popen",
                        lambda cmd, env, stdout, stderr: started.append((cmd, env, stdout)) or started[-1] and FakeProxy())
    monkeypatch.setattr(runner, "port_open", lambda port: False)
    with pytest.raises(runner.ProxyError) as exc:
        runner.start_proxy(8899, {"A": "1"}, log, timeout=0.05, ca_cert=ca)
    assert exc.value.stage == runner.NOT_UP and "did not come up" in exc.value.message and str(exc.value) == exc.value.message
    assert started[-1][1] == {"A": "1"} and started[-1][2] is log
    monkeypatch.setattr(runner, "port_open", lambda port: True)
    monkeypatch.setattr(runner, "addon_live", lambda port: False)
    with pytest.raises(runner.ProxyError) as exc:
        runner.start_proxy(8899, {}, log, timeout=0.05, ca_cert=ca, local="claude", extra=["-w", "x"])
    assert exc.value.stage == runner.NOT_LIVE and "local:claude" in started[-1][0] and started[-1][0][-2:] == ["-w", "x"]
    monkeypatch.setattr(runner, "addon_live", lambda port: True)
    proxy = runner.start_proxy(8899, {}, log, timeout=0.05, ca_cert=ca)
    assert isinstance(proxy, FakeProxy) and not proxy.terminated
    runner.stop_proxy(proxy)
    assert proxy.terminated
    runner.stop_proxy(proxy)
    stuck = FakeProxy(alive_after_terminate=True)
    runner.stop_proxy(stuck)
    assert stuck.terminated and stuck.killed

    def missing(*_args, **_kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(runner.subprocess, "Popen", missing)
    with pytest.raises(runner.ProxyError) as exc:
        runner.start_proxy(8899, {}, log, timeout=0.05, ca_cert=ca)
    assert exc.value.stage == runner.MISSING and "mitmdump not found" in exc.value.message
    log.close()


def test_run_times_out_and_kills_stuck_proxy(home, monkeypatch, tmp_path, capsys):
    proxy = FakeProxy(alive_after_terminate=True)
    monkeypatch.setattr(runner.subprocess, "Popen", lambda cmd, env, stdout, stderr: proxy)
    monkeypatch.setattr(runner, "port_open", lambda port: False)
    assert runner.run(["echo"], 8899, ca_cert=tmp_path / "missing.pem", timeout=0.05) == 1
    assert "did not come up" in capsys.readouterr().out
    assert (home / "proxy.log").exists()
    assert proxy.terminated and proxy.killed
