import json
import os
import socket
import subprocess
from pathlib import Path

import pytest

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
    ca.write_text("cert")
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
    ca.write_text("cert")
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
    ca.write_text("cert")
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
    assert "already in use" in capsys.readouterr().out


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
    env = runner.child_env({"KEEP": "1", "HTTPS_PROXY": "old"}, 8888, tmp_path / "ca.pem")
    assert env["KEEP"] == "1"
    for name in runner.PROXY_ENV_VARS:
        assert env[name] == "http://127.0.0.1:8888"
    for name in runner.CA_ENV_VARS:
        assert env[name] == str(tmp_path / "ca.pem")


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
    ca.write_text("cert")
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
    ca.write_text("cert")
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
        assert all(not runner.addon_live(servers[name].server_port) for name in servers if name != "live")
    finally:
        for server in servers.values():
            server.shutdown()
            server.server_close()
    assert not runner.addon_live(servers["live"].server_port)


def test_run_times_out_and_kills_stuck_proxy(home, monkeypatch, tmp_path, capsys):
    proxy = FakeProxy(alive_after_terminate=True)
    monkeypatch.setattr(runner.subprocess, "Popen", lambda cmd, env, stdout, stderr: proxy)
    monkeypatch.setattr(runner, "port_open", lambda port: False)
    assert runner.run(["echo"], 8899, ca_cert=tmp_path / "missing.pem", timeout=0.05) == 1
    assert "did not come up" in capsys.readouterr().out
    assert (home / "proxy.log").exists()
    assert proxy.terminated and proxy.killed
