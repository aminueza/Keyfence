import json
import socket
import subprocess

import pytest

from keyfence import runner
from keyfence.vault import Vault


def test_proxy_command():
    cmd = runner.proxy_command(9000, extra=["--set", "x=1"])
    assert cmd[0].endswith("mitmdump") or cmd[0].endswith("mitmdump.exe")
    assert cmd[1] == "-q"
    assert "--listen-port" in cmd and "9000" in cmd
    assert cmd[-2:] == ["--set", "x=1"]
    assert str(runner.ADDON_PATH).endswith("addon.py")


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
    monkeypatch.setattr(runner.subprocess, "call", lambda command, env: 0)
    assert runner.run(["/usr/local/bin/claude", "-p"], 8899, ca_cert=ca, timeout=1, local="") == 0
    assert "local:claude" in seen["cmd"]


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
    path = runner.build_env_vault({"GITHUB_TOKEN": "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", "HOME": "/x"})
    try:
        data = json.loads(path.read_text())
        assert bytes.fromhex(data["salt"]) == main.salt
        env_vault = Vault(path=path)
        assert env_vault.contains("ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")
        assert not env_vault.contains("main-secret-value-1")
    finally:
        path.unlink()


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


def test_run_times_out_and_kills_stuck_proxy(home, monkeypatch, tmp_path, capsys):
    proxy = FakeProxy(alive_after_terminate=True)
    monkeypatch.setattr(runner.subprocess, "Popen", lambda cmd, env, stdout, stderr: proxy)
    monkeypatch.setattr(runner, "port_open", lambda port: False)
    assert runner.run(["echo"], 8899, ca_cert=tmp_path / "missing.pem", timeout=0.05) == 1
    assert "did not come up" in capsys.readouterr().out
    assert (home / "proxy.log").exists()
    assert proxy.terminated and proxy.killed
