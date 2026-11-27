import contextlib
import json
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest
from mitmproxy import ctx as mitm_ctx
from mitmproxy.addons import next_layer as mitm_next_layer
from mitmproxy.connection import Client
from mitmproxy.options import Options
from mitmproxy.proxy import layer as mitm_layer
from mitmproxy.proxy.context import Context

from fakes import CA_PEM
from keyfence import runner
from keyfence.config import Config
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


def _tunnels(host, port=443, patterns=("api.openai.com",), peername=("93.184.216.34", 443)):
    return _tunnels_with_argv(runner.allow_hosts_args(_config_with(patterns)), host, port, peername)


def _config_with(patterns):
    config = Config()
    config.hosts = list(patterns)
    config.intercept_all_hosts = False
    return config


def _tunnels_with_argv(argv, host, port=443, peername=("93.184.216.34", 443)):
    options = Options()
    options.allow_hosts = [argv[i + 1] for i, flag in enumerate(argv) if flag == "--allow-hosts"]
    options.ignore_hosts = []
    original = getattr(mitm_ctx, "options", None)
    mitm_ctx.options = options
    try:
        context = Context(Client(peername=("127.0.0.1", 5555), sockname=("127.0.0.1", 1234)), options)
        context.server.address = (host, port)
        context.server.peername = peername
        probe = mitm_layer.NextLayer(context)
        context.layers.append(probe)
        mitm_next_layer.NextLayer().next_layer(probe)
        return probe.layer.flow is None
    finally:
        mitm_ctx.options = original


def test_a_monitored_host_is_intercepted_and_every_other_one_is_tunneled():
    assert not _tunnels("api.openai.com")
    assert _tunnels("evil.com")


def test_the_proxy_intercepts_the_host_with_its_port_and_in_any_case():
    assert not _tunnels("api.openai.com", 8443)
    assert not _tunnels("API.OpenAI.com")


def test_the_proxy_tunnels_a_host_whose_name_only_looks_like_a_monitored_one():
    assert _tunnels("apiXopenai.com")
    assert _tunnels("api.openai.com.evil.com")
    assert _tunnels("evil.com/api.openai.com")


def test_the_proxy_intercepts_a_subdomain_because_the_addon_monitors_it_too():
    config = _config_with(["api.openai.com"])
    assert not _tunnels("sub.api.openai.com")
    assert config.host_matches("sub.api.openai.com")
    assert not _tunnels("evil.com.api.openai.com")
    assert config.host_matches("evil.com.api.openai.com")


def test_the_wildcard_crosses_dots_like_the_config_matcher():
    assert not _tunnels("eastus.services.ai.azure.com", patterns=["*.services.ai.azure.com"])
    assert not _tunnels("a.b.services.ai.azure.com", patterns=["*.services.ai.azure.com"])
    assert _tunnels("services.ai.azure.com.evil.com", patterns=["*.services.ai.azure.com"])


def test_the_proxy_intercepts_every_host_when_the_list_is_empty():
    config = _config_with(["api.openai.com"])
    config.intercept_all_hosts = True
    assert runner.allow_hosts_args(config) == []
    assert not _tunnels_with_argv(runner.allow_hosts_args(config), "evil.com")


def test_a_monitored_address_intercepts_every_host_that_resolves_to_it():
    assert not _tunnels("example.com", patterns=["127.0.0.1"], peername=("127.0.0.1", 9997))


def test_the_probe_host_stays_reachable_because_it_is_in_the_list():
    assert not _tunnels(runner.PROBE_HOST)


def test_every_default_host_stays_intercepted_once_allow_hosts_is_passed():
    for pattern in Config().hosts:
        for host in _hosts_covered_by(pattern):
            assert _config_with([pattern]).host_matches(host), (pattern, host)
            assert not _tunnels(host, patterns=(pattern,)), (pattern, host)


def _hosts_covered_by(pattern):
    if "*" in pattern:
        return (pattern.replace("*", "eastus"), pattern.replace("*", "a.b"))
    return (pattern, f"sub.{pattern}")


@pytest.mark.parametrize("pattern,host,expected", [
    ("api.openai.com", "api.openai.com", True),
    ("api.openai.com", "eastus.api.openai.com", True),
    ("api.openai.com", "evil.com", False),
    ("api.openai.com", "apiXopenai.com", False),
    ("openai.com", "api.openai.com", True),
    ("openai.com", "evilopenai.com", False),
    ("*.openai.com", "eastus.openai.com", True),
    ("*.openai.com", "openai.com", False),
    ("*.a.b.com", "x.y.a.b.com", True),
    ("*.a.b.com", "x.y.a.b.evil.com", False),
])
def test_both_matchers_agree_on_every_pattern_without_a_question_mark_or_a_class(pattern, host, expected):
    monitored = _config_with([pattern]).host_matches(host)
    allowed = bool(re.search(runner.host_regex(pattern), host, re.IGNORECASE))
    assert monitored is expected
    assert monitored == allowed, (pattern, host, monitored, allowed)


@pytest.mark.parametrize("pattern,host", [
    ("a?.com", "a?.com"),
    ("a?.com", "ab.com"),
    ("*?.com", "x.com"),
    ("*?.openai.com", "eastus.openai.com"),
    ("a[s]t.com", "a[s]t.com"),
    ("a[s]t.com", "ast.com"),
    ("*[s]t.com", "ast.com"),
    ("foo].com", "foo].com"),
    ("*].com", "x].com"),
    ("[ab]cd.com", "bcd.com"),
    ("api.openai.com", "sub.api.openai.com"),
    ("*.openai.com", "eastus.openai.com"),
    ("bedrock-runtime.*.amazonaws.com", "bedrock-runtime.us-east-1.amazonaws.com"),
])
def test_the_config_matcher_never_claims_a_host_the_allow_regex_would_tunnel(pattern, host):
    if _config_with([pattern]).host_matches(host):
        assert re.search(runner.host_regex(pattern), host, re.IGNORECASE), (pattern, host)


@pytest.mark.parametrize("suffix", ["", ":443"], ids=["no-port", "port"])
@pytest.mark.parametrize("pattern,host", [
    ("api.openai.com", "api.openai.com"),
    ("api.openai.com", "eastus.api.openai.com"),
    ("openai.com", "api.openai.com"),
    ("*.openai.com", "eastus.openai.com"),
    ("*.a.b.com", "x.y.a.b.com"),
    ("*?.com", "x.com"),
    ("*[s]t.com", "ast.com"),
])
def test_the_allow_regex_accepts_the_address_mitmproxy_sees_whenever_the_config_matcher_accepts_the_host(pattern, host, suffix):
    assert _config_with([pattern]).host_matches(host)
    assert re.search(runner.host_regex(pattern), f"{host}{suffix}", re.IGNORECASE), (pattern, host, suffix)


def test_run_local_defaults_to_command_name(home, monkeypatch, tmp_path):
    seen = {}
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    monkeypatch.setattr(runner.subprocess, "Popen",
                        lambda cmd, env, stdout, stderr, **_kwargs: seen.update(cmd=cmd) or FakeProxy())
    monkeypatch.setattr(runner, "port_open", lambda port: "cmd" in seen)
    monkeypatch.setattr(runner, "addon_live", lambda port: True)
    monkeypatch.setattr(runner.subprocess, "call", lambda command, env: 0)
    assert runner.run(["/usr/local/bin/claude", "-p"], 8899, ca_cert=ca, timeout=1, local="") == 0
    assert "local:claude" in seen["cmd"]


def test_confdir_is_passed_to_mitmdump(tmp_path):
    assert "confdir=" not in " ".join(runner.proxy_command(1, confdir=None))
    cmd = runner.proxy_command(1, confdir=tmp_path / "conf")
    assert cmd[cmd.index(f"confdir={tmp_path / 'conf'}") - 1] == "--set"


def test_run_tells_mitmdump_to_tunnel_the_hosts_it_does_not_monitor(home, write_config, monkeypatch, tmp_path):
    seen = {}
    write_config("mode: audit\nhosts:\n  - api.openai.com\n")
    ca = _wire_fake_proxy(monkeypatch, tmp_path, seen)
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1) == 0
    assert not _tunnels_with_argv(seen["cmd"], "api.openai.com")
    assert _tunnels_with_argv(seen["cmd"], "evil.com")
    assert not _tunnels_with_argv(seen["cmd"], runner.PROBE_HOST)


def test_run_tells_mitmdump_the_tcp_timeout_from_the_config(home, write_config, monkeypatch, tmp_path):
    seen = {}
    write_config("proxy_tcp_timeout: 7200\n")
    ca = _wire_fake_proxy(monkeypatch, tmp_path, seen)
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1) == 0
    assert ["--set", "tcp_timeout=7200"] in _pairs(seen["cmd"])


def test_run_tells_mitmdump_the_default_tcp_timeout(home, write_config, monkeypatch, tmp_path):
    seen = {}
    ca = _wire_fake_proxy(monkeypatch, tmp_path, seen)
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1) == 0
    assert ["--set", "tcp_timeout=3600"] in _pairs(seen["cmd"])


def test_run_still_tunnels_the_hosts_it_does_not_monitor_while_recording(home, write_config, monkeypatch, tmp_path):
    seen = {}
    write_config("mode: audit\nhosts:\n  - api.openai.com\n")
    ca = _wire_fake_proxy(monkeypatch, tmp_path, seen)
    record = tmp_path / "flows"
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1, record=record) == 0
    assert ["-w", str(record.resolve())] in _pairs(seen["cmd"])
    assert not _tunnels_with_argv(seen["cmd"], "api.openai.com")
    assert _tunnels_with_argv(seen["cmd"], "evil.com")


def _pairs(argv):
    return [argv[i:i + 2] for i in range(len(argv) - 1)]


def test_run_keeps_intercepting_every_host_when_asked_to(home, write_config, monkeypatch, tmp_path):
    seen = {}
    write_config("mode: audit\nintercept_all_hosts: true\n")
    ca = _wire_fake_proxy(monkeypatch, tmp_path, seen)
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1) == 0
    assert not _tunnels_with_argv(seen["cmd"], "evil.com")


@pytest.mark.skipif(os.name != "posix", reason="shell exit codes for signals")
@pytest.mark.parametrize(("signal_number", "expected"), [(15, 143), (9, 137), (2, 130)])
def test_run_reports_a_signal_death_as_128_plus_the_signal(home, monkeypatch, tmp_path, signal_number, expected):
    ca = _wire_fake_proxy(monkeypatch, tmp_path)
    monkeypatch.setattr(runner.subprocess, "call", lambda command, env: -signal_number)
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1) == expected


def test_run_keeps_a_positive_exit_code_as_it_is(home, monkeypatch, tmp_path):
    ca = _wire_fake_proxy(monkeypatch, tmp_path)
    monkeypatch.setattr(runner.subprocess, "call", lambda command, env: 3)
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1) == 3


def test_run_record_and_linger(home, monkeypatch, tmp_path, capsys):
    seen = {}
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    proxy = FakeProxy()
    monkeypatch.setattr(runner.subprocess, "Popen",
                        lambda cmd, env, stdout, stderr, **_kwargs: seen.update(cmd=cmd) or proxy)
    monkeypatch.setattr(runner, "port_open", lambda port: "cmd" in seen)
    monkeypatch.setattr(runner, "addon_live", lambda port: True)
    monkeypatch.setattr(runner.subprocess, "call", lambda command, env: 0)
    slept = []
    monkeypatch.setattr(runner.time, "sleep", lambda s: slept.append(s))
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1, record=tmp_path / "rec" / "s.flows", linger=45) == 0
    assert seen["cmd"][-2:] == ["-w", str(tmp_path / "rec" / "s.flows")]
    if os.name == "posix":
        import stat
        assert stat.S_IMODE((tmp_path / "rec" / "s.flows").stat().st_mode) == 0o600
    assert slept == [45] and "keeping the proxy up for 45s" in capsys.readouterr().out
    assert proxy.terminated


def test_run_returns_the_command_code_when_ctrl_c_ends_the_linger(home, monkeypatch, tmp_path, capsys):
    ca = _wire_fake_proxy(monkeypatch, tmp_path)
    monkeypatch.setattr(runner.subprocess, "call", lambda command, env: 3)

    def interrupted(_seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(runner.time, "sleep", interrupted)
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1, linger=30) == 3
    assert "keeping the proxy up for 30s" in capsys.readouterr().out


def _wire_fake_proxy(monkeypatch, tmp_path, seen=None):
    seen = {} if seen is None else seen
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    monkeypatch.setattr(runner.subprocess, "Popen",
                        lambda cmd, env, stdout, stderr, **_kwargs: seen.update(cmd=cmd) or FakeProxy())
    monkeypatch.setattr(runner, "port_open", lambda port: "cmd" in seen)
    monkeypatch.setattr(runner, "addon_live", lambda port: True)
    monkeypatch.setattr(runner.subprocess, "call", lambda command, env: 0)
    return ca


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_run_creates_the_proxy_log_private_from_the_first_moment_it_exists(home, monkeypatch, tmp_path):
    modes_at_chmod = []
    chmod = os.chmod

    def watching_chmod(path, mode, *args, **kwargs):
        if Path(path) == home / "proxy.log":
            modes_at_chmod.append(stat.S_IMODE(Path(path).stat().st_mode))
        return chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(os, "chmod", watching_chmod)
    ca = _wire_fake_proxy(monkeypatch, tmp_path)
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1) == 0
    assert stat.S_IMODE((home / "proxy.log").stat().st_mode) == 0o600
    assert modes_at_chmod in ([], [0o600])


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_proxy_log_mode_goes_on_the_open_handle_and_never_on_the_path(home, monkeypatch, tmp_path):
    log = home / "proxy.log"
    log.write_text("")
    log.chmod(0o644)
    seen = []
    fchmod = os.fchmod
    chmod = os.chmod

    def watching_fchmod(fd, mode, *args, **kwargs):
        seen.append((os.fstat(fd).st_ino, mode))
        return fchmod(fd, mode, *args, **kwargs)

    def refusing_chmod(path, mode, *args, **kwargs):
        if Path(path) == log:
            raise AssertionError(f"the proxy log mode went on the path {path}, not on the handle")
        return chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(os, "fchmod", watching_fchmod)
    monkeypatch.setattr(os, "chmod", refusing_chmod)
    ca = _wire_fake_proxy(monkeypatch, tmp_path)
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1) == 0
    assert [(ino, mode) for ino, mode in seen if ino == log.stat().st_ino] == [(log.stat().st_ino, 0o600)]
    assert stat.S_IMODE(log.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_run_still_sets_every_mode_it_owns_on_a_python_without_fchmod(home, monkeypatch, tmp_path):
    monkeypatch.delattr(os, "fchmod")
    record = tmp_path / "rec" / "s.flows"
    ca = _wire_fake_proxy(monkeypatch, tmp_path)
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1, record=record) == 0
    assert stat.S_IMODE((home / "proxy.log").stat().st_mode) == 0o600
    assert stat.S_IMODE(record.stat().st_mode) == 0o600
    assert stat.S_IMODE((home / runner.BUNDLE_NAME).stat().st_mode) == runner.BUNDLE_MODE


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_run_tightens_a_proxy_log_left_world_readable_by_an_older_version(home, monkeypatch, tmp_path):
    log = home / "proxy.log"
    log.write_text("")
    log.chmod(0o644)
    ca = _wire_fake_proxy(monkeypatch, tmp_path)
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1) == 0
    assert stat.S_IMODE(log.stat().st_mode) == 0o600


def test_run_says_on_stderr_when_the_proxy_log_stays_readable(home, monkeypatch, tmp_path, capsys):
    log = home / "proxy.log"
    fchmod = os.fchmod

    def refusing_only_the_proxy_log_fchmod(fd, mode, *args, **kwargs):
        if log.exists() and os.fstat(fd).st_ino == log.stat().st_ino:
            raise OSError(1, "Operation not permitted")
        return fchmod(fd, mode, *args, **kwargs)

    monkeypatch.setattr(os, "fchmod", refusing_only_the_proxy_log_fchmod)
    ca = _wire_fake_proxy(monkeypatch, tmp_path)
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1) == 0
    err = capsys.readouterr().err
    assert "could not make" in err
    assert "proxy.log" in err
    assert log.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_record_mode_goes_on_the_open_handle_and_never_on_the_path(home, monkeypatch, tmp_path):
    record = tmp_path / "rec" / "s.flows"
    record.parent.mkdir(parents=True)
    record.write_text("")
    record.chmod(0o644)
    seen = []
    fchmod = os.fchmod
    chmod = os.chmod

    def watching_fchmod(fd, mode, *args, **kwargs):
        seen.append((os.fstat(fd).st_ino, mode))
        return fchmod(fd, mode, *args, **kwargs)

    def refusing_chmod(path, mode, *args, **kwargs):
        if Path(path) == record:
            raise AssertionError(f"the record mode went on the path {path}, not on the handle")
        return chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(os, "fchmod", watching_fchmod)
    monkeypatch.setattr(os, "chmod", refusing_chmod)
    ca = _wire_fake_proxy(monkeypatch, tmp_path)
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1, record=record) == 0
    assert [(ino, mode) for ino, mode in seen if ino == record.stat().st_ino] == [(record.stat().st_ino, 0o600)]
    assert stat.S_IMODE(record.stat().st_mode) == 0o600


@pytest.mark.parametrize("mode", ["audit", "block"])
def test_run_record_says_on_stderr_when_the_file_will_hold_secrets(home, write_config, monkeypatch, tmp_path, capsys, mode):
    write_config(f"mode: {mode}\n")
    ca = _wire_fake_proxy(monkeypatch, tmp_path)
    record = tmp_path / "rec" / "s.flows"
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1, record=record) == 0
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
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1, record=tmp_path / "s.flows") == 0
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("config", ["mode: nonsense\n", "mode: [\n"])
def test_run_refuses_an_invalid_config_before_starting_anything(home, write_config, monkeypatch, tmp_path, capsys, config):
    write_config(config)
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *a, **k: pytest.fail("must not start the proxy"))
    monkeypatch.setattr(runner, "port_open", lambda port: False)
    assert runner.run([sys.executable], 8899, ca_cert=tmp_path / "ca.pem", timeout=1, record=tmp_path / "s.flows") == 1
    out, err = capsys.readouterr()
    assert out.startswith("error: ") and err == ""
    assert not (tmp_path / "s.flows").exists()


def test_run_without_record_says_nothing_in_audit_mode(home, write_config, monkeypatch, tmp_path, capsys):
    write_config("mode: audit\n")
    ca = _wire_fake_proxy(monkeypatch, tmp_path)
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1) == 0
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
    assert runner.run([sys.executable], 8899) == 1
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
                        lambda cmd, env, stdout, stderr, **_kwargs: seen.update(proxy_cmd=cmd) or FakeProxy())
    monkeypatch.setattr(runner, "port_open",
                        lambda port: (default_busy and port == runner.DEFAULT_PORT) or "proxy_cmd" in seen)
    monkeypatch.setattr(runner, "addon_live", lambda port: seen["probed"].append(port) or True)
    monkeypatch.setattr(runner.subprocess, "call", lambda command, env: seen.update(env=env) or 0)
    assert runner.run([sys.executable], ca_cert=ca, timeout=1) == 0
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


def test_mitmdump_path_finds_the_install_scheme_scripts_folder(tmp_path, monkeypatch):
    from keyfence import hooks
    scripts = tmp_path / "Scripts"
    scripts.mkdir()
    fake = scripts / "mitmdump.exe"
    fake.write_text("")
    monkeypatch.setattr(runner.sys, "executable", str(tmp_path / "python.exe"))
    monkeypatch.setattr(hooks.sysconfig, "get_paths", lambda *a, **k: {"scripts": str(scripts)})
    monkeypatch.setattr(runner, "find_executable", lambda _name: None)
    assert runner.mitmdump_path() == str(fake)


def test_mitmdump_path_falls_back_to_path_then_bare_name(tmp_path, monkeypatch):
    monkeypatch.setattr(runner.sys, "executable", str(tmp_path / "python"))
    # Ignore this environment's own scripts folder; the fallback is PATH -> bare name.
    monkeypatch.setattr(runner, "find_script", lambda name, finder: finder(name) or finder(f"{name}.exe"))
    monkeypatch.setattr(runner, "find_executable", lambda _name: "/opt/bin/mitmdump")
    assert runner.mitmdump_path() == "/opt/bin/mitmdump"
    monkeypatch.setattr(runner, "find_executable", lambda _name: None)
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


def test_child_env_bypasses_loopback_by_default(tmp_path):
    ca = tmp_path / "ca.pem"
    bundle = tmp_path / "ca-bundle.pem"
    env = runner.child_env({}, 8888, ca, bundle)
    for name in runner.NO_PROXY_ENV_VARS:
        assert env[name] == "localhost,127.0.0.1,::1"


def test_child_env_adds_loopback_to_the_no_proxy_list_the_user_exported(tmp_path):
    ca = tmp_path / "ca.pem"
    bundle = tmp_path / "ca-bundle.pem"
    env = runner.child_env({"NO_PROXY": "internal.corp,127.0.0.1"}, 8888, ca, bundle)
    assert env["NO_PROXY"] == "internal.corp,127.0.0.1,localhost,::1"
    assert env["NO_PROXY"].split(",").count("127.0.0.1") == 1


def test_child_env_keeps_the_two_no_proxy_variables_apart_when_the_user_set_both(tmp_path):
    ca = tmp_path / "ca.pem"
    bundle = tmp_path / "ca-bundle.pem"
    env = runner.child_env({"NO_PROXY": "upper.corp", "no_proxy": "lower.corp"}, 8888, ca, bundle)
    assert env["NO_PROXY"] == "upper.corp,localhost,127.0.0.1,::1"
    assert env["no_proxy"] == "lower.corp,localhost,127.0.0.1,::1"


def test_child_env_gives_the_unset_no_proxy_variable_the_same_list_as_the_set_one(tmp_path):
    ca = tmp_path / "ca.pem"
    bundle = tmp_path / "ca-bundle.pem"
    env = runner.child_env({"NO_PROXY": "internal.corp"}, 8888, ca, bundle)
    assert env["no_proxy"] == env["NO_PROXY"] == "internal.corp,localhost,127.0.0.1,::1"


def test_child_env_leaves_loopback_proxied_when_bypass_is_off(tmp_path):
    ca = tmp_path / "ca.pem"
    bundle = tmp_path / "ca-bundle.pem"
    plain = runner.child_env({}, 8888, ca, bundle, bypass_loopback=False)
    assert "NO_PROXY" not in plain and "no_proxy" not in plain
    kept = runner.child_env({"NO_PROXY": "internal.corp"}, 8888, ca, bundle, bypass_loopback=False)
    assert kept["NO_PROXY"] == "internal.corp"
    assert "no_proxy" not in kept


def test_child_env_default_env_makes_urllib_bypass_the_loopback(tmp_path, monkeypatch):
    ca = tmp_path / "ca.pem"
    bundle = tmp_path / "ca-bundle.pem"
    env = runner.child_env({}, 8888, ca, bundle)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    assert urllib.request.proxy_bypass("localhost") is True
    assert urllib.request.proxy_bypass("127.0.0.1") is True


def _child_env_for_config(write_config, monkeypatch, tmp_path, config_text):
    seen = {}
    write_config(config_text)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    ca = _wire_fake_proxy(monkeypatch, tmp_path, seen)
    monkeypatch.setattr(runner.subprocess, "call", lambda command, env: seen.update(env=env) or 0)
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1) == 0
    return seen["env"]


def test_run_hands_the_child_the_loopback_bypass_by_default(write_config, monkeypatch, tmp_path):
    env = _child_env_for_config(write_config, monkeypatch, tmp_path, "mode: audit\n")
    assert env["NO_PROXY"] == env["no_proxy"] == "localhost,127.0.0.1,::1"


def test_run_drops_the_bypass_when_a_loopback_pattern_is_in_extra_hosts(write_config, monkeypatch, tmp_path):
    env = _child_env_for_config(write_config, monkeypatch, tmp_path,
                                'mode: audit\nextra_hosts: ["127.0.0.*"]\n')
    assert "NO_PROXY" not in env and "no_proxy" not in env


def test_run_drops_the_bypass_when_a_pattern_ends_in_a_loopback_name(write_config, monkeypatch, tmp_path):
    env = _child_env_for_config(write_config, monkeypatch, tmp_path,
                                'mode: audit\nextra_hosts: ["*.localhost"]\n')
    assert "NO_PROXY" not in env and "no_proxy" not in env


def test_run_drops_the_bypass_when_intercept_all_hosts_is_on(write_config, monkeypatch, tmp_path):
    env = _child_env_for_config(write_config, monkeypatch, tmp_path,
                                "mode: audit\nintercept_all_hosts: true\n")
    assert "NO_PROXY" not in env and "no_proxy" not in env


def test_run_drops_the_bypass_when_a_loopback_address_is_listed(write_config, monkeypatch, tmp_path):
    for extra in ('["127.0.0.1"]', '["[::1]"]'):
        env = _child_env_for_config(write_config, monkeypatch, tmp_path,
                                    f"mode: audit\nextra_hosts: {extra}\n")
        assert "NO_PROXY" not in env and "no_proxy" not in env, extra


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


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_bundle_mode_goes_on_the_open_handle_and_never_on_the_path(home, tmp_path, only_roots, monkeypatch):
    only_roots(_roots(tmp_path))
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    seen = []
    fchmod = os.fchmod
    chmod = os.chmod

    def watching_fchmod(fd, mode, *args, **kwargs):
        seen.append((os.fstat(fd).st_ino, mode))
        return fchmod(fd, mode, *args, **kwargs)

    def refusing_chmod(path, mode, *args, **kwargs):
        if Path(path) == home / runner.BUNDLE_NAME:
            raise AssertionError(f"the bundle mode went on the path {path}, not on the handle")
        return chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(os, "fchmod", watching_fchmod)
    monkeypatch.setattr(os, "chmod", refusing_chmod)
    path, _ = runner.ensure_bundle(ca)
    assert seen == [(path.stat().st_ino, runner.BUNDLE_MODE)]
    assert stat.S_IMODE(path.stat().st_mode) == runner.BUNDLE_MODE


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
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1) == 0
    bundle = home / runner.BUNDLE_NAME
    assert bundle.exists() and bundle.read_text().endswith(ca.read_text())
    assert seen["env"]["SSL_CERT_FILE"] == str(bundle)
    assert seen["env"]["NODE_EXTRA_CA_CERTS"] == str(ca)


def test_run_refuses_to_start_the_command_when_the_bundle_cannot_be_built(home, write_config, monkeypatch, tmp_path, capsys, only_roots):
    write_config("mode: redact\n")
    seen = {}
    proxy = FakeProxy()
    monkeypatch.setattr(runner.subprocess, "Popen",
                        lambda cmd, env, stdout, stderr, **_kwargs: seen.update(cmd=cmd) or proxy)
    monkeypatch.setattr(runner, "port_open", lambda port: "cmd" in seen)
    monkeypatch.setattr(runner, "addon_live", lambda port: True)
    monkeypatch.setattr(runner.subprocess, "call", lambda *a, **k: pytest.fail("must not start the command"))
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    only_roots(paths=("/nowhere/ca-bundle.crt",))
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1) == 1
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
        runner.run([sys.executable], 8899)
    assert seen["config"].ignore_keys == ["DB_HOST"]
    write_config("mode: nonsense\n")
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *a, **k: pytest.fail("must not start the proxy"))
    assert runner.run([sys.executable], 8899) == 1
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
                        lambda cmd, env, stdout, stderr, **_kwargs: seen.update(proxy_cmd=cmd, proxy_env=env, stdout=stdout) or proxy)
    monkeypatch.setattr(runner, "port_open", lambda port: "proxy_cmd" in seen)
    monkeypatch.setattr(runner, "addon_live", lambda port: True)

    def fake_call(command, env):
        seen["command"] = command
        seen["env"] = env
        return 7

    monkeypatch.setattr(runner.subprocess, "call", fake_call)
    code = runner.run([sys.executable, "hi"], 8899, ca_cert=ca, timeout=1)
    assert code == 7
    assert seen["command"] == [sys.executable, "hi"]
    assert seen["env"]["HTTPS_PROXY"] == "http://127.0.0.1:8899"
    assert runner.ENV_VAULT_VAR in seen["proxy_env"]
    assert proxy.terminated
    assert seen["stdout"].closed
    assert (home / "proxy.log").exists()


def test_run_when_mitmdump_missing(home, monkeypatch, capsys):
    def missing(*_args, **_kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(runner.subprocess, "Popen", missing)
    assert runner.run([sys.executable], 8899) == 1
    assert "mitmdump not found" in capsys.readouterr().out


def test_run_refuses_to_start_the_command_when_the_addon_is_not_answering(home, monkeypatch, tmp_path, capsys):
    proxy = FakeProxy()
    seen = {}
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    monkeypatch.setattr(runner.subprocess, "Popen", lambda cmd, env, stdout, stderr, **_kwargs: seen.update(cmd=cmd) or proxy)
    monkeypatch.setattr(runner, "port_open", lambda port: "cmd" in seen)
    monkeypatch.setattr(runner, "addon_live", lambda port: False)
    monkeypatch.setattr(runner.subprocess, "call", lambda command, env: pytest.fail("must not start the command"))
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=0.05) == 1
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
                        lambda cmd, env, stdout, stderr, **_kwargs: started.append((cmd, env, stdout)) or started[-1] and FakeProxy())
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
    monkeypatch.setattr(runner.subprocess, "Popen", lambda cmd, env, stdout, stderr, **_kwargs: proxy)
    monkeypatch.setattr(runner, "port_open", lambda port: False)
    assert runner.run([sys.executable], 8899, ca_cert=tmp_path / "missing.pem", timeout=0.05) == 1
    assert "did not come up" in capsys.readouterr().out
    assert (home / "proxy.log").exists()
    assert proxy.terminated and proxy.killed


def test_run_starts_the_command_from_path_not_from_the_current_directory(home, monkeypatch, tmp_path, clone):
    seen = {}
    ca = _wire_fake_proxy(monkeypatch, tmp_path)
    monkeypatch.setattr(runner, "mitmdump_path", lambda: sys.executable)
    monkeypatch.setattr(runner.subprocess, "call", lambda command, env: seen.update(command=command) or 0)
    real = clone.plant(clone.bin, "tool", "real")
    clone.plant(clone.repo, "tool", "planted")
    assert runner.run(["tool", "-x"], 8899, ca_cert=ca, timeout=1) == 0
    assert clone.same(seen["command"][0], real) and seen["command"][1:] == ["-x"]


def test_run_refuses_a_command_that_is_only_in_the_current_directory(home, monkeypatch, tmp_path, clone, capsys):
    proxy = FakeProxy()
    seen = {}
    ca = _wire_fake_proxy(monkeypatch, tmp_path, seen)
    monkeypatch.setattr(runner, "mitmdump_path", lambda: sys.executable)
    monkeypatch.setattr(runner.subprocess, "Popen", lambda cmd, env, stdout, stderr, **_kwargs: seen.update(cmd=cmd) or proxy)
    monkeypatch.setattr(runner.subprocess, "call", lambda command, env: pytest.fail("the command must not start"))
    clone.plant(clone.repo, "tool", "planted")
    assert runner.run(["tool"], 8899, ca_cert=ca, timeout=1) == 127
    assert "keyfence: tool not found on PATH" in capsys.readouterr().err
    assert proxy.terminated


def test_start_proxy_never_runs_a_mitmdump_from_the_current_directory(home, monkeypatch, tmp_path, clone):
    seen = {}
    ca = _wire_fake_proxy(monkeypatch, tmp_path, seen)
    monkeypatch.setattr(runner, "mitmdump_path", lambda: "mitmdump")
    clone.plant(clone.repo, "mitmdump", "planted")
    with pytest.raises(runner.ProxyError) as exc:
        runner.start_proxy(8899, {}, None, timeout=1, ca_cert=ca)
    assert exc.value.stage == runner.MISSING and "cmd" not in seen
    real = clone.plant(clone.bin, "mitmdump", "real")
    runner.start_proxy(8899, {}, None, timeout=1, ca_cert=ca)
    assert clone.same(seen["cmd"][0], real)


@pytest.mark.skipif(os.name != "posix", reason="POSIX process sessions")
def test_start_proxy_starts_mitmdump_in_its_own_session(monkeypatch, tmp_path):
    log = (tmp_path / "proxy.log").open("w")
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    seen = {}

    def popen(cmd, env, stdout, stderr, **kwargs):
        seen.update(kwargs)
        return FakeProxy()

    monkeypatch.setattr(runner.subprocess, "Popen", popen)
    monkeypatch.setattr(runner, "port_open", lambda port: True)
    monkeypatch.setattr(runner, "addon_live", lambda port: True)
    try:
        runner.start_proxy(8899, {}, log, ca_cert=ca)
    finally:
        log.close()
    assert seen.get("start_new_session") is True


@pytest.mark.skipif(os.name != "posix", reason="POSIX signals")
def test_run_lets_the_command_handle_ctrl_c(home, monkeypatch, tmp_path):
    # A fake proxy, but the real child: it traps SIGINT, exits 7, and the
    # signal goes to the whole foreground group, as a terminal sends it.
    real_popen = subprocess.Popen
    seen = {}
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)

    def popen(cmd, env=None, stdout=None, stderr=None, **kwargs):
        if "mitmdump" in Path(str(cmd[0])).name:
            seen["proxy"] = True
            return FakeProxy()
        return real_popen(cmd, env=env, stdout=stdout, stderr=stderr, **kwargs)

    monkeypatch.setattr(runner.subprocess, "Popen", popen)
    monkeypatch.setattr(runner.subprocess, "call", subprocess.call)
    # Free before start_proxy, then listening once the fake proxy started.
    monkeypatch.setattr(runner, "port_open", lambda port: "proxy" in seen)
    monkeypatch.setattr(runner, "addon_live", lambda port: True)

    ready = tmp_path / "ready"
    script = tmp_path / "child.py"
    script.write_text(
        "import os, signal, sys, time\n"
        "def on(signum, frame):\n"
        "    os._exit(7)\n"
        "signal.signal(signal.SIGINT, on)\n"
        f"open({str(ready)!r}, 'w').close()\n"
        "time.sleep(5)\n"
    )

    finished = threading.Event()

    # CI runs pytest in the runner's own process group, so a killpg on the
    # current group would signal the runner agent too: take a private group
    # for the duration of the test and hand it back afterwards.
    original_pgid = os.getpgrp()
    os.setpgid(0, 0)
    private_pgid = os.getpgrp()

    def interrupt():
        deadline = time.monotonic() + 3
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        # A late killpg after run() returned would hit pytest with the
        # restored handler and kill the session instead of failing the test.
        if not finished.is_set():
            with contextlib.suppress(ProcessLookupError):
                os.killpg(private_pgid, signal.SIGINT)

    try:
        threading.Thread(target=interrupt, daemon=True).start()
        code = runner.run([sys.executable, str(script)], 8899, ca_cert=ca, timeout=1)
    finally:
        finished.set()
        os.setpgid(0, original_pgid)
    assert code == 7
    assert seen.get("proxy")


def test_start_proxy_stops_the_proxy_when_startup_is_interrupted(monkeypatch, tmp_path):
    # The proxy starts in its own group, so a Ctrl+C during startup reaches
    # keyfence only: start_proxy must stop it or it would be orphaned (#179).
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    log = (tmp_path / "log").open("w")
    proxy = FakeProxy()
    monkeypatch.setattr(runner.subprocess, "Popen",
                        lambda cmd, env, stdout, stderr, **_kwargs: proxy)

    def interrupt(predicate, timeout, interval=0.1):
        raise KeyboardInterrupt

    monkeypatch.setattr(runner, "wait_for", interrupt)
    try:
        with pytest.raises(KeyboardInterrupt):
            runner.start_proxy(8899, {}, log, timeout=1, ca_cert=ca)
    finally:
        log.close()
    assert proxy.terminated


@pytest.mark.skipif(os.name != "posix", reason="POSIX signals")
@pytest.mark.parametrize(("signal_name", "expected"), [("SIGTERM", 143), ("SIGHUP", 129)])
def test_run_stops_the_proxy_when_sigterm_or_sighup_stops_it(
        home, monkeypatch, tmp_path, signal_name, expected):
    signal_number = getattr(signal, signal_name)
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    proxy = FakeProxy()
    seen = {}
    monkeypatch.setattr(runner.subprocess, "Popen",
                        lambda cmd, env, stdout, stderr, **_kwargs: seen.update(started=True) or proxy)
    monkeypatch.setattr(runner, "port_open", lambda port: "started" in seen)
    monkeypatch.setattr(runner, "addon_live", lambda port: True)

    unguarded = []

    def guard(signum, _frame):
        unguarded.append(signum)
        raise AssertionError(f"run() left SIG{signum} at its default action")

    def signal_self(command, env):
        os.kill(os.getpid(), signal_number)
        return 0

    monkeypatch.setattr(runner.subprocess, "call", signal_self)
    previous = signal.signal(signal_number, guard)
    try:
        assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1) == expected
        assert signal.getsignal(signal_number) is guard
    finally:
        signal.signal(signal_number, previous)
    assert unguarded == []
    assert proxy.terminated
    env_dir = runner.DEFAULT_DIR / runner.ENV_VAULT_DIR
    assert not env_dir.exists() or list(env_dir.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX signals")
def test_run_restores_the_termination_handlers_it_installed(home, monkeypatch, tmp_path):
    ca = _wire_fake_proxy(monkeypatch, tmp_path)
    previous = {signum: signal.getsignal(signum) for signum in (signal.SIGTERM, signal.SIGHUP)}
    sentinel = lambda signum, frame: None
    try:
        for signum in (signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, sentinel)
        assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1) == 0
        for signum in (signal.SIGTERM, signal.SIGHUP):
            assert signal.getsignal(signum) is sentinel
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


@pytest.mark.skipif(os.name != "posix", reason="POSIX signals")
def test_run_stops_the_proxy_even_when_a_second_signal_arrives(home, monkeypatch, tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text(CA_PEM)
    seen = {}

    class InterruptingProxy(FakeProxy):
        def terminate(self):
            os.kill(os.getpid(), signal.SIGTERM)
            super().terminate()

    proxy = InterruptingProxy()
    monkeypatch.setattr(runner.subprocess, "Popen",
                        lambda cmd, env, stdout, stderr, **_kwargs: seen.update(started=True) or proxy)
    monkeypatch.setattr(runner, "port_open", lambda port: "started" in seen)
    monkeypatch.setattr(runner, "addon_live", lambda port: True)

    def signal_self(command, env):
        os.kill(os.getpid(), signal.SIGTERM)
        return 0

    monkeypatch.setattr(runner.subprocess, "call", signal_self)
    guard = lambda signum, frame: (_ for _ in ()).throw(AssertionError("the signal escaped run()"))
    previous = signal.signal(signal.SIGTERM, guard)
    try:
        assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1) == 143
        assert signal.getsignal(signal.SIGTERM) is guard
    finally:
        signal.signal(signal.SIGTERM, previous)
    assert proxy.terminated


@pytest.mark.skipif(os.name != "posix", reason="POSIX signals")
def test_run_keeps_going_when_a_termination_handler_cannot_be_installed(home, monkeypatch, tmp_path):
    ca = _wire_fake_proxy(monkeypatch, tmp_path)
    real_signal = signal.signal

    def refusing(signum, handler):
        if signum == signal.SIGHUP:
            raise OSError("no SIGHUP here")
        return real_signal(signum, handler)

    monkeypatch.setattr(runner.signal, "signal", refusing)
    assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1) == 0


@pytest.mark.skipif(os.name != "posix", reason="POSIX signals")
def test_an_ignored_sighup_stays_ignored_so_nohup_keeps_working(home, monkeypatch, tmp_path):
    ca = _wire_fake_proxy(monkeypatch, tmp_path)
    during = {}

    def hang_up(command, env):
        during["handler"] = signal.getsignal(signal.SIGHUP)
        during["sigterm"] = signal.getsignal(signal.SIGTERM)
        assert during["handler"] == signal.SIG_IGN
        os.kill(os.getpid(), signal.SIGHUP)
        return 0

    monkeypatch.setattr(runner.subprocess, "call", hang_up)
    sigterm_before = signal.getsignal(signal.SIGTERM)
    previous = signal.signal(signal.SIGHUP, signal.SIG_IGN)
    try:
        assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1) == 0
        assert signal.getsignal(signal.SIGHUP) == signal.SIG_IGN
    finally:
        signal.signal(signal.SIGHUP, previous)
    assert during["sigterm"] is not sigterm_before


@pytest.mark.skipif(os.name != "posix", reason="POSIX signals")
def test_an_ignored_sigint_stays_ignored_for_the_command(home, monkeypatch, tmp_path):
    ca = _wire_fake_proxy(monkeypatch, tmp_path)
    during = {}
    monkeypatch.setattr(runner.subprocess, "call",
                        lambda command, env: during.update(handler=signal.getsignal(signal.SIGINT)) or 0)
    previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        assert runner.run([sys.executable], 8899, ca_cert=ca, timeout=1) == 0
        assert signal.getsignal(signal.SIGINT) == signal.SIG_IGN
    finally:
        signal.signal(signal.SIGINT, previous)
    assert during["handler"] == signal.SIG_IGN


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups")
def test_exec_stops_mitmdump_when_its_process_group_is_terminated(tmp_path):
    if not Path(runner.mitmdump_path()).is_file():
        pytest.skip("mitmdump is not installed")
    port = runner.free_port()
    env = dict(os.environ, HOME=str(tmp_path), KEYFENCE_HOME=str(tmp_path / "home"),
               KEYFENCE_CONFIG=str(tmp_path / "config.yaml"), MITMPROXY_CONFDIR=str(tmp_path / "mitm"))
    env.pop("KEYFENCE_ENV_VAULT", None)
    repo = Path(__file__).resolve().parent.parent
    process = subprocess.Popen(
        [sys.executable, "-m", "keyfence", "exec", "-p", str(port), "--",
         sys.executable, "-c", "import time; time.sleep(60)"],
        env=env, cwd=repo, start_new_session=True)
    try:
        assert runner.wait_for(lambda: runner.addon_live(port), 30), "the proxy never came up"
        os.killpg(process.pid, signal.SIGTERM)
        assert process.wait(timeout=10) == 143
        assert runner.wait_for(lambda: not runner.port_open(port), 5), "mitmdump kept the port"
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        listing = subprocess.run(["ps", "-eo", "pid=,command="], capture_output=True, text=True).stdout
        for line in listing.splitlines():
            if f"--listen-port {port}" in line:
                with contextlib.suppress(ProcessLookupError, ValueError):
                    os.kill(int(line.split()[0]), signal.SIGKILL)


def test_run_with_a_record_path_that_is_a_directory_says_so_and_leaves_no_vault(
        home, write_config, monkeypatch, tmp_path, capsys):
    seen = {}
    write_config("mode: redact\n")
    ca = _wire_fake_proxy(monkeypatch, tmp_path, seen)
    a_directory = tmp_path / "flows"
    a_directory.mkdir()

    code = runner.run([sys.executable], 8899, ca_cert=ca, timeout=1, record=a_directory)

    assert code == 1
    out = capsys.readouterr()
    assert out.out.count("error:") + out.err.count("error:") == 1
    assert "cannot write the record file" in (out.out + out.err)
    env_dir = runner.DEFAULT_DIR / "env"
    assert not env_dir.exists() or list(env_dir.iterdir()) == []
    assert "cmd" not in seen, "the proxy was started for a record path that cannot be written"
