import http.client
import json
import re

import pytest
import yaml

from keyfence import cli, doctor, runner, selftest
from keyfence.config import Config
from keyfence.doctor import FAIL, INFO, OK
from keyfence.vault import Vault

VALUE = "keyfence-selftest-0123456789abcdef"
TOKEN = "<<SECRET_abcdef0123>>"
MODES = ("block", "redact", "placeholder", "audit")
BLOCKED = json.dumps({"error": {"type": "keyfence_blocked", "message": "no"}})


def post(url, body):
    host, port = url.split("/")[2].split(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=5)
    try:
        conn.request("POST", url, body=body, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        return resp.status, resp.read().decode()
    finally:
        conn.close()


class FakeProxy:
    def poll(self):
        return None


class FakeAddon:
    def __init__(self, mode, home, transform=None, restore=True, audit=True, forward=True, status=None):
        self.mode = mode
        self.home = home
        self.transform = transform
        self.restore = restore
        self.audit = audit
        self.forward = forward
        self.status = status
        self.proxy = FakeProxy()
        self.stopped = False
        self.started = False
        self.env = {}

    def start_proxy(self, port, env, log, timeout, ca_cert):
        self.started = True
        self.port = port
        self.env = env
        log.write(f"keyfence 0.0: mode={self.mode}\n")
        log.flush()
        return self.proxy

    def stop_proxy(self, proxy):
        assert proxy is self.proxy
        self.stopped = True

    def probe(self, port):
        cfg = Config.load(self.env["KEYFENCE_CONFIG"])
        return {"keyfence": "0.0", "mode": cfg.mode, "hosts": len(cfg.hosts)}

    def send(self, port, url, body):
        assert port == self.port
        text = body.decode()
        if self.audit:
            with (self.home / "audit.log").open("a") as fh:
                fh.write("not json\n")
                fh.write(json.dumps({"host": "127.0.0.1", "mode": self.mode, "findings": [{"kind": "vault"}]}) + "\n")
        if self.transform is not None:
            text = text.replace(VALUE, self.transform)
        elif self.mode == "block":
            return self.status or 403, BLOCKED
        elif self.mode == "redact":
            text = text.replace(VALUE, selftest.REDACTED)
        elif self.mode == "placeholder":
            text = text.replace(VALUE, TOKEN)
        if not self.forward:
            return self.status or 200, "{}"
        status, response = post(url, text.encode())
        if self.mode == "placeholder" and self.restore:
            response = response.replace(TOKEN, VALUE)
        return self.status or status, response

    def run(self, ca_cert, **kwargs):
        return selftest.run(home=self.home, value=VALUE, ca_cert=ca_cert, start_proxy=self.start_proxy,
                            stop_proxy=self.stop_proxy, probe=self.probe, send=self.send, **kwargs)


@pytest.fixture
def ca(tmp_path):
    path = tmp_path / "mitm" / "mitmproxy-ca-cert.pem"
    path.parent.mkdir()
    path.write_text("cert")
    return path


@pytest.fixture
def addon(home, write_config, tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "port_open", lambda port: False)
    made = []

    def make(mode, config=None, **kwargs):
        write_config(config or f"mode: {mode}\n")
        made.append(FakeAddon(mode, tmp_path / f"selftest-home-{len(made)}", **kwargs))
        return made[-1]

    return make


def labels(report, status=None):
    return [c.label for c in report.checks if status is None or c.status == status]


def detail(report, label):
    return [c.detail for c in report.checks if c.label == label][-1]


@pytest.mark.parametrize("mode", MODES)
def test_every_mode_passes_with_a_faithful_addon(addon, ca, home, mode):
    fake = addon(mode)
    environ = {"PATH": "/bin", runner.ENV_VAULT_VAR: "/stale/env.json"}
    report = fake.run(ca, environ=environ)
    assert report.ok and report.mode == mode
    assert labels(report) == ["mitmdump", "config", "proxy", "addon", "CA certificate", "mode", "request",
                              "response", "audit log", "TLS"]
    assert labels(report, INFO) == ["TLS"]
    assert fake.started and fake.stopped
    assert fake.env["KEYFENCE_HOME"] == str(fake.home) and fake.env["PATH"] == "/bin"
    assert fake.env["KEYFENCE_CONFIG"] == str(fake.home / "config.yaml")
    assert runner.ENV_VAULT_VAR not in fake.env
    copied = yaml.safe_load((fake.home / "config.yaml").read_text())
    assert copied["mode"] == mode and copied["extra_hosts"] == ["127.0.0.1"]
    assert copied["audit_log"] == str(fake.home / "audit.log")
    assert Vault(path=fake.home / "vault.json").contains(VALUE)
    assert not (home / "vault.json").exists() and not (home / "audit.log").exists()
    assert (home / "config.yaml").read_text() == f"mode: {mode}\n"
    assert (home / "selftest.log").read_text().startswith("keyfence 0.0")
    text = selftest.render(report)
    assert "FAIL" not in text
    if mode == "audit":
        assert "watching traffic in audit mode" in text
    else:
        assert f"protecting traffic in {mode} mode." in text


def test_user_extra_hosts_are_kept_in_the_copy(addon, ca):
    fake = addon("redact", config="mode: redact\nextra_hosts: [localhost]\nnotice: false\n")
    report = fake.run(ca)
    assert report.ok
    copied = yaml.safe_load((fake.home / "config.yaml").read_text())
    assert copied["extra_hosts"] == ["localhost", "127.0.0.1"] and copied["notice"] is False
    assert "21 hosts" in detail(report, "config")


def test_mitmdump_missing_stops_before_anything_starts(addon, ca, monkeypatch):
    fake = addon("redact")
    monkeypatch.setattr(runner, "mitmdump_path", lambda: "mitmdump")
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    report = fake.run(ca)
    assert labels(report) == ["mitmdump"] and labels(report, FAIL) == ["mitmdump"]
    assert "not found" in detail(report, "mitmdump") and not fake.started
    assert "NOT protecting traffic: mitmdump failed" in selftest.render(report)


def test_invalid_config_is_reported(addon, ca):
    fake = addon("redact", config="mode: nonsense\n")
    report = fake.run(ca)
    assert labels(report, FAIL) == ["config"] and "invalid mode" in detail(report, "config")
    assert report.mode is None and not fake.started


def test_busy_port_is_refused(addon, ca, monkeypatch):
    fake = addon("redact")
    monkeypatch.setattr(runner, "port_open", lambda port: port == 9010)
    report = fake.run(ca, port=9010)
    assert labels(report, FAIL) == ["proxy"] and "already in use" in detail(report, "proxy")
    assert not fake.started


@pytest.mark.parametrize("stage, label, before", [
    (runner.MISSING, "mitmdump", ["mitmdump", "config"]),
    (runner.NOT_UP, "proxy", ["mitmdump", "config"]),
    (runner.NOT_LIVE, "addon", ["mitmdump", "config", "proxy"]),
])
def test_proxy_start_failures_name_the_stage(addon, ca, home, stage, label, before):
    fake = addon("redact")

    def failing(port, env, log, timeout, ca_cert):
        log.write("line one\n\nline two\n")
        log.flush()
        raise runner.ProxyError(stage, f"broken at {stage}")

    report = selftest.run(home=fake.home, value=VALUE, ca_cert=ca, start_proxy=failing, stop_proxy=fake.stop_proxy,
                          probe=fake.probe, send=fake.send)
    assert labels(report) == [*before, label] and labels(report, FAIL) == [label]
    text = detail(report, label)
    assert text.startswith(f"broken at {stage}; last lines of {home / 'selftest.log'}:")
    assert text.endswith("      line one\n      line two") and not fake.stopped


def test_empty_log_is_said_so(addon, ca, home):
    fake = addon("redact")

    def failing(port, env, log, timeout, ca_cert):
        raise runner.ProxyError(runner.NOT_UP, "dead")

    report = selftest.run(home=fake.home, value=VALUE, ca_cert=ca, start_proxy=failing, probe=fake.probe, send=fake.send)
    assert detail(report, "proxy") == f"dead; {home / 'selftest.log'} is empty"


def test_missing_ca_fails_after_the_proxy_is_up(addon, tmp_path):
    fake = addon("redact")
    report = fake.run(tmp_path / "nowhere.pem")
    assert labels(report, FAIL) == ["CA certificate"] and labels(report)[-1] == "CA certificate"
    assert "keyfence exec would hand" in detail(report, "CA certificate") and fake.stopped


def test_probe_that_stops_answering(addon, ca):
    fake = addon("redact")
    fake.probe = lambda port: None
    report = fake.run(ca)
    assert labels(report, FAIL) == ["addon"] and "stopped answering" in detail(report, "addon")
    assert labels(report).count("addon") == 2


@pytest.mark.parametrize("body", [{"mode": "audit", "hosts": 21}, {"mode": "redact", "hosts": 20}])
def test_config_not_applied_is_a_mode_mismatch(addon, ca, body):
    fake = addon("redact")
    fake.probe = lambda port: {"keyfence": "0.0", **body}
    report = fake.run(ca)
    assert labels(report, FAIL) == ["mode"]
    assert f"reports mode={body['mode']} with {body['hosts']} hosts, the config says mode=redact with 21" in detail(report, "mode")
    assert "not applied" in detail(report, "mode")


def test_request_that_gets_no_answer(addon, ca):
    fake = addon("redact")

    def dead(port, url, body):
        raise ConnectionRefusedError("refused")

    fake.send = dead
    report = fake.run(ca)
    assert labels(report, FAIL) == ["request"] and "no answer through the proxy: refused" in detail(report, "request")


@pytest.mark.parametrize("mode", ("block", "redact", "placeholder"))
def test_value_reaching_the_listener_unchanged_is_the_core_failure(addon, ca, mode):
    fake = addon(mode, transform=VALUE)
    report = fake.run(ca)
    assert labels(report, FAIL) == ["request"]
    assert "reached the listener unchanged (HTTP 200); the proxy is not scanning" in detail(report, "request")


def test_block_mode_needs_a_403_and_an_empty_listener(addon, ca):
    fake = addon("block", status=200)
    report = fake.run(ca)
    assert detail(report, "request") == "expected HTTP 403 from the proxy, got 200; nothing reached the listener"
    fake = addon("block", transform=selftest.REDACTED, status=403)
    report = fake.run(ca)
    assert labels(report, FAIL) == ["request"]
    assert detail(report, "request").endswith("got 403; the listener received something else")


def test_redact_mode_failures(addon, ca):
    fake = addon("redact", forward=False)
    report = fake.run(ca)
    assert detail(report, "request") == "nothing reached the listener (HTTP 200); the proxy did not forward the request"
    fake = addon("redact", transform=TOKEN)
    report = fake.run(ca)
    assert "neither the value nor [REDACTED:vault]" in detail(report, "request")
    fake = addon("redact")
    original = fake.send
    fake.send = lambda port, url, body: (original(port, url, body)[0], f"leak {VALUE}")
    report = fake.run(ca)
    assert labels(report, FAIL) == ["response"] and "came back in the response" in detail(report, "response")


def test_placeholder_mode_failures(addon, ca):
    fake = addon("placeholder", transform=selftest.REDACTED)
    report = fake.run(ca)
    assert "neither the value nor a <<SECRET_...>> placeholder" in detail(report, "request")
    fake = addon("placeholder", restore=False)
    report = fake.run(ca)
    assert labels(report, FAIL) == ["response"] and "was not restored" in detail(report, "response")
    fake = addon("placeholder")
    original = fake.send
    fake.send = lambda port, url, body: (original(port, url, body)[0], "{}")
    report = fake.run(ca)
    assert labels(report, FAIL) == ["response"]


def test_the_notice_text_does_not_count_as_a_leftover_placeholder(addon, ca):
    fake = addon("placeholder")
    original = fake.send

    def with_notice(port, url, body):
        status, response = original(port, url, body)
        return status, response.replace("selftest token", "keyfence replaced values with <<SECRET_id>> tokens; selftest token")

    fake.send = with_notice
    report = fake.run(ca)
    assert report.ok


def test_audit_mode_failures(addon, ca):
    fake = addon("audit", transform=selftest.REDACTED)
    report = fake.run(ca)
    assert labels(report, FAIL) == ["request"] and "audit mode must not alter requests" in detail(report, "request")
    fake = addon("audit", audit=False)
    report = fake.run(ca)
    assert labels(report, FAIL) == ["audit log"] and "no entry with a vault finding" in detail(report, "audit log")


def test_audit_entries_ignore_other_hosts_modes_and_kinds(tmp_path):
    path = tmp_path / "audit.log"
    assert selftest.audit_entries(path, "redact") == 0
    path.write_text("\n".join([
        "garbage",
        json.dumps({"host": "api.openai.com", "mode": "redact", "findings": [{"kind": "vault"}]}),
        json.dumps({"host": "127.0.0.1", "mode": "block", "findings": [{"kind": "vault"}]}),
        json.dumps({"host": "127.0.0.1", "mode": "redact", "findings": [{"kind": "entropy"}]}),
        json.dumps({"host": "127.0.0.1", "mode": "redact", "findings": [{"kind": "vault"}]}),
    ]) + "\n")
    assert selftest.audit_entries(path, "redact") == 1


def test_send_through_speaks_absolute_form_http(home):
    with selftest.Listener() as listener:
        status, response = selftest.send_through(listener.port, listener.url, b'{"content": "hello"}')
        assert status == 200 and json.loads(response) == {"selftest": '{"content": "hello"}'}
        assert listener.received == [b'{"content": "hello"}'] and listener.text() == '{"content": "hello"}'
    with pytest.raises(OSError):
        selftest.send_through(listener.port, listener.url, b"x", timeout=1)


def test_free_port_and_throwaway_value_and_log_tail(tmp_path):
    port = runner.free_port()
    assert 1024 < port < 65536 and not runner.port_open(port)
    value = selftest.throwaway_value()
    assert re.fullmatch(r"keyfence-selftest-[0-9a-f]{16}", value) and value != selftest.throwaway_value()
    assert selftest.log_tail(tmp_path / "missing.log") == ""
    log = tmp_path / "some.log"
    log.write_text("\n".join(str(i) for i in range(20)))
    assert selftest.log_tail(log, limit=2).endswith("      18\n      19")


def test_temporary_home_starts_from_defaults_without_a_config_file(home, tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    selftest.write_home(root, VALUE)
    assert yaml.safe_load((root / "config.yaml").read_text()) == {"extra_hosts": ["127.0.0.1"],
                                                                   "audit_log": str(root / "audit.log")}
    assert Config.load(root / "config.yaml").mode == "redact"


def test_render_lists_every_failed_step():
    report = selftest.Report([doctor.Check(OK, "a", "fine"), doctor.Check(FAIL, "b", "bad"), doctor.Check(FAIL, "c", "worse")],
                             mode="block")
    text = selftest.render(report)
    assert "ok    a: fine" in text and "FAIL  b: bad" in text
    assert "NOT protecting traffic: b, c failed" in text and not report.ok and report.failed() == ["b", "c"]


def test_cli_selftest_command(home, monkeypatch, capsys):
    seen = {}

    def fake_run(port, timeout):
        seen.update(port=port, timeout=timeout)
        return selftest.Report([doctor.Check(OK, "request", "fine")], mode="block")

    monkeypatch.setattr(selftest, "run", fake_run)
    assert cli.main(["selftest"]) == 0
    assert seen == {"port": None, "timeout": 20.0}
    assert "protecting traffic in block mode" in capsys.readouterr().out
    monkeypatch.setattr(selftest, "run", lambda port, timeout: seen.update(port=port, timeout=timeout)
                        or selftest.Report([doctor.Check(FAIL, "addon", "gone")], mode="block"))
    assert cli.main(["selftest", "-p", "9010", "--timeout", "3"]) == 1
    assert seen == {"port": 9010, "timeout": 3.0}
    assert "FAIL  addon: gone" in capsys.readouterr().out


def test_selftest_module_does_not_import_mitmproxy():
    import subprocess, sys
    code = "import sys, keyfence.selftest; print('mitmproxy' in sys.modules)"
    assert subprocess.run([sys.executable, "-c", code], capture_output=True, text=True).stdout.strip() == "False"
