import json
import os

import pytest
from mitmproxy import http
from mitmproxy.test import tflow, tutils

import keyfence.addon as addon_module
from keyfence.addon import ENV_VAULT_VAR, MAPPING_KEY, STREAMED_KEY, KeyFence
from keyfence.vault import Vault

KEY = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
BODY = json.dumps({"messages": [{"role": "user", "content": f"my token is {KEY} ok"}]}).encode()


def make_flow(body=BODY, host="api.openai.com", path=b"/v1/chat/completions?x=1"):
    return tflow.tflow(req=tutils.treq(host=host, method=b"POST", path=path, content=body))


def make_response_flow(mapping, headers, body=b""):
    flow = make_flow()
    flow.metadata[MAPPING_KEY] = mapping
    flow.response = tutils.tresp(
        headers=http.Headers([(k.encode(), v.encode()) for k, v in headers.items()]),
        content=body)
    return flow


@pytest.fixture
def guard(write_config):
    def _make(mode="redact", extra=""):
        write_config(f"mode: {mode}\n{extra}")
        return KeyFence()
    return _make


def test_module_exposes_addon_instance(home):
    assert isinstance(addon_module.addons[0], KeyFence)


def test_load_logs_summary(guard, caplog):
    kf = guard()
    with caplog.at_level("INFO", logger="keyfence"):
        kf.load(None)
    assert "mode=redact" in caplog.text


def test_unmonitored_host_is_ignored(guard):
    kf = guard()
    flow = make_flow(host="example.com")
    kf.request(flow)
    assert flow.request.content == BODY
    assert kf.stats["scanned"] == 0


def test_empty_body_is_ignored(guard):
    kf = guard()
    flow = make_flow(body=b"")
    kf.request(flow)
    assert kf.stats["scanned"] == 0


def test_clean_body_passes_untouched(guard):
    kf = guard()
    flow = make_flow(body=b'{"content":"explain entropy"}')
    kf.request(flow)
    assert flow.request.content == b'{"content":"explain entropy"}'
    assert kf.stats == {"scanned": 1, "findings": 0, "blocked": 0, "errors": 0}


def test_redact_mode(guard, home):
    kf = guard("redact")
    flow = make_flow()
    kf.request(flow)
    text = flow.request.get_text()
    assert KEY not in text
    assert "[REDACTED:github-token]" in text
    assert flow.response is None
    assert MAPPING_KEY not in flow.metadata
    entry = json.loads((home / "audit.log").read_text().splitlines()[-1])
    assert entry["host"] == "api.openai.com"
    assert entry["path"] == "/v1/chat/completions"
    assert entry["count"] == 1
    assert entry["findings"][0]["kind"] == "github-token"
    assert entry["findings"][0]["key"] == "content"
    assert KEY not in (home / "audit.log").read_text()


def test_audit_log_caps_previews(guard, home, monkeypatch):
    monkeypatch.setattr(addon_module, "AUDIT_PREVIEW_LIMIT", 1)
    kf = guard("redact")
    other = "sk-proj-Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"
    kf.request(make_flow(body=f"{KEY} {other}".encode()))
    entry = json.loads((home / "audit.log").read_text().splitlines()[-1])
    assert entry["count"] == 2
    assert len(entry["findings"]) == 1


def test_redaction_adds_notice_to_system_prompt(guard):
    kf = guard("redact")
    body = json.dumps({"system": "sys", "messages": [{"role": "user", "content": f"key {KEY}"}]}).encode()
    flow = make_flow(body=body, host="api.anthropic.com")
    kf.request(flow)
    out = json.loads(flow.request.get_text())
    assert "keyfence" in out["system"]
    assert "[REDACTED:github-token]" in out["messages"][0]["content"]


def test_notice_can_be_disabled(guard):
    kf = guard("redact", "notice: false\n")
    body = json.dumps({"system": "sys", "messages": [{"role": "user", "content": f"key {KEY}"}]}).encode()
    flow = make_flow(body=body, host="api.anthropic.com")
    kf.request(flow)
    assert json.loads(flow.request.get_text())["system"] == "sys"


def test_clean_request_gets_no_notice(guard):
    kf = guard("redact")
    body = json.dumps({"system": "sys", "messages": []}).encode()
    flow = make_flow(body=body, host="api.anthropic.com")
    kf.request(flow)
    assert flow.request.content == body


def test_block_mode(guard):
    kf = guard("block")
    flow = make_flow()
    kf.request(flow)
    assert flow.response.status_code == 403
    payload = json.loads(flow.response.get_text())
    assert payload["error"]["type"] == "keyfence_blocked"
    assert "github-token" in payload["error"]["message"]
    assert kf.stats["blocked"] == 1


def test_placeholder_mode_sets_mapping_and_identity_encoding(guard):
    kf = guard("placeholder")
    other = "sk-proj-Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"
    flow = make_flow(body=f"first {KEY} then {other}".encode())
    kf.request(flow)
    assert flow.request.get_text() == "first <<SECRET_1>> then <<SECRET_2>>"
    assert flow.metadata[MAPPING_KEY] == {"<<SECRET_1>>": KEY, "<<SECRET_2>>": other}
    assert flow.request.headers["accept-encoding"] == "identity"


def test_detector_crash_fails_closed(guard, monkeypatch):
    kf = guard("redact")

    def boom(*_args, **_kwargs):
        raise RuntimeError("simulated detector crash")

    monkeypatch.setattr(addon_module, "scan", boom)
    flow = make_flow()
    kf.request(flow)
    assert flow.response.status_code == 403
    assert "internal error" in json.loads(flow.response.get_text())["error"]["message"]
    assert kf.stats["errors"] == 1


def test_vault_is_reloaded_when_file_changes(guard, home):
    kf = guard("redact")
    Vault().add("senha-interna-sem-formato-2026")
    os.utime(home / "vault.json", (1, 1))
    flow = make_flow(body=b"the password is senha-interna-sem-formato-2026")
    kf.request(flow)
    assert "[REDACTED:vault]" in flow.request.get_text()


def test_env_vault_is_merged(guard, home, monkeypatch):
    main = Vault()
    main.add("main-vault-secret-value")
    env_vault = Vault(path=home / "env.json", salt=main.salt)
    env_vault.add("env-only-secret-value")
    monkeypatch.setenv(ENV_VAULT_VAR, str(env_vault.path))
    kf = guard("redact")
    assert kf.vault.count() == 2
    flow = make_flow(body=b"x=env-only-secret-value y=main-vault-secret-value")
    kf.request(flow)
    assert flow.request.get_text() == "x=[REDACTED:vault] y=[REDACTED:vault]"


def test_missing_env_vault_is_ignored(guard, home, monkeypatch):
    monkeypatch.setenv(ENV_VAULT_VAR, str(home / "missing.json"))
    assert guard().vault.count() == 0


def test_responseheaders_streams_when_nothing_to_restore(guard):
    kf = guard()
    flow = make_flow()
    flow.response = tutils.tresp()
    kf.responseheaders(flow)
    assert flow.response.stream is True


def test_responseheaders_ignores_missing_response(guard):
    kf = guard()
    flow = make_flow()
    flow.response = None
    kf.responseheaders(flow)


def test_responseheaders_installs_sse_restorer(guard):
    kf = guard("placeholder")
    flow = make_response_flow({"<<SECRET_1>>": KEY}, {"content-type": "text/event-stream"})
    kf.responseheaders(flow)
    assert callable(flow.response.stream)
    assert flow.metadata[STREAMED_KEY]
    event = b'data: {"delta":{"text":"use <<SECRET_1>>"}}\n\n'
    out = flow.response.stream(event) + flow.response.stream(b"")
    assert KEY.encode() in out


def test_responseheaders_buffers_compressed_sse(guard):
    kf = guard("placeholder")
    flow = make_response_flow(
        {"<<SECRET_1>>": KEY},
        {"content-type": "text/event-stream", "content-encoding": "gzip"})
    kf.responseheaders(flow)
    assert flow.response.stream is False
    assert STREAMED_KEY not in flow.metadata


def test_response_restores_buffered_json(guard):
    kf = guard("placeholder")
    flow = make_response_flow(
        {"<<SECRET_1>>": KEY}, {"content-type": "application/json"},
        body=b'{"content":"echo <<SECRET_1>>"}')
    kf.response(flow)
    assert flow.response.get_text() == f'{{"content":"echo {KEY}"}}'


def test_response_skips_when_streamed_or_unmapped(guard):
    kf = guard("placeholder")
    flow = make_response_flow({"<<SECRET_1>>": KEY}, {}, body=b"<<SECRET_1>>")
    flow.metadata[STREAMED_KEY] = True
    kf.response(flow)
    assert flow.response.get_text() == "<<SECRET_1>>"

    plain = make_flow()
    plain.response = tutils.tresp(content=b"<<SECRET_1>>")
    kf.response(plain)
    assert plain.response.get_text() == "<<SECRET_1>>"

    empty = make_response_flow({"<<SECRET_1>>": KEY}, {}, body=b"")
    kf.response(empty)
    assert empty.response.get_text() == ""


def test_audit_log_failure_is_logged_not_raised(guard, home, caplog, monkeypatch):
    kf = guard("redact", f"audit_log: {home / 'nope' / 'audit.log'}\n")
    real_mkdir = addon_module.Path.mkdir

    def failing_mkdir(self, *args, **kwargs):
        if self.name == "nope":
            raise OSError("read-only")
        return real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(addon_module.Path, "mkdir", failing_mkdir)
    with caplog.at_level("WARNING", logger="keyfence"):
        kf.request(make_flow())
    assert "audit log" in caplog.text
