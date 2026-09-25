import json
import os
import re

import pytest
from mitmproxy import http
from mitmproxy.test import tflow, tutils
from mitmproxy.websocket import Opcode, WebSocketData, WebSocketMessage

import keyfence.addon as addon_module
from keyfence.addon import ENV_VAULT_VAR, MAPPING_KEY, STREAMED_KEY, KeyFence
from keyfence.detectors import ScanReport
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
        kf = KeyFence()
        kf.load(None)
        return kf
    return _make


def test_package_import_declares_the_addon_and_touches_no_files(home):
    assert len(addon_module.addons) == 1 and isinstance(addon_module.addons[0], KeyFence)
    assert addon_module.addons[0].config is None and addon_module.addons[0].vault is None
    assert not (home / "vault.json").exists()


@pytest.mark.parametrize("module_name", ["__mitmproxy_script__.addon", "__mitmproxy_addon__.addon", "addon"])
def test_addon_is_declared_whatever_the_loader_names_the_module(home, write_config, module_name):
    import importlib.util
    write_config("mode: block\n")
    spec = importlib.util.spec_from_file_location(module_name, addon_module.__file__)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert len(module.addons) == 1 and type(module.addons[0]).__name__ == "KeyFence"
    assert not (home / "vault.json").exists()
    module.addons[0].load(None)
    assert module.addons[0].config.mode == "block" and (home / "vault.json").exists()


def test_probe_host_is_answered_by_the_addon_and_never_forwarded(guard):
    from keyfence import __version__
    kf = guard("block")
    flow = make_flow(body=b"", host=addon_module.PROBE_HOST, path=b"/")
    kf.request(flow)
    assert flow.response.status_code == 200
    assert json.loads(flow.response.get_text()) == {"keyfence": __version__, "mode": "block", "hosts": len(kf.config.hosts)}
    assert kf.stats["scanned"] == 0


def test_request_before_load_sets_up_lazily(home, write_config):
    write_config("mode: block\n")
    kf = KeyFence()
    flow = make_flow()
    kf.request(flow)
    assert flow.response.status_code == 403 and kf.config.mode == "block"


def test_request_fails_closed_when_setup_fails(home, write_config, caplog):
    write_config("mode: redact\n")
    (home / "vault.json").write_text("x")
    kf = KeyFence()
    flow = make_flow(body=b"", host=addon_module.PROBE_HOST, path=b"/")
    with caplog.at_level("ERROR", logger="keyfence"):
        kf.request(flow)
    assert flow.response.status_code == 403 and "failing closed" in caplog.text
    assert kf.stats["errors"] == 1


def test_load_logs_summary_at_warning_level(home, write_config, caplog):
    from keyfence import __version__
    write_config("mode: redact\n")
    with caplog.at_level("WARNING", logger="keyfence"):
        KeyFence().load(None)
    assert [record.levelname for record in caplog.records] == ["WARNING"]
    assert f"keyfence {__version__}: mode=redact | " in caplog.text
    assert "hosts monitored" in caplog.text and "rules" in caplog.text and "vault with 0 secret(s)" in caplog.text


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
    assert kf.stats == {"scanned": 1, "findings": 0, "suppressed": 0, "blocked": 0, "errors": 0, "canaries": 0}


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


def test_audit_log_shows_at_most_two_characters_of_a_short_secret(guard, home):
    secret = "Zq8xK2mP9vL4"
    Vault().add(secret)
    kf = guard("redact")
    kf.request(make_flow(body=json.dumps({"content": f"my token is {secret}"}).encode()))
    text = (home / "audit.log").read_text()
    entry = json.loads(text.splitlines()[-1])
    finding = next(f for f in entry["findings"] if f["kind"] == "vault")
    assert finding["key"] == "content"
    assert secret not in text
    assert sum(finding["preview"].count(c) for c in set(secret)) <= 2


def test_redaction_adds_notice_to_system_prompt(guard):
    kf = guard("redact")
    body = json.dumps({"system": "sys", "messages": [{"role": "user", "content": f"key {KEY}"}]}).encode()
    flow = make_flow(body=body, host="api.anthropic.com")
    kf.request(flow)
    out = json.loads(flow.request.get_text())
    assert "keyfence" in out["system"]
    assert "[REDACTED:github-token]" in out["messages"][0]["content"]


@pytest.mark.parametrize("mode, promise", [("redact", "not restored"), ("placeholder", "restored automatically")])
def test_notice_follows_the_configured_mode(guard, mode, promise):
    kf = guard(mode)
    body = json.dumps({"system": "sys", "messages": [{"role": "user", "content": f"key {KEY}"}]}).encode()
    flow = make_flow(body=body, host="api.anthropic.com")
    kf.request(flow)
    assert promise in json.loads(flow.request.get_text())["system"]


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


def test_audit_mode_logs_and_changes_nothing(guard, home, caplog):
    kf = guard("audit")
    flow = make_flow()
    with caplog.at_level("WARNING", logger="keyfence"):
        kf.request(flow)
    assert flow.request.content == BODY
    assert flow.response is None and MAPPING_KEY not in flow.metadata
    assert "AUDIT -> api.openai.com: 1 secret(s) sent unchanged" in caplog.text
    entry = json.loads((home / "audit.log").read_text().splitlines()[-1])
    assert entry["mode"] == "audit" and entry["findings"][0]["kind"] == "github-token"


def test_injected_config_and_vault_are_not_reloaded(home, write_config):
    from keyfence.config import Config
    write_config("mode: block\n")
    cfg = Config(mode="redact", audit_log=home / "demo-audit.log")
    vault = Vault(path=home / "other.json")
    kf = KeyFence(config=cfg, vault=vault)
    (home / "config.yaml").write_text("mode: block\n")
    os.utime(home / "config.yaml", (5, 5))
    flow = make_flow()
    kf.request(flow)
    assert flow.response is None and "[REDACTED:github-token]" in flow.request.get_text()
    assert (home / "demo-audit.log").exists()


def test_block_mode(guard):
    kf = guard("block")
    flow = make_flow()
    kf.request(flow)
    assert flow.response.status_code == 403
    payload = json.loads(flow.response.get_text())
    assert payload["error"]["type"] == "keyfence_blocked"
    assert "github-token" in payload["error"]["message"]
    assert kf.stats["blocked"] == 1


BEDROCK = "bedrock-runtime.us-east-1.amazonaws.com"
SIGV4 = "AWS4-HMAC-SHA256 Credential=EXAMPLE/20260924/us-east-1/bedrock/aws4_request, SignedHeaders=host;x-amz-date, Signature=0f1e"
SIGV4A = "AWS4-ECDSA-P256-SHA256 Credential=EXAMPLE/20260924/bedrock/aws4_request, SignedHeaders=host, Signature=3045"


def signed_flow(body=BODY, authorization=SIGV4, path=b"/model/anthropic.claude/invoke"):
    flow = make_flow(body=body, host=BEDROCK, path=path)
    if authorization:
        flow.request.headers["authorization"] = authorization
    return flow


@pytest.mark.parametrize("mode", ["redact", "placeholder"])
@pytest.mark.parametrize("authorization", [SIGV4, SIGV4A])
def test_sigv4_signed_request_with_a_secret_is_blocked_instead_of_rewritten(guard, home, mode, authorization):
    kf = guard(mode)
    flow = signed_flow(authorization=authorization)
    kf.request(flow)
    assert flow.response.status_code == 403
    message = json.loads(flow.response.get_text())["error"]["message"]
    assert "SigV4" in message and "github-token" in message
    assert flow.request.content == BODY and MAPPING_KEY not in flow.metadata
    assert kf.stats["blocked"] == 1
    assert json.loads((home / "audit.log").read_text().splitlines()[-1])["host"] == BEDROCK


def test_presigned_url_counts_as_signed(guard):
    kf = guard("redact")
    flow = signed_flow(authorization=None,
                       path=b"/model/x/invoke?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=0f1e")
    kf.request(flow)
    assert flow.response.status_code == 403 and "SigV4" in flow.response.get_text()


def test_unsigned_request_to_bedrock_is_still_redacted(guard):
    kf = guard("redact")
    flow = signed_flow(authorization="Bearer bedrock-api-key-example")
    kf.request(flow)
    assert flow.response is None
    assert "[REDACTED:github-token]" in flow.request.get_text()


def test_sigv4_signed_request_in_audit_mode_passes_unchanged(guard):
    kf = guard("audit")
    flow = signed_flow()
    kf.request(flow)
    assert flow.response is None and flow.request.content == BODY


def test_clean_sigv4_signed_request_passes_untouched(guard):
    kf = guard("redact")
    body = b'{"messages":[{"role":"user","content":"explain entropy"}]}'
    flow = signed_flow(body=body)
    kf.request(flow)
    assert flow.response is None and flow.request.content == body
    assert kf.stats["blocked"] == 0


TOKEN_RE = re.compile(r"<<SECRET_[0-9a-f]{10}>>")


def test_placeholder_mode_sets_mapping_and_identity_encoding(guard):
    kf = guard("placeholder")
    other = "sk-proj-Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"
    flow = make_flow(body=f"first {KEY} then {other}".encode())
    kf.request(flow)
    text = flow.request.get_text()
    tokens = TOKEN_RE.findall(text)
    assert len(tokens) == 2 and tokens[0] != tokens[1]
    assert text == f"first {tokens[0]} then {tokens[1]}"
    assert flow.metadata[MAPPING_KEY] == {tokens[0]: KEY, tokens[1]: other}
    assert flow.request.headers["accept-encoding"] == "identity"


def test_placeholders_are_deterministic_across_requests_and_order(guard, home):
    kf = guard("placeholder")
    other = "sk-proj-Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"
    first = make_flow(body=f"{KEY} {other}".encode())
    second = make_flow(body=f"{other} then {KEY} and {KEY}".encode())
    kf.request(first)
    kf.request(second)
    inverse = {v: k for k, v in first.metadata[MAPPING_KEY].items()}
    assert second.request.get_text() == f"{inverse[other]} then {inverse[KEY]} and {inverse[KEY]}"
    restarted = KeyFence()
    third = make_flow(body=KEY.encode())
    restarted.request(third)
    assert third.request.get_text() == inverse[KEY]


def test_placeholder_collisions_get_longer_ids(guard, monkeypatch):
    kf = guard("placeholder")
    digests = {KEY: "a" * 10 + "bb" + "0" * 52, "sk-proj-Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv": "a" * 10 + "cc" + "0" * 52}
    monkeypatch.setattr(kf.vault, "placeholder_digest", lambda value: digests[value])
    flow = make_flow(body=f"{KEY} sk-proj-Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv".encode())
    kf.request(flow)
    mapping = flow.metadata[MAPPING_KEY]
    assert set(mapping) == {"<<SECRET_" + "a" * 10 + ">>", "<<SECRET_" + "a" * 10 + "bb>>"}
    assert set(mapping.values()) == set(digests)


def test_canary_is_logged_and_audited(guard, home, caplog):
    Vault().add_canary("canary-value-0123456789", "/work/.env")
    kf = guard("redact")
    flow = make_flow(body=b"INTERNAL_API_TOKEN=canary-value-0123456789")
    with caplog.at_level("WARNING", logger="keyfence"):
        kf.request(flow)
    assert "CANARY tripped" in caplog.text and "/work/.env" in caplog.text
    assert flow.request.get_text() == "INTERNAL_API_TOKEN=[REDACTED:canary]"
    entry = json.loads((home / "audit.log").read_text().splitlines()[-1])
    assert entry["findings"][0] == {"kind": "canary", "preview": "*" * 23, "key": None, "label": "/work/.env"}
    assert kf.stats["canaries"] == 1


def test_proxy_start_persists_vault_salt(guard, home):
    guard("redact")
    assert (home / "vault.json").exists()


def test_detector_crash_fails_closed(guard, monkeypatch):
    kf = guard("redact")

    def boom(*_args, **_kwargs):
        raise RuntimeError("simulated detector crash")

    monkeypatch.setattr(addon_module, "scan_report", boom)
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
    assert not env_vault.path.exists() and not env_vault.lock_path.exists()
    main.add("later-secret-value-3")
    os.utime(home / "vault.json", (1, 1))
    kf._maybe_reload_vault()
    assert kf.vault.count() == 3 and kf.vault.contains("env-only-secret-value")
    flow = make_flow(body=b"x=env-only-secret-value y=main-vault-secret-value")
    kf.request(flow)
    assert flow.request.get_text() == "x=[REDACTED:vault] y=[REDACTED:vault]"


def test_secret_added_during_exec_on_a_fresh_machine_keeps_the_proxy_working(guard, home, monkeypatch):
    from keyfence.runner import build_env_vault
    assert not (home / "vault.json").exists()
    env_vault = build_env_vault({"OPENAI_API_KEY": "sk-proj-Zq8vLm3pR7tYw2Kd9Xc4Bn6"})
    monkeypatch.setenv(ENV_VAULT_VAR, str(env_vault.path))
    kf = guard("redact")
    Vault().add("added-during-the-session-1")
    os.utime(home / "vault.json", (1, 1))
    flow = make_flow(body=b"x=added-during-the-session-1 y=sk-proj-Zq8vLm3pR7tYw2Kd9Xc4Bn6")
    kf.request(flow)
    assert flow.response is None
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
    out = b"".join(flow.response.stream(event) + flow.response.stream(b""))
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


def test_buffered_sse_restores_split_placeholders(guard):
    kf = guard("placeholder")
    body = (b'data: {"delta":{"text":"gz key <<SEC"}}\n\n'
            b'data: {"delta":{"text":"RET_1>> end"}}\n\n')
    flow = make_response_flow(
        {"<<SECRET_1>>": KEY},
        {"content-type": "text/event-stream", "content-encoding": "gzip"}, body=body)
    kf.responseheaders(flow)
    assert flow.response.stream is False
    kf.response(flow)
    assert KEY.encode() in flow.response.content and b"<<SEC" not in flow.response.content


def test_config_is_reloaded_when_file_changes(guard, home, write_config):
    kf = guard("redact")
    write_config("mode: block\n")
    os.utime(home / "config.yaml", (1, 1))
    flow = make_flow()
    kf.request(flow)
    assert flow.response is not None and flow.response.status_code == 403


def test_invalid_config_reload_keeps_previous(guard, home, write_config, caplog):
    kf = guard("redact")
    write_config("mode: nonsense\n")
    os.utime(home / "config.yaml", (2, 2))
    flow = make_flow()
    with caplog.at_level("ERROR", logger="keyfence"):
        kf.request(flow)
    assert "config reload failed" in caplog.text
    assert kf.config.mode == "redact" and "[REDACTED:github-token]" in flow.request.get_text()


def test_corrupted_vault_stops_startup_with_a_message(home, write_config, monkeypatch, capsys):
    write_config("mode: redact\n")
    (home / "vault.json").write_text("x")
    kf = KeyFence()
    with pytest.raises(addon_module.VaultError) as exc:
        kf._setup()
    assert "keyfence import" in str(exc.value)
    monkeypatch.setattr(addon_module.os, "_exit", lambda code: (_ for _ in ()).throw(SystemExit(code)))
    with pytest.raises(SystemExit) as stop:
        kf.load(None)
    assert stop.value.code == 1
    err = capsys.readouterr().err
    assert err.startswith("keyfence: ") and "Traceback" not in err


def test_missing_or_empty_config_keeps_previous(guard, home, write_config, caplog):
    kf = guard("block", 'extra_hosts: ["example.test"]\n')
    (home / "config.yaml").write_text("")
    os.utime(home / "config.yaml", (3, 3))
    flow = make_flow(host="example.test")
    with caplog.at_level("WARNING", logger="keyfence"):
        kf.request(flow)
    assert flow.response is not None and flow.response.status_code == 403
    assert "missing or empty" in caplog.text
    (home / "config.yaml").unlink()
    second = make_flow(host="example.test")
    kf.request(second)
    assert second.response is not None and second.response.status_code == 403
    assert kf.config.mode == "block"


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


HOST = "db.internal.example.com"
RANDOM = "Zq8xK2mP9vL4nR7tW3yB6cF1dH5jXw2Kp"


def test_ignored_value_is_neither_blocked_nor_audited_and_never_written_in_clear(guard, home, caplog):
    Vault().add(HOST)
    kf = guard("block", f"ignore_values:\n  - {HOST}\n")
    assert kf.ignore.value_count == 1
    clean = make_flow(body=json.dumps({"content": f"connect to {HOST}"}).encode())
    with caplog.at_level("INFO", logger="keyfence"):
        kf.request(clean)
    assert clean.response is None
    assert kf.stats["suppressed"] == 1 and kf.stats["findings"] == 0 and kf.stats["blocked"] == 0
    assert "1 finding(s) ignored by config for api.openai.com" in caplog.text
    assert not (home / "audit.log").exists()
    mixed = make_flow(body=json.dumps({"content": f"{HOST} and {KEY}"}).encode())
    kf.request(mixed)
    assert mixed.response.status_code == 403
    entry = json.loads((home / "audit.log").read_text().splitlines()[-1])
    assert entry["count"] == 1 and entry["suppressed"] == 1
    assert entry["findings"] == [{"kind": "github-token", "preview": "gh…89 (40 chars)", "key": "content"}]
    assert HOST not in (home / "audit.log").read_text()
    assert HOST not in (home / "vault.json").read_text()


def test_audit_entry_omits_suppressed_when_nothing_was_ignored(guard, home):
    kf = guard("redact", f"ignore_values:\n  - {HOST}\n")
    kf.request(make_flow())
    entry = json.loads((home / "audit.log").read_text().splitlines()[-1])
    assert "suppressed" not in entry and entry["count"] == 1


def test_ignored_key_uses_the_json_key_of_the_finding(guard):
    kf = guard("block", "ignore_keys:\n  - db_host\n")
    body = json.dumps({"DB_HOST": RANDOM, "content": "hello"}).encode()
    allowed = make_flow(body=body)
    kf.request(allowed)
    assert allowed.response is None and kf.stats["suppressed"] == 1
    blocked = make_flow(body=json.dumps({"other": RANDOM}).encode())
    kf.request(blocked)
    assert blocked.response.status_code == 403


def test_ignore_lists_are_rebuilt_on_config_and_vault_reload(guard, home, write_config, caplog):
    Vault().add(HOST)
    kf = guard("block")
    blocked = make_flow(body=f"host {HOST}".encode())
    kf.request(blocked)
    assert blocked.response.status_code == 403
    write_config(f"mode: block\nignore_values: [{HOST}]\n")
    os.utime(home / "config.yaml", (1, 1))
    allowed = make_flow(body=f"host {HOST}".encode())
    with caplog.at_level("INFO", logger="keyfence"):
        kf.request(allowed)
    assert allowed.response is None
    assert "config reloaded: mode=block | " in caplog.text and "ignoring 0 key(s), 1 value(s)" in caplog.text
    Vault().add("another-secret-value-2026")
    os.utime(home / "vault.json", (1, 1))
    again = make_flow(body=f"host {HOST} and another-secret-value-2026".encode())
    kf.request(again)
    assert again.response.status_code == 403
    assert kf.vault.count() == 2 and kf.ignore.value_count == 1
    assert json.loads((home / "audit.log").read_text().splitlines()[-1])["suppressed"] == 1


def test_injected_config_carries_its_ignore_lists(home):
    from keyfence.config import Config
    vault = Vault(path=home / "other.json")
    vault.add(HOST)
    cfg = Config(mode="block", ignore_values=[HOST], audit_log=home / "demo-audit.log")
    kf = KeyFence(config=cfg, vault=vault)
    flow = make_flow(body=f"host {HOST}".encode())
    kf.request(flow)
    assert flow.response is None and kf.stats["suppressed"] == 1


ESCAPED_SECRET = "senha-do-postgres-producao-2026"


def test_redact_keeps_json_valid_next_to_escapes(guard):
    Vault().add(ESCAPED_SECRET)
    kf = guard("redact")
    body = json.dumps({"content": "prefix\t" + KEY + "\n" + ESCAPED_SECRET + " end", "note": "caf\u00e9 " + KEY}).encode()
    flow = make_flow(body=body)
    kf.request(flow)
    out = json.loads(flow.request.get_text())
    assert re.fullmatch(r"prefix\t\[REDACTED:github-token\]\n\[REDACTED:vault\] end", out["content"])
    assert re.fullmatch(r"caf\u00e9 \[REDACTED:github-token\]", out["note"])
    assert flow.response is None and kf.stats["errors"] == 0


def test_placeholder_keeps_json_valid_and_restores_next_to_escapes(guard):
    kf = guard("placeholder")
    flow = make_flow(body=json.dumps({"content": "line\n" + KEY + "\tend"}).encode())
    kf.request(flow)
    out = json.loads(flow.request.get_text())
    token = next(iter(flow.metadata[MAPPING_KEY]))
    assert out["content"] == f"line\n{token}\tend"
    flow.response = tutils.tresp(headers=http.Headers([(b"content-type", b"application/json")]),
                                 content=json.dumps({"text": f"use {token} now"}).encode())
    kf.response(flow)
    assert json.loads(flow.response.get_text())["text"] == f"use {KEY} now"


def test_a_replacement_inside_an_escape_is_widened_to_the_whole_escape(guard, monkeypatch):
    kf = guard("redact")
    text = '{"content": "caf\\u00e9 secret"}'
    start = text.index("00e9")
    finding = addon_module.Finding(kind="x", value="00e9 sec", start=start, end=start + 8)
    monkeypatch.setattr(addon_module, "scan_report", lambda *a, **k: ScanReport([finding]))
    flow = make_flow(body=text.encode())
    kf.request(flow)
    assert json.loads(flow.request.get_text())["content"] == "caf[REDACTED:x]ret"


def test_a_rewrite_that_would_break_the_json_fails_closed(guard, monkeypatch, caplog):
    kf = guard("redact")
    finding = addon_module.Finding(kind="x", value='{"con', start=0, end=5)
    monkeypatch.setattr(addon_module, "scan_report", lambda *a, **k: ScanReport([finding]))
    flow = make_flow(body=b'{"content": "abc"}')
    with caplog.at_level("ERROR", logger="keyfence"):
        kf.request(flow)
    assert flow.response.status_code == 403
    assert "breaking its JSON" in json.loads(flow.response.get_text())["error"]["message"]
    assert kf.stats["errors"] == 1 and "failing closed" in caplog.text


def test_non_json_bodies_are_spliced_as_before(guard):
    kf = guard("redact")
    flow = make_flow(body=("path C:\\temp\\" + KEY + " done").encode())
    kf.request(flow)
    assert flow.request.get_text() == "path C:\\temp\\[REDACTED:github-token] done"


def test_whole_escapes_leaves_spans_outside_escapes_alone():
    text = 'a\\nb\\u0041c'
    escapes = addon_module.json_escapes(text)
    assert escapes == ([1, 4], [3, 10])
    assert addon_module.whole_escapes(0, 1, escapes) == (0, 1)
    assert addon_module.whole_escapes(2, 3, escapes) == (1, 3)
    assert addon_module.whole_escapes(3, 6, escapes) == (3, 10)
    assert addon_module.whole_escapes(10, 11, escapes) == (10, 11)


def make_ws_flow(host="api.openai.com", path=b"/v1/realtime"):
    flow = tflow.tflow(req=tutils.treq(host=host, method=b"GET", path=path, content=b""))
    flow.websocket = WebSocketData()
    return flow


def send_frame(kf, flow, content, from_client=True, opcode=Opcode.TEXT):
    if isinstance(content, str):
        content = content.encode()
    message = WebSocketMessage(opcode, from_client, content)
    flow.websocket.messages.append(message)
    kf.websocket_message(flow)
    return message


def test_websocket_frame_to_monitored_host_is_redacted(guard, home, caplog):
    kf = guard("redact")
    flow = make_ws_flow()
    with caplog.at_level("WARNING", logger="keyfence"):
        message = send_frame(kf, flow, json.dumps({"text": f"my token is {KEY}"}))
    assert not message.dropped
    assert json.loads(message.text)["text"] == "my token is [REDACTED:github-token]"
    assert "REDACT -> api.openai.com: 1 secret(s) removed from a websocket frame" in caplog.text
    entry = json.loads((home / "audit.log").read_text().splitlines()[-1])
    assert entry["host"] == "api.openai.com" and entry["path"] == "/v1/realtime"
    assert entry["websocket"] is True and entry["findings"][0]["kind"] == "github-token"
    assert kf.stats["scanned"] == 1 and kf.stats["findings"] == 1


def test_websocket_frame_to_unmonitored_host_is_left_alone(guard):
    kf = guard("redact")
    message = send_frame(kf, make_ws_flow(host="example.com"), f"token {KEY}")
    assert message.text == f"token {KEY}" and kf.stats["scanned"] == 0


def test_clean_websocket_frame_passes_untouched(guard, home):
    kf = guard("redact")
    message = send_frame(kf, make_ws_flow(), "explain entropy")
    assert message.text == "explain entropy" and not message.dropped
    assert kf.stats["scanned"] == 1 and kf.stats["findings"] == 0
    assert not (home / "audit.log").exists()


def test_websocket_frame_in_block_mode_is_dropped(guard, caplog):
    kf = guard("block")
    with caplog.at_level("WARNING", logger="keyfence"):
        message = send_frame(kf, make_ws_flow(), f"token {KEY}")
    assert message.dropped and message.text == f"token {KEY}"
    assert kf.stats["blocked"] == 1
    assert "BLOCKED -> api.openai.com: 1 secret(s) in a websocket frame" in caplog.text


def test_websocket_frame_in_audit_mode_is_logged_unchanged(guard, home, caplog):
    kf = guard("audit")
    with caplog.at_level("WARNING", logger="keyfence"):
        message = send_frame(kf, make_ws_flow(), f"token {KEY}")
    assert not message.dropped and message.text == f"token {KEY}"
    assert "AUDIT -> api.openai.com: 1 secret(s) sent unchanged in a websocket frame" in caplog.text
    assert json.loads((home / "audit.log").read_text().splitlines()[-1])["websocket"] is True


def test_websocket_placeholders_are_restored_in_the_frames_that_come_back(guard):
    kf = guard("placeholder")
    flow = make_ws_flow()
    sent = send_frame(kf, flow, json.dumps({"text": f"use {KEY} now"}))
    token = next(iter(flow.metadata[MAPPING_KEY]))
    assert json.loads(sent.text)["text"] == f"use {token} now"
    back = send_frame(kf, flow, f"the key is {token}", from_client=False)
    assert back.text == f"the key is {KEY}" and not back.dropped


def test_websocket_server_frames_are_untouched_without_a_mapping(guard):
    kf = guard("redact")
    flow = make_ws_flow()
    back = send_frame(kf, flow, "<<SECRET_1>> stays", from_client=False)
    assert back.text == "<<SECRET_1>> stays" and not back.dropped
    assert kf.stats["scanned"] == 0 and kf.stats["errors"] == 0


def test_binary_websocket_server_frames_pass_through_a_mapped_connection(guard):
    kf = guard("placeholder")
    flow = make_ws_flow()
    send_frame(kf, flow, json.dumps({"text": f"use {KEY}"}))
    assert flow.metadata[MAPPING_KEY]
    audio = b"\x00\x01\x02 <<SECRET_1>> \xff"
    back = send_frame(kf, flow, audio, from_client=False, opcode=Opcode.BINARY)
    assert back.content == audio and not back.dropped and kf.stats["errors"] == 0


def test_binary_websocket_frames_are_not_scanned(guard):
    kf = guard("block")
    message = send_frame(kf, make_ws_flow(), KEY.encode(), opcode=Opcode.BINARY)
    assert not message.dropped and kf.stats["scanned"] == 0


def test_empty_websocket_frame_is_ignored(guard):
    kf = guard("redact")
    message = send_frame(kf, make_ws_flow(), "")
    assert not message.dropped and kf.stats["scanned"] == 0


def test_websocket_message_without_a_frame_is_ignored(guard):
    kf = guard("redact")
    flow = make_ws_flow()
    kf.websocket_message(flow)
    flow.websocket = None
    kf.websocket_message(flow)
    assert kf.stats["scanned"] == 0


def test_websocket_detector_crash_drops_the_frame(guard, monkeypatch, caplog):
    kf = guard("redact")

    def boom(*_args, **_kwargs):
        raise RuntimeError("simulated detector crash")

    monkeypatch.setattr(addon_module, "scan_report", boom)
    with caplog.at_level("ERROR", logger="keyfence"):
        message = send_frame(kf, make_ws_flow(), f"token {KEY}")
    assert message.dropped and kf.stats["errors"] == 1
    assert "failing closed" in caplog.text


def test_a_frame_rewrite_that_would_break_the_json_drops_the_frame(guard, monkeypatch, caplog):
    kf = guard("redact")
    finding = addon_module.Finding(kind="x", value='{"te', start=0, end=4)
    monkeypatch.setattr(addon_module, "scan_report", lambda *a, **k: ScanReport([finding]))
    with caplog.at_level("ERROR", logger="keyfence"):
        message = send_frame(kf, make_ws_flow(), '{"text": "abc"}')
    assert message.dropped and kf.stats["errors"] == 1
    assert "failing closed" in caplog.text


def test_running_turns_websocket_interception_back_on(guard, caplog):
    from mitmproxy.test import taddons
    kf = guard("redact")
    with taddons.context(kf) as tctx:
        tctx.options.websocket = False
        with caplog.at_level("WARNING", logger="keyfence"):
            kf.running()
        assert tctx.options.websocket is True
        assert "websocket interception was off" in caplog.text
        caplog.clear()
        kf.running()
        assert tctx.options.websocket is True and "websocket interception was off" not in caplog.text
