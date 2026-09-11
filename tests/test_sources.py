import json

import pytest

from keyfence import sources


def fake_runner(responses):
    calls = []

    def run(command):
        calls.append(command)
        for prefix, output in responses:
            if command[:len(prefix)] == prefix:
                return output
        raise AssertionError(f"unexpected command {command}")

    run.calls = calls
    return run


def test_op_reads_concealed_fields_of_every_item():
    run = fake_runner([
        (["op", "item", "list"], json.dumps([{"id": "a"}, {"id": "b"}])),
        (["op", "item", "get", "a"], json.dumps({"fields": [{"type": "CONCEALED", "value": "secret-one-value"}, {"type": "STRING", "value": "user"}]})),
        (["op", "item", "get", "b"], json.dumps({"fields": [{"type": "CONCEALED", "value": ""}, {"type": "CONCEALED", "value": "secret-two-value"}]})),
    ])
    assert sources.fetch("op", "Personal", run) == [("password", "secret-one-value"), ("password", "secret-two-value")]
    assert run.calls[0] == ["op", "item", "list", "--format", "json", "--categories", sources.OP_CATEGORIES, "--vault", "Personal"]
    assert run.calls[1][-1] == "--reveal"


def test_vault_reads_kv_v2_and_v1_with_keys():
    v2 = fake_runner([(["vault", "kv", "get"], json.dumps({"data": {"data": {"pw": "vault-secret-value", "host": "db.internal", "n": 1}, "metadata": {}}}))])
    assert sorted(sources.fetch("vault", "secret/app", v2)) == [("host", "db.internal"), ("pw", "vault-secret-value")]
    v1 = fake_runner([(["vault", "kv", "get"], json.dumps({"data": {"pw": "v1-secret-value"}}))])
    assert sources.fetch("vault", "secret/app", v1) == [("pw", "v1-secret-value")]
    with pytest.raises(sources.SourceError):
        sources.fetch("vault", None, v1)


def test_doppler_uses_project_and_config():
    run = fake_runner([(["doppler", "secrets", "download"], json.dumps({"DB_PASSWORD": "doppler-secret-value", "PORT": "3000"}))])
    assert sorted(sources.fetch("doppler", "myapp/prd", run)) == [("DB_PASSWORD", "doppler-secret-value"), ("PORT", "3000")]
    assert run.calls[0][-4:] == ["--project", "myapp", "--config", "prd"]
    assert "--project" not in fake_runner([(["doppler"], "{}")]).calls


def test_aws_handles_json_and_plain_secrets():
    js = fake_runner([(["aws", "secretsmanager"], json.dumps({"username": "u", "password": "aws-secret-value"}) + "\n")])
    assert sorted(sources.fetch("aws", "prod/db", js)) == [("password", "aws-secret-value"), ("username", "u")]
    plain = fake_runner([(["aws", "secretsmanager"], "just-a-plain-token-value\n")])
    assert sources.fetch("aws", "prod/token", plain) == [("secret", "just-a-plain-token-value")]
    number = fake_runner([(["aws", "secretsmanager"], "12345\n")])
    assert sources.fetch("aws", "prod/n", number) == [("secret", "12345")]
    with pytest.raises(sources.SourceError):
        sources.fetch("aws", None, plain)


def test_non_json_output_is_a_clean_error():
    broken = fake_runner([(["vault", "kv", "get"], "Error: not logged in\n")])
    with pytest.raises(sources.SourceError) as exc:
        sources.fetch("vault", "secret/app", broken)
    assert "did not return JSON" in str(exc.value)
    empty = fake_runner([(["doppler"], "")])
    assert sources.fetch("doppler", None, empty) == []


def test_unknown_source():
    with pytest.raises(sources.SourceError):
        sources.fetch("nope", None, lambda cmd: "")


def test_real_runner_reports_missing_and_failing_tools(monkeypatch):
    with pytest.raises(sources.SourceError) as exc:
        sources._run(["definitely-not-a-command-xyz", "x"])
    assert "not installed" in str(exc.value)
    monkeypatch.setattr(sources.shutil, "which", lambda name: "/bin/false")
    with pytest.raises(sources.SourceError) as exc:
        sources._run(["false"])
    assert "exited with" in str(exc.value)
    monkeypatch.setattr(sources.shutil, "which", lambda name: "/bin/echo")
    assert sources._run(["echo", "hi"]).strip() == "hi"
