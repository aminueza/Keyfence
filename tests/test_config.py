import pytest

from keyfence.config import DEFAULT_AI_HOSTS, Config


def test_defaults_when_no_file(home):
    cfg = Config.load()
    assert cfg.mode == "redact"
    assert cfg.hosts == DEFAULT_AI_HOSTS
    assert not cfg.intercept_all_hosts
    assert len(cfg.scan.rules) >= 200


def test_reads_yaml(write_config, home):
    write_config(
        "mode: block\n"
        "hosts: [one.example]\n"
        "extra_hosts: [two.example]\n"
        "intercept_all_hosts: true\n"
        "audit_log: ~/kf-audit.log\n"
        "scan:\n"
        "  patterns: false\n"
        "  entropy: false\n"
        "  entropy_min_length: 30\n"
        "  entropy_threshold: 5.0\n"
        "  allowlist: [abc]\n"
        "  gitleaks: false\n")
    cfg = Config.load()
    assert cfg.mode == "block"
    assert cfg.hosts == ["one.example", "two.example"]
    assert cfg.intercept_all_hosts
    assert str(cfg.audit_log).endswith("kf-audit.log")
    assert not cfg.scan.patterns_enabled
    assert not cfg.scan.entropy_enabled
    assert cfg.scan.entropy_min_length == 30
    assert cfg.scan.entropy_threshold == 5.0
    assert cfg.scan.allowlist == ["abc"]
    assert cfg.scan.rules == []


def test_empty_yaml_uses_defaults(write_config):
    write_config("")
    assert Config.load().mode == "redact"


def test_explicit_path(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("mode: placeholder\n")
    assert Config.load(path).mode == "placeholder"


def test_custom_gitleaks_rules_path(write_config, tmp_path):
    rules = tmp_path / "r.toml"
    rules.write_text('[[rules]]\nid = "only"\nregex = "abc"\n')
    write_config(f"scan:\n  gitleaks_rules: {rules}\n")
    assert [r.name for r in Config.load().scan.rules] == ["only"]


def test_gitleaks_disabled_list(write_config, home):
    assert "generic-api-key" not in {r.name for r in Config.load().scan.rules}
    write_config("scan:\n  gitleaks_disabled: []\n")
    assert "generic-api-key" in {r.name for r in Config.load().scan.rules}
    write_config("scan:\n  gitleaks_disabled: [adobe-client-secret]\n")
    names = {r.name for r in Config.load().scan.rules}
    assert "adobe-client-secret" not in names and "generic-api-key" in names


def test_invalid_mode_raises(write_config):
    write_config("mode: yolo\n")
    with pytest.raises(ValueError):
        Config.load()


@pytest.mark.parametrize("host,expected", [
    ("api.openai.com", True),
    ("API.OPENAI.COM", True),
    ("sub.api.openai.com", True),
    ("bedrock-runtime.us-east-1.amazonaws.com", True),
    ("myorg.openai.azure.com", True),
    ("example.com", False),
    ("notapi.openai.com.evil.com", False),
])
def test_host_matches(host, expected):
    assert Config().host_matches(host) is expected


def test_intercept_all_hosts():
    cfg = Config(intercept_all_hosts=True)
    assert cfg.host_matches("anything.example")
