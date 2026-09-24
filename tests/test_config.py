import pytest

from keyfence.config import DEFAULT_AI_HOSTS, Config
from keyfence.vault import Vault


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
        "notice: false\n"
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
    assert cfg.notice is False
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


def test_audit_mode_is_valid(write_config):
    write_config("mode: audit\n")
    assert Config.load().mode == "audit"


@pytest.mark.parametrize("host,expected", [
    ("api.openai.com", True),
    ("api.githubcopilot.com", True),
    ("us-central1-aiplatform.googleapis.com", True),
    ("aiplatform.googleapis.com", True),
    ("myproj.services.ai.azure.com", True),
    ("models.inference.ai.azure.com", True),
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


def test_ignore_lists_are_parsed(write_config, home):
    write_config("ignore_keys:\n  - DB_HOST\n  - ' SERVICE_NAME '\nignore_values:\n  - db.internal.example.com\n")
    cfg = Config.load()
    assert cfg.ignore_keys == ["DB_HOST", "SERVICE_NAME"]
    assert cfg.ignore_values == ["db.internal.example.com"]
    ignore = cfg.ignore_list(Vault(path=home / "vault.json"))
    assert ignore.key_count == 2 and ignore.value_count == 1
    assert ignore.ignores("db_host", "x") and ignore.ignores(None, "db.internal.example.com")
    assert not ignore.ignores("other", "x")


def test_ignore_lists_default_to_empty(write_config, home):
    write_config("ignore_keys:\nignore_values: []\n")
    cfg = Config.load()
    assert cfg.ignore_keys == [] and cfg.ignore_values == []
    assert Config().ignore_keys == [] and Config().ignore_values == []
    ignore = Config().ignore_list(Vault(path=home / "vault.json"))
    assert ignore.key_count == 0 and ignore.value_count == 0


@pytest.mark.parametrize("text", [
    "ignore_keys: DB_HOST\n",
    "ignore_values: db.internal.example.com\n",
    "ignore_keys: [DB_HOST, 3]\n",
    "ignore_values: [true]\n",
    "ignore_values: ['', x]\n",
    "ignore_keys: {a: b}\n",
])
def test_ignore_lists_reject_wrong_types(write_config, text):
    write_config(text)
    with pytest.raises(ValueError, match="must be a list of non-empty strings"):
        Config.load()


def test_malformed_yaml_is_a_value_error_naming_the_file(home, write_config):
    write_config("mode: [\n")
    with pytest.raises(ValueError) as exc:
        Config.load()
    assert "not valid YAML" in str(exc.value) and "config.yaml" in str(exc.value)
