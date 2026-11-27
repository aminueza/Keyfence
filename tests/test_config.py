from pathlib import Path

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


@pytest.mark.parametrize("value", ["", "  "])
def test_empty_config_env_uses_the_default_path(home, monkeypatch, value):
    monkeypatch.setenv("KEYFENCE_CONFIG", value)
    assert Config.path() == home / "config.yaml"


def test_custom_gitleaks_rules_path(write_config, tmp_path):
    rules = tmp_path / "r.toml"
    rules.write_text('[[rules]]\nid = "only"\nregex = "abc"\n')
    write_config(f"scan:\n  gitleaks_rules: {rules}\n")
    assert [r.name for r in Config.load().scan.rules] == ["only"]


def test_gitleaks_rules_expands_home(write_config, tmp_path, monkeypatch):
    fake_home = tmp_path / "fake-home"
    fake_home.mkdir()
    (fake_home / "rules.toml").write_text('[[rules]]\nid = "only"\nregex = "abc"\n')
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    write_config("scan:\n  gitleaks_rules: ~/rules.toml\n")
    assert [r.name for r in Config.load().scan.rules] == ["only"]


def test_gitleaks_rules_relative_path_resolves_next_to_config(write_config, home):
    rules = home / "custom" / "rules.toml"
    rules.parent.mkdir()
    rules.write_text('[[rules]]\nid = "only"\nregex = "abc"\n')
    write_config("scan:\n  gitleaks_rules: custom/rules.toml\n")
    assert [r.name for r in Config.load().scan.rules] == ["only"]


@pytest.mark.parametrize("value", ['""', '"  "'])
def test_an_empty_gitleaks_rules_path_is_rejected(write_config, value):
    write_config(f"scan:\n  gitleaks_rules: {value}\n")
    with pytest.raises(ValueError, match="scan.gitleaks_rules must be a non-empty string path"):
        Config.load()


def test_missing_gitleaks_rules_raises_value_error(write_config):
    write_config("scan:\n  gitleaks_rules: missing.toml\n")
    with pytest.raises(ValueError) as excinfo:
        Config.load()
    assert "scan.gitleaks_rules" in str(excinfo.value)
    assert "missing.toml" in str(excinfo.value)


def test_invalid_gitleaks_rules_raises_value_error(write_config, home):
    (home / "rules.toml").write_text("not = [valid\n")
    write_config("scan:\n  gitleaks_rules: rules.toml\n")
    with pytest.raises(ValueError, match="scan.gitleaks_rules"):
        Config.load()


@pytest.mark.parametrize("content, problem", [
    (b'[[rules]]\nregex = "abc"\n', "rule 1 needs a string `id`"),
    (b'rules = "x"\n', "`rules` must be a list of tables"),
    (b'[[rules]]\nid = "a"\nregex = "abc"\nsecretGroup = "one"\n', "rule 1 (a): `secretGroup` must be an integer"),
    (b'[[rules]]\nid = "a"\nregex = "abc"\nsecretGroup = true\n', "rule 1 (a): `secretGroup` must be an integer"),
    (b"\xff\xfe junk", "codec can't decode"),
    (b'[[rules]]\nid = "a"\nregex = "abc"\nentropy = "x"\n', "rule 1 (a): `entropy` must be a number"),
    (b'[[rules]]\nid = "a"\nregex = "abc"\nentropy = nan\n', "rule 1 (a): `entropy` must be a number"),
    (b'[[rules]]\nid = "a"\nregex = "tok_(x+)"\nsecretGroup = 3\n', "rule a: `secretGroup` is 3, but its regex has 1 group(s)"),
    (b'[[rules]]\nid = "a"\nregex = "tok_(x+)"\nsecretGroup = -1\n', "rule a: `secretGroup` is -1, but its regex has 1 group(s)"),
    (b'[[rules]]\nid = "a"\nregex = 5\n', "rule 1 (a): `regex` must be a string"),
    (b'[[rules]]\nid = "a"\nregex = "abc"\nkeywords = "abc"\n', "rule 1 (a): `keywords` must be a list of strings"),
    (b'[[rules]]\nid = "a"\nregex = "abc"\nallowlists = "x"\n', "rule 1 (a): `allowlists` must be a list of tables"),
    (b'[[rules]]\nid = "a"\nregex = "abc"\n[[rules.allowlists]]\nregexes = "x"\n', "rule 1 (a): `allowlists.regexes` must be a list of strings"),
])
def test_a_gitleaks_rules_file_of_the_wrong_shape_names_the_setting_the_file_and_the_problem(write_config, home, content, problem):
    (home / "rules.toml").write_bytes(content)
    write_config("scan:\n  gitleaks_rules: rules.toml\n")
    with pytest.raises(ValueError) as excinfo:
        Config.load()
    message = str(excinfo.value)
    assert message.startswith(f"scan.gitleaks_rules: {home / 'rules.toml'}: ")
    assert problem in message


def test_a_gitleaks_rule_with_a_huge_integer_entropy_is_refused_with_one_message(write_config, home):
    (home / "rules.toml").write_text('[[rules]]\nid = "a"\nregex = "abc"\nentropy = 1' + "0" * 400 + "\n")
    write_config("scan:\n  gitleaks_rules: rules.toml\n")
    with pytest.raises(ValueError, match="rule 1 \\(a\\): `entropy` must be a number"):
        Config.load()


def test_a_gitleaks_rule_without_a_regex_is_still_accepted(write_config, home):
    (home / "rules.toml").write_text('[[rules]]\nid = "a"\npath = "x.pem"\n[[rules]]\nid = "b"\nregex = "abc"\nentropy = 2\n')
    write_config("scan:\n  gitleaks_rules: rules.toml\n")
    assert [r.name for r in Config.load().scan.rules] == ["b"]


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


def test_proxy_tcp_timeout_defaults_to_one_hour(home):
    assert Config.load().proxy_tcp_timeout == 3600


def test_proxy_tcp_timeout_reads_the_configured_value(write_config):
    write_config("proxy_tcp_timeout: 7200\n")
    assert Config.load().proxy_tcp_timeout == 7200


@pytest.mark.parametrize("text", [
    "proxy_tcp_timeout: 600.5\n",
    "proxy_tcp_timeout: '600'\n",
    "proxy_tcp_timeout: true\n",
])
def test_proxy_tcp_timeout_rejects_non_integer_values(write_config, text):
    write_config(text)
    with pytest.raises(ValueError, match="proxy_tcp_timeout"):
        Config.load()


@pytest.mark.parametrize("text", [
    "proxy_tcp_timeout: 0\n",
    "proxy_tcp_timeout: -1\n",
])
def test_proxy_tcp_timeout_rejects_non_positive_values(write_config, text):
    write_config(text)
    with pytest.raises(ValueError, match="proxy_tcp_timeout"):
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


@pytest.mark.parametrize("key", ["hosts", "extra_hosts"])
def test_hosts_lists_reject_a_single_string(write_config, key):
    # `hosts: api.anthropic.com` must not become 17 one-character hosts.
    write_config(f"{key}: api.anthropic.com\n")
    with pytest.raises(ValueError, match=rf"{key} must be a list of non-empty strings"):
        Config.load()


@pytest.mark.parametrize("key", ["hosts", "extra_hosts"])
def test_hosts_lists_reject_non_string_members(write_config, key):
    write_config(f"{key}: [api.anthropic.com, 3]\n")
    with pytest.raises(ValueError, match=rf"{key} must be a list of non-empty strings"):
        Config.load()


@pytest.mark.parametrize("key", ["hosts", "extra_hosts"])
@pytest.mark.parametrize("member", ['""', '" "'])
def test_hosts_lists_reject_empty_members(write_config, key, member):
    write_config(f"{key}: [{member}]\n")
    with pytest.raises(ValueError, match=rf"{key} must be a list of non-empty strings"):
        Config.load()


def test_empty_hosts_list_keeps_the_defaults(write_config, home):
    write_config("hosts: []\n")
    assert Config.load().hosts == DEFAULT_AI_HOSTS


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


@pytest.mark.parametrize("text,expected_key", [
    ("- mode: block\n", "config.yaml"),
    ("just a string\n", "config.yaml"),
    ("scan: true\n", "scan"),
    ("scan: [a, b]\n", "scan"),
    ("notice: 'false'\n", "notice"),
    ("notice: 1\n", "notice"),
    ("scan:\n  patterns: 'false'\n", "scan.patterns"),
    ("scan:\n  entropy: 1\n", "scan.entropy"),
    ("scan:\n  gitleaks: 'yes'\n", "scan.gitleaks"),
    ("scan:\n  entropy_threshold: '4.5'\n", "scan.entropy_threshold"),
    ("scan:\n  entropy_threshold: true\n", "scan.entropy_threshold"),
    ("scan:\n  entropy_min_length: '30'\n", "scan.entropy_min_length"),
    ("scan:\n  entropy_min_length: true\n", "scan.entropy_min_length"),
    ("scan:\n  entropy_max_length: '512'\n", "scan.entropy_max_length"),
    ("scan:\n  entropy_max_length: false\n", "scan.entropy_max_length"),
    ("scan:\n  allowlist: abc\n", "scan.allowlist"),
    ("scan:\n  gitleaks_disabled: generic-api-key\n", "scan.gitleaks_disabled"),
    ("scan:\n  gitleaks_rules: 123\n", "scan.gitleaks_rules"),
    ("intercept_all_hosts: 'false'\n", "intercept_all_hosts"),
    ("intercept_all_hosts:\n", "intercept_all_hosts"),
    ("audit_log: [1, 2]\n", "audit_log"),
    ("audit_log: false\n", "audit_log"),
    ('audit_log: ""\n', "audit_log"),
    ('audit_log: "   "\n', "audit_log"),
])
def test_config_rejects_non_mapping_and_wrong_typed_values(write_config, text, expected_key):
    write_config(text)
    with pytest.raises(ValueError, match=expected_key):
        Config.load()


def test_null_gitleaks_disabled_and_allowlist_default_to_empty(write_config, home):
    write_config("scan:\n  gitleaks_disabled:\n  allowlist:\n")
    cfg = Config.load()
    assert cfg.scan.gitleaks_disabled == []
    assert cfg.scan.allowlist == []
    assert "generic-api-key" in {r.name for r in cfg.scan.rules}


def test_cli_reports_single_error_line_on_non_mapping_config(home, write_config, capsys):
    from keyfence import cli
    write_config("- mode: block\n")
    assert cli.main(["status"]) == 1
    err = capsys.readouterr().err.strip()
    assert err.startswith("error:")
    assert len(err.splitlines()) == 1
    assert "Traceback" not in err


def test_prompt_hook_reports_config_error_not_guard_crash(home, write_config, capsys):
    import io
    import json
    from keyfence import prompt
    write_config("scan:\n  entropy_threshold: '4.5'\n")
    payload = json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "hello"})
    assert prompt.run(io.StringIO(payload), io.StringIO()) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["decision"] == "block"
    assert "configuration failed to load" in data["reason"]
    assert "guard crashed" not in data["reason"]
    assert "scan.entropy_threshold" in data["reason"]


def test_null_audit_log_keeps_the_default(write_config, home):
    write_config("audit_log:\n")
    assert Config.load().audit_log == Config().audit_log


def configuration_row(key: str) -> str:
    text = (Path(__file__).resolve().parent.parent / "docs" / "configuration.md").read_text()
    rows = [line for line in text.splitlines() if line.startswith(f"| `{key}` |")]
    assert len(rows) == 1, f"{key} has {len(rows)} rows in docs/configuration.md"
    return rows[0]


def test_docs_say_which_options_need_a_restart():
    assert "restart" in configuration_row("proxy_tcp_timeout")
    assert "next session" in configuration_row("intercept_all_hosts")


def test_docs_do_not_promise_a_reload_for_every_option():
    text = (Path(__file__).resolve().parent.parent / "docs" / "configuration.md").read_text()
    assert "like every other option" not in text
