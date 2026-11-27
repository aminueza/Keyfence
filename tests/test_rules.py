import re

import pytest

from keyfence.rules import BUNDLED_RULES, DEFAULT_DISABLED, Rule, compile_regex, load_rules, present_keywords


def test_bundled_rules_load():
    rules = load_rules()
    assert len(rules) >= 200
    assert BUNDLED_RULES.exists()


def test_inline_ignorecase_is_normalised():
    pattern = compile_regex(r"abc(?i)def")
    assert pattern.flags & re.IGNORECASE
    assert pattern.search("ABCDEF")


def test_end_of_string_anchor_is_translated():
    pattern = compile_regex(r"tok-[a-z]+\z")
    assert pattern.search("x tok-abc")
    assert not pattern.search("tok-abc\n")
    assert compile_regex(r"literal\\z").search("literal\\z")


def test_every_bundled_rule_with_a_regex_loads():
    import tomllib
    with BUNDLED_RULES.open("rb") as fh:
        expected = sum(1 for r in tomllib.load(fh)["rules"] if "regex" in r and r["id"] != "generic-api-key")
    assert len(load_rules()) == expected


def test_compile_regex_without_flags_is_case_sensitive():
    assert compile_regex("abc").search("ABC") is None


def test_rules_with_inline_flags_are_loaded():
    names = {r.name for r in load_rules()}
    assert "adobe-client-secret" in names
    assert "linear-api-key" in names


def test_rule_without_regex_is_skipped(tmp_path):
    path = tmp_path / "rules.toml"
    path.write_text('[[rules]]\nid = "path-only"\npath = ".*\\\\.p12$"\n'
                    '[[rules]]\nid = "ok"\nregex = "abc"\n')
    assert [r.name for r in load_rules(path)] == ["ok"]


def test_rule_with_invalid_regex_is_skipped(tmp_path):
    path = tmp_path / "rules.toml"
    path.write_text('[[rules]]\nid = "broken"\nregex = "(unclosed"\n')
    assert load_rules(path) == []


@pytest.mark.parametrize("regex", ["a{4294967296}", "(" * 600 + ")" * 600])
def test_rule_with_a_regex_python_refuses_to_compile_is_skipped(tmp_path, regex):
    path = tmp_path / "rules.toml"
    path.write_text(f'[[rules]]\nid = "huge"\nregex = "{regex}"\nkeywords = ["a"]\n')
    assert load_rules(path) == []


def test_an_allowlist_regex_python_refuses_to_compile_is_dropped_on_its_own(tmp_path):
    path = tmp_path / "rules.toml"
    path.write_text('[[rules]]\nid = "x"\nregex = "tok_[a-z]+"\nkeywords = ["tok_"]\n'
                    '[[rules.allowlists]]\nregexes = ["tok_example", "b{4294967296}"]\n')
    rule = load_rules(path)[0]
    assert rule.is_ignored("tok_example")
    assert not rule.is_ignored("tok_real")
    assert len(rule.ignore_regexes) == 1


def test_extend_use_default_loads_the_bundled_rules_too(tmp_path):
    path = tmp_path / "gitleaks.toml"
    path.write_text('[extend]\nuseDefault = true\n\n[[rules]]\nid = "mine"\nregex = "mine_[a-z]{20}"\n')
    names = [r.name for r in load_rules(path)]
    assert "mine" in names
    assert len(names) == len(load_rules()) + 1


def test_extend_disabled_rules_drops_a_bundled_rule(tmp_path):
    path = tmp_path / "gitleaks.toml"
    path.write_text('[extend]\nuseDefault = true\ndisabledRules = ["aws-access-token"]\n')
    names = [r.name for r in load_rules(path)]
    assert "aws-access-token" not in names
    assert len(names) == len(load_rules()) - 1


def test_a_custom_rule_with_a_bundled_id_replaces_it(tmp_path):
    path = tmp_path / "gitleaks.toml"
    path.write_text('[extend]\nuseDefault = true\n\n[[rules]]\nid = "aws-access-token"\n'
                    'regex = "AKIA[0-9]{16}"\nkeywords = ["AKIA"]\n')
    rules = load_rules(path)
    mine = [r for r in rules if r.name == "aws-access-token"]
    assert len(mine) == 1
    assert mine[0].pattern.pattern != next(r.pattern.pattern for r in load_rules() if r.name == "aws-access-token")
    assert len(rules) == len(load_rules())


def test_extend_path_is_refused(tmp_path):
    path = tmp_path / "gitleaks.toml"
    path.write_text('[extend]\npath = "other.toml"\n')
    with pytest.raises(ValueError, match="scan.gitleaks_rules"):
        load_rules(path)


@pytest.mark.parametrize("text", ['[extend]\nuseDefault = "yes"\n', '[extend]\ndisabledRules = "aws-access-token"\n',
                                  'extend = "x"\n'])
def test_a_bad_extend_table_is_refused(tmp_path, text):
    path = tmp_path / "gitleaks.toml"
    path.write_text(text)
    with pytest.raises(ValueError, match="extend"):
        load_rules(path)


def test_extend_disabled_rules_leaves_a_rule_of_the_file_itself(tmp_path):
    path = tmp_path / "gitleaks.toml"
    path.write_text('[extend]\nuseDefault = true\ndisabledRules = ["aws-access-token"]\n\n[[rules]]\nid = "aws-access-token"\n'
                    'regex = "AKIA[0-9]{16}"\nkeywords = ["AKIA"]\n')
    rules = load_rules(path)
    assert [r.pattern.pattern for r in rules if r.name == "aws-access-token"] == ["AKIA[0-9]{16}"]
    assert len(rules) == len(load_rules())


def test_extend_disabled_rules_without_use_default_drops_nothing(tmp_path):
    path = tmp_path / "gitleaks.toml"
    path.write_text('[extend]\ndisabledRules = ["mine"]\n\n[[rules]]\nid = "mine"\nregex = "mine_[a-z]{20}"\n')
    assert [r.name for r in load_rules(path)] == ["mine"]


def test_allowlists_are_parsed(tmp_path):
    path = tmp_path / "rules.toml"
    path.write_text(
        '[[rules]]\nid = "x"\nregex = "tok_[a-z]+"\nkeywords = ["tok_"]\n'
        '[[rules.allowlists]]\nregexes = ["tok_example", "(bad"]\nstopwords = ["Sample"]\n')
    rule = load_rules(path)[0]
    assert rule.is_ignored("tok_example")
    assert rule.is_ignored("tok_sample")
    assert not rule.is_ignored("tok_real")
    assert len(rule.ignore_regexes) == 1


def test_applies_to_uses_keywords():
    rule = Rule(name="r", pattern=re.compile("x"), keywords=("needle",))
    assert rule.applies_to("hay needle hay")
    assert not rule.applies_to("hay only")
    assert Rule(name="r", pattern=re.compile("x")).applies_to("anything")


def test_generic_api_key_is_disabled_by_default():
    assert "generic-api-key" in DEFAULT_DISABLED
    assert "generic-api-key" not in {r.name for r in load_rules()}
    assert "generic-api-key" in {r.name for r in load_rules(disabled=())}


def test_single_capture_group_is_the_secret(tmp_path):
    path = tmp_path / "rules.toml"
    path.write_text(
        '[[rules]]\nid = "one"\nregex = "tok-([a-z0-9]{10})"\n'
        '[[rules]]\nid = "two"\nregex = "(a)(b)"\n'
        '[[rules]]\nid = "explicit"\nregex = "(x)(y)"\nsecretGroup = 2\n')
    groups = {r.name: r.secret_group for r in load_rules(path)}
    assert groups == {"one": 1, "two": 0, "explicit": 2}


def test_present_keywords_handles_overlapping_keywords():
    short = Rule(name="s", pattern=re.compile("x"), keywords=("key",))
    long = Rule(name="l", pattern=re.compile("x"), keywords=("apikey",))
    none = Rule(name="n", pattern=re.compile("x"))
    present = present_keywords("set apikey=1", [short, long, none])
    assert present == {"key", "apikey"}
    assert short.applies_with(present) and long.applies_with(present) and none.applies_with(present)
    assert not short.applies_with(present_keywords("nothing here", [short]))
    assert present_keywords("anything", [none]) == frozenset()


def test_missing_rules_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_rules(tmp_path / "nope.toml")


def _dense(unit: str, size: int) -> str:
    return unit * (size // len(unit))


def test_every_bundled_rule_is_fast_on_keyword_dense_text():
    import time
    slow = []
    for rule in load_rules(disabled=()):
        for keyword in (rule.keywords or ("key",))[:3]:
            for unit in (keyword, keyword + "-", keyword + "A1", keyword + "=", keyword + ": ", keyword + "."):
                started = time.perf_counter()
                for _ in rule.pattern.finditer(_dense(unit, 16384)):
                    pass
                if time.perf_counter() - started > 1.0:
                    slow.append((rule.name, unit))
    assert slow == []


@pytest.mark.parametrize("name,unit", [("curl-auth-header", "curl="), ("curl-auth-user", "curl-")])
def test_curl_rules_are_linear_on_a_long_line_of_curl_words(name, unit):
    import time
    rule = next(r for r in load_rules() if r.name == name)
    started = time.perf_counter()
    assert list(rule.pattern.finditer(_dense(unit, 65536))) == []
    assert time.perf_counter() - started < 1.0


def test_only_the_curl_rules_scan_line_by_line():
    from keyfence.rules import LineAnchoredPattern
    anchored = {r.name for r in load_rules(disabled=()) if isinstance(r.pattern, LineAnchoredPattern)}
    assert anchored == {"curl-auth-header", "curl-auth-user"}


@pytest.mark.parametrize("text", [
    "curl https://a.example; curl -H 'Authorization: Bearer tok_abcdef12345' https://b.example",
    "curl https://a.example\ncurl https://b.example \\\n  -H \"Authorization: Bearer tok_abcdef12345\"",
    "curl x curl y curl z\nnothing here\ncurl -X POST -H \"X-Api-Key: abcdef0123456789\" https://c.example",
    "curl -H \"Authorization: Token abcdefgh1234\" https://a curl -H \"Authorization: Token zyxwvuts9876\" https://b",
    "curl -u admin:s3cr3tpass https://a\ncurl x\ncurl --user=me:hunter22 https://b",
    "curl a\r\ncurl b\r\n  -u 'svc:p4ssw0rd' https://c",
    "curl https://a curl https://b\n" + "line\n" * 7 + "curl -H 'Authorization: Bearer tok_abcdef12345' https://c",
])
def test_line_anchored_scan_returns_the_matches_of_the_plain_pattern(text):
    for rule in load_rules():
        if rule.name.startswith("curl-auth-"):
            expected = [(m.span(), m.groups()) for m in rule.pattern.pattern.finditer(text)]
            assert [(m.span(), m.groups()) for m in rule.pattern.finditer(text)] == expected


def test_identifier_prefix_is_dropped_when_the_secret_is_a_group(tmp_path):
    path = tmp_path / "rules.toml"
    path.write_text(
        "[[rules]]\nid = \"single\"\nregex = '''(?i)[\\w.-]{0,50}?(?:acme)[\\s'\"]{0,3}=([a-z0-9]{12})'''\n"
        "[[rules]]\nid = \"double\"\nregex = '''[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?(?:(?-i:Acme))=)([a-z0-9]{12})'''\n"
        "[[rules]]\nid = \"whole\"\nregex = '''[\\w.-]{0,50}?(?:acme)=(x)(y)'''\n")
    rules = {r.name: r for r in load_rules(path)}
    assert rules["single"].pattern.pattern == "(?:acme)[\\s'\"]{0,3}=([a-z0-9]{12})"
    assert rules["double"].pattern.pattern == r"(?i:(?:(?-i:Acme))=)([a-z0-9]{12})"
    assert rules["whole"].pattern.pattern.startswith(r"[\w.-]{0,50}?")
    assert rules["single"].pattern.search("MY_APP_ACME =abcdef123456").group(1) == "abcdef123456"
    assert rules["double"].pattern.search("my_ACME_Acme=abcdef123456")
    assert rules["double"].pattern.search("my_aCME=abcdef123456") is None


def test_rules_whose_secret_is_the_whole_match_keep_the_identifier():
    rule = next(r for r in load_rules() if r.name == "dropbox-long-lived-api-token")
    text = "MY_DROPBOX_TOKEN = abcdefghijkAAAAAAAAAAA-_0123abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
    match = next(rule.pattern.finditer(text))
    assert match.group(rule.secret_group).startswith("MY_DROPBOX_TOKEN")


@pytest.mark.parametrize("name,text,secret", [
    ("okta-access-token", "export MY_OKTA_API_TOKEN=00" + "a1B2c3D4e5" * 4, "00" + "a1B2c3D4e5" * 4),
    ("cohere-api-token", "app.cohere_key: '" + "Ab1" * 13 + "Z'", "Ab1" * 13 + "Z"),
    ("sumologic-access-id", "SUMO_ACCESS_ID=suABCdef123456 ", "suABCdef123456"),
])
def test_trimmed_rules_still_find_secrets_behind_long_identifiers(name, text, secret):
    rule = next(r for r in load_rules() if r.name == name)
    assert [m.group(rule.secret_group) for m in rule.pattern.finditer(text)] == [secret]
