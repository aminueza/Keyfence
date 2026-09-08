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
