import re

import pytest

from keyfence.rules import BUNDLED_RULES, Rule, compile_regex, load_rules


def test_bundled_rules_load():
    rules = load_rules()
    assert len(rules) >= 200
    assert BUNDLED_RULES.exists()


def test_inline_ignorecase_is_normalised():
    pattern = compile_regex(r"abc(?i)def")
    assert pattern.flags & re.IGNORECASE
    assert pattern.search("ABCDEF")


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


def test_missing_rules_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_rules(tmp_path / "nope.toml")
