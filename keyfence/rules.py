from __future__ import annotations

import re
import tomllib
import warnings
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

BUNDLED_RULES = Path(__file__).parent / "rules" / "gitleaks.toml"
_INLINE_IGNORECASE = re.compile(r"\(\?i\)")


@dataclass
class Rule:
    name: str
    pattern: re.Pattern
    secret_group: int = 0
    min_entropy: float = 0.0
    keywords: tuple[str, ...] = ()
    ignore_regexes: tuple[re.Pattern, ...] = ()
    stopwords: tuple[str, ...] = ()

    def applies_to(self, text_lower: str) -> bool:
        return not self.keywords or any(k in text_lower for k in self.keywords)

    def applies_with(self, present: frozenset[str]) -> bool:
        return not self.keywords or any(k in present for k in self.keywords)

    def is_ignored(self, value: str) -> bool:
        low = value.lower()
        if any(word in low for word in self.stopwords):
            return True
        return any(r.search(value) for r in self.ignore_regexes)


def present_keywords(text_lower: str, rules: Iterable[Rule]) -> frozenset[str]:
    keywords = {k for r in rules for k in r.keywords}
    return frozenset(k for k in keywords if k in text_lower)


def compile_regex(regex: str, flags: int = 0) -> re.Pattern:
    if _INLINE_IGNORECASE.search(regex):
        regex = _INLINE_IGNORECASE.sub("", regex)
        flags |= re.IGNORECASE
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)
        return re.compile(regex, flags)


def _compile_many(regexes: list[str]) -> tuple[re.Pattern, ...]:
    compiled = []
    for regex in regexes:
        try:
            compiled.append(compile_regex(regex))
        except re.error:
            continue
    return tuple(compiled)


def _rule_from_gitleaks(raw: dict) -> Rule | None:
    if "regex" not in raw:
        return None
    try:
        pattern = compile_regex(raw["regex"])
    except re.error:
        return None
    ignore_regexes: list[str] = []
    stopwords: list[str] = []
    for allow in raw.get("allowlists", []):
        ignore_regexes.extend(allow.get("regexes", []))
        stopwords.extend(allow.get("stopwords", []))
    secret_group = int(raw.get("secretGroup", 0)) or (1 if pattern.groups == 1 else 0)
    return Rule(
        name=raw["id"],
        pattern=pattern,
        secret_group=secret_group,
        min_entropy=float(raw.get("entropy", 0.0)),
        keywords=tuple(k.lower() for k in raw.get("keywords", [])),
        ignore_regexes=_compile_many(ignore_regexes),
        stopwords=tuple(s.lower() for s in stopwords),
    )


DEFAULT_DISABLED = ("generic-api-key",)


def load_rules(path: str | Path | None = None,
               disabled: Iterable[str] = DEFAULT_DISABLED) -> list[Rule]:
    source = Path(path) if path else BUNDLED_RULES
    skip = set(disabled)
    with source.open("rb") as fh:
        data = tomllib.load(fh)
    rules = []
    for raw in data.get("rules", []):
        if raw.get("id") in skip:
            continue
        rule = _rule_from_gitleaks(raw)
        if rule is not None:
            rules.append(rule)
    return rules
