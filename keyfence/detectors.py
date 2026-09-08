from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from .rules import Rule, compile_regex


@dataclass
class Finding:
    kind: str
    value: str
    start: int
    end: int

    @property
    def masked(self) -> str:
        v = self.value
        if len(v) <= 10:
            return "*" * len(v)
        return f"{v[:4]}…{v[-4:]} ({len(v)} chars)"


def _rule(name: str, regex: str, **kwargs) -> Rule:
    return Rule(name=name, pattern=compile_regex(regex), **kwargs)


_GENERIC_ASSIGNMENT = compile_regex(r"""(?ix)
    \b[a-z0-9_-]*(?:api[_-]?key|apikey|secret|passwd|password|senha|auth[_-]?token|
        access[_-]?token|client[_-]?secret|private[_-]?key|db[_-]?pass|token)
    \b\s*[:=]\s*
    ["']?(?P<val>[^\s"'&]{8,})["']?
    """)

_PLACEHOLDER_VALUES = (
    r"^(?:changeme|change-me|placeholder|redacted|x+|password|senha|secret|"
    r"null|none|undefined|true|false)$"
)

BUILTIN_RULES: list[Rule] = [
    _rule("pem-private-key",
          r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
          r"[\s\S]+?"
          r"-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
    _rule("anthropic-api-key", r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
    _rule("openai-api-key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b"),
    _rule("aws-access-key-id", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    _rule("github-token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    _rule("github-pat-fine-grained", r"\bgithub_pat_[A-Za-z0-9_]{80,}\b"),
    _rule("gitlab-token", r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    _rule("slack-token", r"\bxox[baprse]-[A-Za-z0-9-]{10,}\b"),
    _rule("slack-webhook",
          r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"),
    _rule("google-api-key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    _rule("gcp-service-account", r'"private_key"\s*:\s*"-----BEGIN[^"]+"'),
    _rule("stripe-key", r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{20,}\b"),
    _rule("sendgrid-key", r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{40,}\b"),
    _rule("twilio-key", r"\bSK[0-9a-fA-F]{32}\b"),
    _rule("npm-token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    _rule("pypi-token", r"\bpypi-[A-Za-z0-9_-]{50,}\b"),
    _rule("huggingface-token", r"\bhf_[A-Za-z0-9]{30,}\b"),
    _rule("doppler-token", r"\bdp\.pt\.[A-Za-z0-9]{40,}\b"),
    _rule("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    _rule("heroku-uuid-key",
          r"(?i)heroku[^\n]{0,20}\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
    Rule("generic-assignment", _GENERIC_ASSIGNMENT,
         secret_group=_GENERIC_ASSIGNMENT.groupindex["val"],
         ignore_regexes=(
             compile_regex(_PLACEHOLDER_VALUES, re.IGNORECASE),
             compile_regex(r"(?i)^(?:\$\{|\$[a-z_]|<|your|chang|exemplo|example)"),
         )),
]


def _overlaps(start: int, end: int, spans) -> bool:
    return any(not (end <= s or start >= e) for s, e in spans)


def _scan_rules(text: str, rules: list[Rule]) -> list[Finding]:
    findings: list[Finding] = []
    claimed: list[tuple[int, int]] = []
    lower = text.lower()
    for rule in rules:
        if not rule.applies_to(lower):
            continue
        for m in rule.pattern.finditer(text):
            value = m.group(rule.secret_group)
            if not value:
                continue
            start, end = m.span(rule.secret_group)
            if rule.min_entropy and shannon_entropy(value) < rule.min_entropy:
                continue
            if rule.is_ignored(value) or _overlaps(start, end, claimed):
                continue
            claimed.append((start, end))
            findings.append(Finding(kind=rule.name, value=value, start=start, end=end))
    return findings


_TOKEN_SPLIT = re.compile(r"""[\s"'`,;{}()\[\]<>\\]+""")
_WORDISH = re.compile(r"^[A-Za-z]+$")
_HEXISH = re.compile(r"^[0-9a-fA-F]+$")
_PATHISH = re.compile(r"^[./~]|://")
_QUERY_VALUE = re.compile(r"[?&][A-Za-z0-9_.-]*(?:token|key|secret|auth|password|pass|sig)[A-Za-z0-9_.-]*=([^&\s#]{8,})", re.IGNORECASE)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _scan_entropy(text: str, min_length: int = 24, threshold: float = 4.5) -> list[Finding]:
    findings: list[Finding] = []
    pos = 0
    for raw in _TOKEN_SPLIT.split(text):
        idx = text.find(raw, pos)
        if idx == -1:
            idx = text.find(raw)
        pos = idx + len(raw) if idx >= 0 else pos

        token = raw.strip(".,:=!?")
        if len(token) < min_length:
            continue
        if _WORDISH.match(token) or _PATHISH.search(token):
            continue
        if _HEXISH.match(token) and len(token) in (32, 40, 64):
            continue
        has_upper = any(c.isupper() for c in token)
        has_lower = any(c.islower() for c in token)
        has_digit = any(c.isdigit() for c in token)
        if sum([has_upper, has_lower, has_digit]) < 2:
            continue
        if shannon_entropy(token) >= threshold:
            start = idx if idx >= 0 else 0
            off = raw.find(token)
            findings.append(Finding(
                kind="entropy", value=token,
                start=start + off, end=start + off + len(token)))
    return findings


def _scan_url_query(text: str) -> list[Finding]:
    return [
        Finding(kind="url-query-secret", value=m.group(1), start=m.start(1), end=m.end(1))
        for m in _QUERY_VALUE.finditer(text)
    ]


def _scan_vault(text: str, vault) -> list[Finding]:
    if vault is None or vault.is_empty():
        return []
    findings: list[Finding] = []
    seen_spans: set[tuple[int, int]] = set()
    candidates: set[str] = set()
    for raw in _TOKEN_SPLIT.split(text):
        if len(raw) >= vault.min_length:
            candidates.add(raw)
            candidates.add(raw.strip(".,:=!?&"))
    for m in re.finditer(r"[:=]\s*([^\s\"']{%d,})" % vault.min_length, text):
        candidates.add(m.group(1))

    for cand in candidates:
        if vault.contains(cand):
            for m in re.finditer(re.escape(cand), text):
                span = (m.start(), m.end())
                if span not in seen_spans:
                    seen_spans.add(span)
                    findings.append(Finding(
                        kind="vault", value=cand, start=span[0], end=span[1]))
    return findings


@dataclass
class ScanConfig:
    patterns_enabled: bool = True
    entropy_enabled: bool = True
    entropy_min_length: int = 24
    entropy_threshold: float = 4.5
    allowlist: list[str] = field(default_factory=list)
    gitleaks: bool = True
    gitleaks_rules: str | None = None
    rules: list[Rule] = field(default_factory=list)


def scan(text: str, vault=None, config: ScanConfig | None = None) -> list[Finding]:
    config = config or ScanConfig()
    findings: list[Finding] = []

    findings.extend(_scan_vault(text, vault))
    if config.patterns_enabled:
        findings.extend(_scan_rules(text, BUILTIN_RULES + config.rules))
        findings.extend(_scan_url_query(text))
    if config.entropy_enabled:
        findings.extend(_scan_entropy(
            text, config.entropy_min_length, config.entropy_threshold))

    if config.allowlist:
        allow = set(config.allowlist)
        findings = [f for f in findings if f.value not in allow]

    priority = {"vault": 0, "entropy": 2}
    findings.sort(key=lambda f: (priority.get(f.kind, 1), f.start))
    result: list[Finding] = []
    for f in findings:
        if _overlaps(f.start, f.end, ((r.start, r.end) for r in result)):
            continue
        result.append(f)
    result.sort(key=lambda f: f.start)
    return result
