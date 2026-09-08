from __future__ import annotations

import base64
import binascii
import bisect
import math
import re
from dataclasses import dataclass, field

from .rules import DEFAULT_DISABLED, Rule, compile_regex, present_keywords


@dataclass
class Finding:
    kind: str
    value: str
    start: int
    end: int
    key: str | None = None

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
    ["']?(?P<val>[^\s"'&\\]{8,})["']?
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
             compile_regex(r"[()]"),
             compile_regex(r"^\[REDACTED"),
         )),
]


def _overlaps(start: int, end: int, spans) -> bool:
    return any(not (end <= s or start >= e) for s, e in spans)


def _scan_rules(text: str, rules: list[Rule]) -> list[Finding]:
    findings: list[Finding] = []
    claimed: list[tuple[int, int]] = []
    present = present_keywords(text.lower(), rules)
    for rule in rules:
        if not rule.applies_with(present):
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
_PATHISH = re.compile(r"^[./~]|://|^data:")
_BASE64ISH = re.compile(r"^[A-Za-z0-9+/_-]+=*$")
_DATA_URI = re.compile(r"data:[\w/+.-]+;base64,[A-Za-z0-9+/=_-]+")
_QUERY_VALUE = re.compile(r"[?&][A-Za-z0-9_.-]*(?:token|key|secret|auth|password|pass|sig)[A-Za-z0-9_.-]*=([^&\s#\\]{8,})", re.IGNORECASE)

SKIP_PREFIXES = (
    "toolu_", "srvtoolu_", "mcptoolu_", "msg_", "msgbatch_", "req_", "compl_",
    "chatcmpl-", "call_", "fc_", "rs_", "resp_", "run_", "step_", "thread_",
    "asst_", "file-", "file_", "batch_", "gen-", "ws_", "container_", "sess_",
    "evt_", "trace_", "span_", "cmpl-", "ftjob-", "vs_", "vsf_", "msgi_",
    "sha256-", "sha384-", "sha512-", "h1:",
)

ENTROPY_SKIP_KEYS = frozenset({
    "id", "tool_use_id", "tool_call_id", "call_id", "signature", "data",
    "cache_control", "encrypted_content", "previous_response_id", "message_id",
    "request_id", "session_id", "conversation_id", "user_id", "trace_id",
    "span_id", "idempotency_key", "sha256", "checksum", "hash", "etag", "digest",
    "fingerprint", "image", "audio", "thumbnail", "file_id", "container_id",
    "batch_id", "item_id", "response_id", "parent_id", "integrity",
})


def _decodes_to_json(token: str) -> bool:
    if len(token) < 8 or not _BASE64ISH.match(token):
        return False
    head = token[:4].replace("-", "+").replace("_", "/")
    try:
        decoded = base64.b64decode(head, validate=True)
    except (binascii.Error, ValueError):
        return False
    return decoded[:1] in (b"{", b"[")


_JSON_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[{}\[\]]')
_KEY_FOLLOWS = re.compile(r"\s*:")


def string_value_spans(text: str) -> list[tuple[int, int, str | None]]:
    spans: list[tuple[int, int, str | None]] = []
    stack: list[list] = []
    for m in _JSON_TOKEN.finditer(text):
        tok = m.group()
        if tok == "{":
            stack.append(["{", None])
        elif tok == "[":
            stack.append(["[", stack[-1][1] if stack else None])
        elif tok in "}]":
            if stack:
                stack.pop()
        elif stack and stack[-1][0] == "{" and _KEY_FOLLOWS.match(text, m.end()):
            stack[-1][1] = tok[1:-1]
        else:
            spans.append((m.start() + 1, m.end() - 1, stack[-1][1] if stack else None))
    return spans


def _json_spans(text: str) -> list[tuple[int, int, str | None]]:
    stripped = text.lstrip()
    if not stripped or stripped[0] not in "{[":
        return []
    return string_value_spans(text)


def _enclosing(start: int, end: int, spans: list[tuple]) -> tuple | None:
    idx = bisect.bisect_right(spans, start, key=lambda sp: sp[0]) - 1
    if idx >= 0 and end <= spans[idx][1]:
        return spans[idx]
    return None


def _excluded_spans(text: str, json_spans: list[tuple[int, int, str | None]]) -> list[list[tuple]]:
    uri_spans = [m.span() for m in _DATA_URI.finditer(text)]
    key_spans = [(s, e) for s, e, key in json_spans if key in ENTROPY_SKIP_KEYS]
    return [uri_spans, key_spans]


def _inside(start: int, end: int, span_lists: list[list[tuple]]) -> bool:
    return any(_enclosing(start, end, spans) is not None for spans in span_lists)


def _key_at(start: int, end: int, json_spans: list[tuple[int, int, str | None]]) -> str | None:
    span = _enclosing(start, end, json_spans)
    return span[2] if span else None


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _scan_entropy(text: str, min_length: int = 24, threshold: float = 4.5,
                  max_length: int = 512, json_spans=None) -> list[Finding]:
    findings: list[Finding] = []
    excluded = _excluded_spans(text, _json_spans(text) if json_spans is None else json_spans)
    pos = 0
    for raw in _TOKEN_SPLIT.split(text):
        idx = text.find(raw, pos)
        if idx == -1:
            idx = text.find(raw)
        pos = idx + len(raw) if idx >= 0 else pos

        token = raw.strip(".,:=!?")
        if len(token) < min_length or len(token) > max_length or not token.isascii():
            continue
        if _WORDISH.match(token) or _PATHISH.search(token):
            continue
        if _HEXISH.match(token) and len(token) in (32, 40, 64):
            continue
        if token.startswith(SKIP_PREFIXES) or _decodes_to_json(token):
            continue
        if "(" in token or ")" in token or "=" in token.rstrip("="):
            continue
        has_upper = any(c.isupper() for c in token)
        has_lower = any(c.islower() for c in token)
        has_digit = any(c.isdigit() for c in token)
        if sum([has_upper, has_lower, has_digit]) < 2:
            continue
        if shannon_entropy(token) < threshold:
            continue
        start = (idx if idx >= 0 else 0) + raw.find(token)
        end = start + len(token)
        if _inside(start, end, excluded):
            continue
        findings.append(Finding(kind="entropy", value=token, start=start, end=end))
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
    for m in re.finditer(r"[:=]\s*([^\s\"'\\]{%d,})" % vault.min_length, text):
        candidates.add(m.group(1))

    for cand in candidates:
        if vault.contains(cand):
            kind = "canary" if vault.canary_label(cand) is not None else "vault"
            for m in re.finditer(re.escape(cand), text):
                span = (m.start(), m.end())
                if span not in seen_spans:
                    seen_spans.add(span)
                    findings.append(Finding(kind=kind, value=cand, start=span[0], end=span[1]))
    return findings


@dataclass
class ScanConfig:
    patterns_enabled: bool = True
    entropy_enabled: bool = True
    entropy_min_length: int = 24
    entropy_threshold: float = 4.5
    entropy_max_length: int = 512
    allowlist: list[str] = field(default_factory=list)
    gitleaks: bool = True
    gitleaks_rules: str | None = None
    gitleaks_disabled: list[str] = field(default_factory=lambda: list(DEFAULT_DISABLED))
    rules: list[Rule] = field(default_factory=list)


def scan(text: str, vault=None, config: ScanConfig | None = None) -> list[Finding]:
    config = config or ScanConfig()
    findings: list[Finding] = []
    json_spans = _json_spans(text)

    findings.extend(_scan_vault(text, vault))
    if config.patterns_enabled:
        findings.extend(_scan_rules(text, BUILTIN_RULES + config.rules))
        findings.extend(_scan_url_query(text))
    if config.entropy_enabled:
        findings.extend(_scan_entropy(
            text, config.entropy_min_length, config.entropy_threshold,
            config.entropy_max_length, json_spans))

    if config.allowlist:
        allow = set(config.allowlist)
        findings = [f for f in findings if f.value not in allow]

    priority = {"canary": 0, "vault": 0, "entropy": 2}
    findings.sort(key=lambda f: (priority.get(f.kind, 1), f.start))
    result: list[Finding] = []
    for f in findings:
        if _overlaps(f.start, f.end, ((r.start, r.end) for r in result)):
            continue
        if json_spans:
            f.key = _key_at(f.start, f.end, json_spans)
        result.append(f)
    result.sort(key=lambda f: f.start)
    return result
