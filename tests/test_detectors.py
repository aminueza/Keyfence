import pytest

from keyfence.detectors import BUILTIN_RULES, Finding, ScanConfig, _scan_rules, scan, shannon_entropy
from keyfence.rules import load_rules
from keyfence.vault import Vault

from fakes import ADOBE_SECRET, SLACK_TOKEN, SLACK_WEBHOOK, STRIPE_KEY, TWILIO_KEY

NO_ENTROPY = ScanConfig(entropy_enabled=False)


@pytest.mark.parametrize("kind,text", [
    ("aws-access-key-id", "config: AKIAIOSFODNN7EXAMPLE region us-east-1"),
    ("openai-api-key", "OPENAI_API_KEY=sk-proj-Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"),
    ("anthropic-api-key", "usa sk-ant-api03-xYz123AbC456dEf789GhI012jKl345MnO"),
    ("github-token", "token: ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"),
    ("gitlab-token", "glpat-AbCdEfGhIj-KlMnOpQrSt"),
    ("slack-token", SLACK_TOKEN),
    ("google-api-key", "key=AIzaSyA1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU1v"),
    ("stripe-key", STRIPE_KEY),
    ("twilio-key", TWILIO_KEY),
    ("huggingface-token", "hf_AbCdEfGhIjKlMnOpQrStUvWxYz012345"),
    ("jwt", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQdQw4w9WgXcQ"),
    ("slack-webhook", SLACK_WEBHOOK),
])
def test_builtin_patterns(kind, text):
    findings = scan(text, config=NO_ENTROPY)
    assert any(f.kind == kind for f in findings), f"{kind} not detected in: {text}"


def test_pem_private_key():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA7fakefakefake\nmorefakecontent\n"
        "-----END RSA PRIVATE KEY-----"
    )
    findings = scan(f"here: {pem}", config=NO_ENTROPY)
    assert any(f.kind == "pem-private-key" for f in findings)


def test_generic_assignment():
    findings = scan(
        'DB_PASSWORD="hunter2hunter2!" and api_key: minhaChaveSuperSecreta123',
        config=NO_ENTROPY)
    assert [f.kind for f in findings].count("generic-assignment") == 2


def test_generic_assignment_bare_token():
    findings = scan("token: minhaChaveSuperSecreta123", config=NO_ENTROPY)
    assert [f.kind for f in findings] == ["generic-assignment"]


def test_generic_assignment_ignores_placeholders():
    findings = scan(
        "password=changeme\napi_key=${MY_KEY}\nsecret: <your-secret-here>\ntoken=YOUR_TOKEN_HERE",
        config=NO_ENTROPY)
    assert findings == []


def test_url_query_secret_detected():
    text = "GET https://api.example.com/v1?key=Zq8xK2mP9vL4nR7tW3yB6cF1dH5j&x=1"
    findings = scan(text, config=NO_ENTROPY)
    assert [f.kind for f in findings] == ["url-query-secret"]
    assert findings[0].value == "Zq8xK2mP9vL4nR7tW3yB6cF1dH5j"


def test_url_query_token_detected():
    text = "https://x.com/a?token=AbCdEfGhIjKlMnOpQrStUvWxYz012345"
    findings = scan(text, config=NO_ENTROPY)
    assert len(findings) == 1
    assert findings[0].value == "AbCdEfGhIjKlMnOpQrStUvWxYz012345"


def test_clean_text_has_no_findings():
    text = (
        "Hi! Can you review this Python function that sorts a list? "
        "It uses sorted() with a lambda and lives in utils/helpers.py."
    )
    assert scan(text, config=ScanConfig(rules=load_rules())) == []


def test_clean_code_has_no_findings():
    text = (
        "const secretKey = process.env.SECRET_KEY;\n"
        "export default function handler(req, res) { res.status(200).json({ ok: true }) }"
    )
    assert scan(text, config=ScanConfig(rules=load_rules())) == []


def test_entropy_math():
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == 2.0
    assert shannon_entropy("") == 0.0


def test_entropy_catches_random_secret():
    text = "my bank password is Zq8xK2mP9vL4nR7tW3yB6cF1dH5j and it stays between us"
    findings = scan(text)
    assert any(f.kind == "entropy" for f in findings)


@pytest.mark.parametrize("text", [
    "commit abc1234def5678901234abc1234def5678901234 on branch main",
    "see /usr/local/lib/python3.11/site-packages/mitmproxy/addons",
    "Pneumonoultramicroscopicsilicovolcanoconiosis is a long word",
    "https://docs.python.org/3/library/hashlib.html",
    "id=3f2504e0-4f89-11d3-9a0c-0305e82c3301",
])
def test_entropy_avoids_false_positives(text):
    findings = [f for f in scan(text) if f.kind == "entropy"]
    assert findings == [], f"entropy false positive in: {text}"


def test_entropy_token_position_is_exact():
    secret = "Zq8xK2mP9vL4nR7tW3yB6cF1dH5j"
    text = f"prefix ({secret}), suffix"
    f = next(f for f in scan(text) if f.kind == "entropy")
    assert text[f.start:f.end] == secret


def test_entropy_disabled_by_config():
    text = "value Zq8xK2mP9vL4nR7tW3yB6cF1dH5j here"
    assert scan(text, config=NO_ENTROPY) == []


def test_patterns_disabled_by_config():
    cfg = ScanConfig(patterns_enabled=False, entropy_enabled=False)
    assert scan("token: ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", config=cfg) == []


@pytest.fixture
def vault(tmp_path):
    return Vault(path=tmp_path / "vault.json")


def test_vault_detects_registered_secret(vault):
    vault.add("senha-do-postgres-producao-2026")
    text = "connect with psql -U app -W senha-do-postgres-producao-2026 -h db.internal"
    findings = scan(text, vault=vault)
    assert any(f.kind == "vault" for f in findings)


def test_vault_detects_secret_after_equals(vault):
    vault.add("tokenSemFormatoNenhum12345")
    findings = scan("DB_TOKEN=tokenSemFormatoNenhum12345", vault=vault)
    assert any(f.kind == "vault" for f in findings)


def test_vault_detects_secret_with_trailing_punctuation(vault):
    vault.add("tokenSemFormatoNenhum12345")
    findings = scan("the value is tokenSemFormatoNenhum12345.", vault=vault)
    assert [f.kind for f in findings] == ["vault"]
    assert findings[0].value == "tokenSemFormatoNenhum12345"


def test_vault_reports_every_occurrence(vault):
    vault.add("tokenSemFormatoNenhum12345")
    text = "a tokenSemFormatoNenhum12345 b tokenSemFormatoNenhum12345"
    assert len([f for f in scan(text, vault=vault) if f.kind == "vault"]) == 2


def test_vault_wins_over_pattern_on_overlap(vault):
    key = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    vault.add(key)
    findings = scan(f"token={key}", vault=vault)
    assert [f.kind for f in findings] == ["vault"]


def test_empty_vault_is_skipped(vault):
    assert scan("token=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", vault=vault, config=NO_ENTROPY)[0].kind == "github-token"


def test_allowlist_suppresses_finding():
    fake = "sk-proj-Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"
    cfg = ScanConfig(entropy_enabled=False, allowlist=[fake])
    assert scan(f"doc example: {fake}", config=cfg) == []


def test_no_overlapping_findings():
    text = "OPENAI_API_KEY=sk-proj-Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"
    findings = scan(text, config=ScanConfig(rules=load_rules()))
    spans = sorted((f.start, f.end) for f in findings)
    for (s1, e1), (s2, e2) in zip(spans, spans[1:]):
        assert e1 <= s2, "overlapping findings"


def test_masked_preview_hides_secret():
    findings = scan("token: ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")
    f = findings[0]
    assert f.value not in f.masked
    assert Finding("x", "short", 0, 5).masked == "*****"


def test_gitleaks_rules_extend_builtins():
    cfg = ScanConfig(entropy_enabled=False, rules=load_rules())
    text = f"the adobe value is {ADOBE_SECRET} here"
    assert [f.kind for f in scan(text, config=cfg)] == ["adobe-client-secret"]
    assert scan(text, config=NO_ENTROPY) == []


def test_gitleaks_rules_are_skipped_without_keywords():
    cfg = ScanConfig(entropy_enabled=False, rules=load_rules())
    assert scan("nothing to see here, plain text only", config=cfg) == []


def test_builtin_rules_take_priority_over_gitleaks():
    cfg = ScanConfig(entropy_enabled=False, rules=load_rules())
    findings = scan("OPENAI_API_KEY=sk-proj-Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv", config=cfg)
    assert [f.kind for f in findings] == ["openai-api-key"]


def test_gitleaks_entropy_threshold_filters_low_entropy_matches():
    rule = next(r for r in load_rules() if r.name == "generic-api-key")
    assert rule.min_entropy > 0
    assert _scan_rules("api_key = 'aaaaaaaaaaaaaaaaaaaaaaaa'", [rule]) == []
    assert _scan_rules("api_key = 'Zq8xK2mP9vL4nR7tW3yB6cF1dH5j'", [rule])[0].kind == "generic-api-key"


def test_builtin_rule_names_are_unique():
    names = [r.name for r in BUILTIN_RULES]
    assert len(names) == len(set(names))
