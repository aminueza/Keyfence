# Detection

Three checks run on every request body sent to a monitored host.

## 1. Vault

Every token in the request is hashed with HMAC-SHA256 and a per-vault salt,
then compared with the hashes you registered through `keyfence import`,
`keyfence add-secret` or the `keyfence exec` environment snapshot. This
catches any exact value, whatever its format: database passwords, internal
tokens, anything.

The vault file (`~/.keyfence/vault.json`) holds only the salt and the
hashes. Values shorter than 8 characters are refused because they would
match ordinary words.

## 2. Patterns

Built-in rules cover OpenAI, Anthropic, AWS, GitHub, GitLab, Slack, Google,
Stripe, Twilio, SendGrid, npm, PyPI, Hugging Face, JWTs, PEM private keys,
`password=` style assignments and secrets in URL query strings.

On top of that, the bundled [gitleaks](https://github.com/gitleaks/gitleaks)
ruleset adds about 220 formats. Rules run only when one of their keywords
appears in the text. Rules with an entropy threshold apply it to the matched
secret. Rule-level allowlists from the gitleaks file are honoured. Rules with
a single capture group report that group as the secret, as gitleaks does.

`generic-api-key` is disabled by default because it matches ordinary prose
and code. `scan.gitleaks_disabled` controls the list, and
`scan.gitleaks_rules` points to your own gitleaks-compatible TOML.

## 3. Entropy

Strings of 24 to 512 characters with Shannon entropy of at least 4.5 bits
per character and at least two character classes (upper, lower, digit) are
flagged. This catches random secrets with no known format.

Excluded from the entropy check:

- words, file paths, URLs and `data:` URIs
- hex strings of 32, 40 or 64 characters (hashes and checksums)
- base64 that decodes to JSON (telemetry and event payloads)
- API object ids such as `toolu_…`, `msg_…`, `call_…`, `chatcmpl-…`
- when the body is JSON, values of keys that hold ids, hashes, signatures
  or binary data: `id`, `tool_use_id`, `signature`, `data`,
  `cache_control`, `sha256` and similar

## Merging

Findings from the three checks are merged. When two overlap, the vault wins
over patterns and patterns win over entropy. Values listed in
`scan.allowlist` are dropped.

## Audit log

Every request with findings appends one JSON line to
`~/.keyfence/audit.log`:

```json
{"ts": "2026-09-08T15:46:20-0300", "host": "api.anthropic.com",
 "path": "/v1/messages", "mode": "redact", "count": 2,
 "findings": [{"kind": "vault", "preview": "ghp_…6789 (40 chars)", "key": "content"}]}
```

`preview` is the first and last four characters. `key` is the JSON key the
value was found under, which is how you trace a false positive. At most 50
findings are listed per request; `count` is the real total. The log never
contains a secret.

`keyfence scan` prints the same information for a text, file or stdin, and
`keyfence status` shows the last five requests grouped by kind.
