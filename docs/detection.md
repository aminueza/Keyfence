# Detection

Three checks run on every request body sent to a monitored host, and on
every text WebSocket frame the client sends to one.

## 1. Vault

Every token in the request is hashed with HMAC-SHA256 and a per-vault salt,
then compared with the hashes you registered through `keyfence import`,
`keyfence add-secret` or the `keyfence exec` environment snapshot. This
catches any exact value, whatever its format: database passwords, internal
tokens, anything.

The vault file (`~/.keyfence/vault.json`) holds only the salt and the
hashes. Values shorter than 8 characters are refused because they would
match ordinary words.

`keyfence import` keeps a value when its name looks like a secret or when
the value has high entropy, so a hostname or an id can end up in the vault
and block every request that mentions it. List the name under
`ignore_keys` or the value under `ignore_values` in `config.yaml` and it is
neither registered nor reported; see
[configuration](configuration.md#ignore-lists).

### Canaries

`keyfence canary .env` appends a line such as `INTERNAL_API_TOKEN=<random>`
to the file and registers the value in the vault as a canary, together with
the file's path. The value is fake and useless, so it can only reach a
request if a tool read that file and sent its contents. When that happens
the finding has kind `canary`, the audit entry carries the file path under
`label`, and the proxy logs `CANARY tripped` with that path: on the
terminal for `keyfence run`, in `~/.keyfence/proxy.log` for
`keyfence exec`. The value is redacted or blocked like any other secret.

Use it to check what your agents actually read: plant one in each file that
should never reach a model and watch the audit log.

## 2. Patterns

Built-in rules cover OpenAI, Anthropic, AWS, GitHub, GitLab, Slack, Google,
Stripe, Twilio, SendGrid, npm, PyPI, Hugging Face, JWTs, PEM private keys,
`password=` style assignments and secrets in URL query strings.

On top of that, the bundled [gitleaks](https://github.com/gitleaks/gitleaks)
ruleset adds about 220 formats. Rules run only when one of their keywords
appears in the text. Rules with an entropy threshold apply it to the matched
secret. Rule-level allowlists from the gitleaks file are honoured. Rules with
a single capture group report that group as the secret, as gitleaks does.

In a JSON body, pattern rules see each escape that stands for a
character (`\n`, `\t`, `\r`, `\b`, `\f`, `\uXXXX`) as spaces of the same
length, so a rule with a word boundary still matches a secret that follows
one, and offsets stay those of the body as sent. `\"`, `\\` and `\/` are
left as they are. The reported value is the text as sent, escapes included.

The built-in assignment rule ignores placeholder values such as `changeme`
or `${VAR}`, values that contain parentheses, and values that are already
a redaction token, so a model repeating `TOKEN=[REDACTED]` is not flagged
again.

`generic-api-key` is disabled by default because it matches ordinary prose
and code. `scan.gitleaks_disabled` controls the list, and
`scan.gitleaks_rules` points to your own gitleaks-compatible TOML.

## 3. Entropy

Strings of 24 to 512 characters with Shannon entropy of at least 4.5 bits
per character and at least two character classes (upper, lower, digit) are
flagged. This catches random secrets with no known format.

Excluded from the entropy check:

- words, file paths, URLs, `data:` URIs and anything with non-ASCII
  characters
- hex strings of 32, 40 or 64 characters (hashes and checksums)
- base64 that decodes to JSON (telemetry and event payloads)
- API object ids such as `toolu_…`, `msg_…`, `call_…`, `chatcmpl-…`
- when the body is JSON, values of keys that hold ids, hashes, signatures
  or binary data: `id`, `tool_use_id`, `signature`, `data`,
  `cache_control`, `sha256` and similar

A random-looking value that is not a secret, or a JSON key of your own
that holds such values, can be excluded with `ignore_values` and
`ignore_keys` in `config.yaml` instead of lowering the threshold for
everything.

## Merging

Findings from the three checks are merged. Values listed in
`scan.allowlist`, values listed in `ignore_values` and findings under a
JSON key listed in `ignore_keys` are dropped first, so an ignored value
can never shadow a longer secret it overlaps. Then, when two findings
overlap, the vault wins over patterns and patterns win over entropy.

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
findings are listed per request; `count` is the real total. When the ignore
lists dropped findings from a request that still had others, the entry
carries `suppressed` with how many; a request whose only findings were
ignored is not logged. The log never contains a secret, and never an
ignored value either.

`keyfence scan` prints the same information for a text, file or stdin, and
`keyfence status` shows the last five requests grouped by kind.
