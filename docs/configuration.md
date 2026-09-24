# Configuration

Copy `config.example.yaml` to `~/.keyfence/config.yaml`. Every key is
optional.

| key | default | description |
|---|---|---|
| `mode` | `redact` | `audit` (log only, change nothing), `redact`, `placeholder` or `block` |
| `hosts` | 20 AI provider hosts | hosts to monitor; wildcards allowed |
| `extra_hosts` | `[]` | hosts to add to the default list |
| `intercept_all_hosts` | `false` | scan every host, not only AI providers |
| `notice` | `true` | add the system prompt notice when a request was changed |
| `scan.patterns` | `true` | built-in pattern rules |
| `scan.gitleaks` | `true` | bundled gitleaks rules |
| `scan.gitleaks_rules` | bundled file | path to your own gitleaks-compatible TOML |
| `scan.gitleaks_disabled` | `[generic-api-key]` | rule ids to skip |
| `scan.entropy` | `true` | entropy check |
| `scan.entropy_min_length` | `24` | minimum token length for the entropy check |
| `scan.entropy_max_length` | `512` | tokens longer than this are treated as encoded data |
| `scan.entropy_threshold` | `4.5` | bits per character |
| `scan.allowlist` | `[]` | exact values never treated as secrets |
| `ignore_keys` | `[]` | variable names or JSON keys whose values are never registered or reported; case-insensitive, `*` and `?` allowed |
| `ignore_values` | `[]` | values never registered or reported; compared by salted hash, see below |
| `audit_log` | `~/.keyfence/audit.log` | where detections are logged |

Default hosts: `api.openai.com`, `api.anthropic.com`,
`generativelanguage.googleapis.com`, `api.mistral.ai`, `api.groq.com`,
`api.cohere.com`, `api.together.xyz`, `api.deepseek.com`, `api.x.ai`,
`openrouter.ai`, `api.perplexity.ai`, `api.fireworks.ai`,
`bedrock-runtime.*.amazonaws.com`, `*.openai.azure.com`,
`*.services.ai.azure.com`, `*.cognitiveservices.azure.com`,
`models.inference.ai.azure.com`, `api.githubcopilot.com`,
`aiplatform.googleapis.com`, `*-aiplatform.googleapis.com`. Subdomains
match. Editors with their own backend (Cursor, Windsurf) are not on the
list: add their hosts with `extra_hosts` if you verify they carry JSON
request bodies, and tell us.

`audit` mode records findings in the audit log and on the console exactly
as the other modes do, and sends the request untouched, without the system
prompt notice. It is the way to see what your tools send before you turn
on redaction.

## Ignore lists

`keyfence import` registers a value when its name looks like a secret or
when the value has high entropy, and a hostname such as
`DB_HOST=db.internal.example.com` qualifies on entropy alone. Once it is in
the vault every request that mentions it is a finding, and in `block` mode a
403. The two ignore lists say "this one is not a secret":

```yaml
ignore_keys:
  - DB_HOST
  - SERVICE_NAME
  - "*_URL"
ignore_values:
  - db.internal.example.com
```

`ignore_keys` matches the variable name in `.env` files, credential files
and the environment, the key in JSON files and secret manager output, and,
at detection time, the JSON key a finding sits under (the `key` field of the
audit entry). Matching is case-insensitive and exact; `*` and `?` match as
in shell globs, so `*_HOST` covers a family of names. A pair whose key is
ignored is not registered, even with `--all`, and a finding under an
ignored key is dropped. Keys are only known when the request body is JSON;
a value found in plain text has no key and is not affected by
`ignore_keys`.

`ignore_values` lists the values themselves. They are never registered and
never reported, whichever check found them: vault, patterns, gitleaks
rules, URL query strings or entropy. The value is written in clear in
`config.yaml`, which is your file, but keyfence hashes each entry with the
vault salt as soon as the file is read and compares hashes from then on:
the value is not held in memory beyond the loaded config, and it never
reaches `vault.json`, the audit log or the console. Because the hash uses
the vault salt, the same entry keeps working when the vault is reloaded.
Matching is exact, like the vault: `db.internal.example.com` does not
cover `postgres://app:pw@db.internal.example.com`, so a connection string
carrying a password is still caught.

Both lists apply to `keyfence import` (files, `--env`, `--from`), to the
environment snapshot `keyfence exec` takes, to `keyfence scan` and to the
proxy. A running proxy picks up changes to either list without a restart,
like every other option. `keyfence status` shows how many entries each list
holds, `keyfence scan` says how many findings it dropped, and an audit
entry carries `suppressed: n` when a request had other findings besides
the ignored ones. A request whose only findings were ignored is clean and
is not logged. `scan.allowlist` is the older, narrower form of
`ignore_values`: exact values compared in clear and applied at detection
time only.

## Environment variables

| variable | description |
|---|---|
| `KEYFENCE_HOME` | state directory, default `~/.keyfence` |
| `KEYFENCE_CONFIG` | config file path, default `$KEYFENCE_HOME/config.yaml` |
| `KEYFENCE_ENV_VAULT` | set by `keyfence exec` for the proxy; path of the temporary environment vault |
| `MITMPROXY_CONFDIR` | where mitmproxy keeps its CA, default `~/.mitmproxy` |

## The system prompt notice

When keyfence changes a request it appends a short note to the system
prompt: the tokens are expected and configured by the user, they are not
tampering, and the model should not warn the user or suggest rotating
credentials. The rest depends on the mode. In `redact` the note says the
`[REDACTED:…]` tokens are final and must not be written into code or
commands as if they were the value. In `placeholder` it says to write
`<<SECRET_id>>` tokens exactly as shown so they can be restored. Without
the note, models tend to treat the tokens as evidence of compromise.

Supported shapes: Anthropic `system` as a string or as a list of blocks (the
note is a new block at the end, so cached prefixes stay valid), OpenAI chat
(a trailing system message) and Responses `instructions`, Gemini
`systemInstruction`. Other bodies are left alone. Clean requests are never
touched. Set `notice: false` to disable.

## Other behaviour

- If the detector raises an exception, the request gets a 403. A bug in
  keyfence cannot let a secret through.
- Secret values are never written to disk. The vault stores hashes, the
  audit log stores masked previews, and the `exec` environment snapshot is a
  temporary hash file removed on exit.
- Placeholders are deterministic. The id in `<<SECRET_id>>` is derived from
  an HMAC of the value with the vault salt, so the same secret gets the same
  placeholder in every request and every session on that machine. The
  model sees a consistent transcript, and prompt caches built on earlier
  turns stay valid when a new secret shows up. On a collision the id is
  lengthened.
- Responses that contain no placeholders are streamed without buffering.
- When a request contains placeholders, keyfence sets
  `Accept-Encoding: identity` so the response can be rewritten as it
  streams. Placeholders split across SSE events are still restored.
- The vault file and the config file are reloaded when they change, so
  `import`, `add-secret`, `canary` and edits to `config.yaml` take effect
  on a running proxy. A config file that fails to parse is logged and the
  previous configuration stays in force. A vault file that fails to parse
  stops the proxy at startup with a message, and makes a running proxy
  fail closed until the file is fixed or moved aside.
- The vault is written atomically and updates take a file lock
  (`vault.json.lock` next to it, `flock` on POSIX and `msvcrt.locking` on
  Windows), so the running proxy never reads a half-written file and two
  commands registering secrets at the same time both land. A command that
  finds the lock taken says so on stderr and waits up to 30 seconds, then
  gives up with instructions. An emptied or removed `config.yaml` is
  ignored by a running proxy; only a file that parses replaces the
  configuration in force.
