# Configuration

Copy `config.example.yaml` to `~/.keyfence/config.yaml`. Every key is
optional.

| key | default | description |
|---|---|---|
| `mode` | `redact` | `block`, `redact` or `placeholder` |
| `hosts` | 14 AI provider hosts | hosts to monitor; wildcards allowed |
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
| `audit_log` | `~/.keyfence/audit.log` | where detections are logged |

Default hosts: `api.openai.com`, `api.anthropic.com`,
`generativelanguage.googleapis.com`, `api.mistral.ai`, `api.groq.com`,
`api.cohere.com`, `api.together.xyz`, `api.deepseek.com`, `api.x.ai`,
`openrouter.ai`, `api.perplexity.ai`, `api.fireworks.ai`,
`bedrock-runtime.*.amazonaws.com`, `*.openai.azure.com`. Subdomains match.

## Environment variables

| variable | description |
|---|---|
| `KEYFENCE_HOME` | state directory, default `~/.keyfence` |
| `KEYFENCE_CONFIG` | config file path, default `$KEYFENCE_HOME/config.yaml` |
| `KEYFENCE_ENV_VAULT` | set by `keyfence exec` for the proxy; path of the temporary environment vault |
| `MITMPROXY_CONFDIR` | where mitmproxy keeps its CA, default `~/.mitmproxy` |

## The system prompt notice

When keyfence changes a request it appends a short note to the system
prompt: the `[REDACTED:…]` and `<<SECRET_id>>` tokens are expected and configured by the user, they
are not tampering, the model should not warn the user or suggest rotating
credentials, and placeholders must be written exactly as shown so they can
be restored. Without the note, models tend to treat the tokens as evidence
of compromise.

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
  (`vault.json.lock` next to it), so the running proxy never reads a
  half-written file and two commands registering secrets at the same time
  both land. An emptied or removed `config.yaml` is ignored by a running
  proxy; only a file that parses replaces the configuration in force.
