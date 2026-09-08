# keyfence

[![CI](https://github.com/aminueza/keyfence/actions/workflows/ci.yml/badge.svg)](https://github.com/aminueza/keyfence/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)

keyfence is a local HTTP proxy that stops secrets from reaching LLM APIs.

It checks every request sent to an AI provider before the request leaves
your machine. If the request contains an API key, a password or another
secret, keyfence blocks the request, redacts the secret, or replaces it with
a placeholder and puts the real value back in the response.

It works at the network level. Claude Code, Cursor, Codex, Aider, curl and
your own scripts all go through the same proxy. No plugin is needed.

![How keyfence sits between your tools and the provider](https://raw.githubusercontent.com/aminueza/keyfence/main/docs/keyfence-flow.png)

## Install

```bash
pip install keyfence
```

Requires Python 3.12 or newer. mitmproxy is installed as a dependency.

## Usage

```bash
keyfence import              # register your secrets (hashes only)
keyfence exec -- claude      # run a tool through the proxy
```

`keyfence import` reads `.env` files in the current directory and these
files in your home directory: `.aws/credentials`, `.netrc`, `.npmrc`,
`.pypirc`, `.git-credentials`, `.docker/config.json`. It stores a salted
HMAC-SHA256 hash of each value. It never stores the values themselves.

`keyfence exec` starts the proxy, sets the proxy and CA environment
variables for the command, and runs it. Values of environment variables
with names like `*_KEY`, `*_TOKEN`, `*_SECRET` or `*_PASSWORD` are also
protected for the session. The proxy stops when the command exits.

### Trust the CA certificate

mitmproxy creates a certificate authority in `~/.mitmproxy/` on first run.
Your tools need to trust it so the proxy can read HTTPS traffic. On macOS:

```bash
sudo security add-trusted-cert -d -p ssl \
  -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem
```

For Linux and Windows see the
[mitmproxy certificate docs](https://docs.mitmproxy.org/stable/concepts-certificates/).

## How detection works

Three checks run on every request body sent to a monitored host:

1. **Vault.** Every token in the request is hashed and compared with the
   hashes you registered. This catches any exact value, whatever its
   format, including database passwords and internal tokens.
2. **Patterns.** Built-in rules for OpenAI, Anthropic, AWS, GitHub, GitLab,
   Slack, Google, Stripe, Twilio, SendGrid, npm, PyPI, Hugging Face, JWTs,
   PEM private keys, `password=` style assignments and secrets in URL query
   strings, plus 221 rules from the
   [gitleaks](https://github.com/gitleaks/gitleaks) ruleset.
3. **Entropy.** Long strings with high entropy and mixed character classes.
   Commit hashes, file paths, URLs, UUIDs, base64-encoded JSON, API object
   ids such as `toolu_…` or `msg_…`, and JSON fields that hold ids, hashes,
   signatures or binary data are excluded.

Findings from the three checks are merged. When two overlap, the vault wins
over patterns and patterns win over entropy.

## Modes

Set `mode` in the config file.

| mode | behaviour |
|---|---|
| `block` | the request gets a 403 response and is not sent |
| `redact` (default) | the secret is replaced with `[REDACTED:<kind>]` and the request is sent |
| `placeholder` | the secret is replaced with `<<SECRET_n>>`, the request is sent, and the real value is restored in the response |

`placeholder` mode keeps generated code working: the model writes
`<<SECRET_1>>` and your tool receives the real value. Restoration works for
streamed responses too, even when a placeholder is split across SSE events.

## Commands

| command | description |
|---|---|
| `keyfence import [files] [--env] [--all]` | register secrets from files or the environment |
| `keyfence add-secret` | register one secret typed at a hidden prompt |
| `keyfence exec [-p PORT] [--all-env] -- <cmd>` | run a command through the proxy |
| `keyfence run [-p PORT]` | run the proxy in the foreground on port 8888 |
| `keyfence scan 'text'`, `keyfence scan -f FILE` | test detection on text, a file or stdin |
| `keyfence status` | show config, vault size, rule count and recent detections |

`--all` and `--all-env` register every value longer than 8 characters, not
only the ones that look like secrets.

## Manual proxy setup

If you do not use `keyfence exec`, run the proxy and point your tools at it:

```bash
keyfence run

export HTTPS_PROXY=http://127.0.0.1:8888
export HTTP_PROXY=http://127.0.0.1:8888
export NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem   # Node tools, e.g. Claude Code
export SSL_CERT_FILE=~/.mitmproxy/mitmproxy-ca-cert.pem         # Python tools
export REQUESTS_CA_BUNDLE=~/.mitmproxy/mitmproxy-ca-cert.pem
```

For desktop apps, set the system proxy to `127.0.0.1:8888`.

## Docker

```bash
docker compose up -d
docker compose run --rm keyfence import /data/.env
docker compose run --rm keyfence status
docker compose logs -f
```

The container writes its state to `./data/`: `vault.json`, `config.yaml`,
`audit.log` and the CA certificate in `certs/`. Trust
`./data/certs/mitmproxy-ca-cert.pem` as shown above. The proxy reloads the
vault when the file changes, so `import` and `add-secret` do not need a
restart.

## Configuration

Copy `config.example.yaml` to `~/.keyfence/config.yaml`. Options:

| key | default | description |
|---|---|---|
| `mode` | `redact` | `block`, `redact` or `placeholder` |
| `hosts` | 14 AI provider hosts | hosts to monitor; wildcards allowed |
| `extra_hosts` | `[]` | hosts to add to the default list |
| `intercept_all_hosts` | `false` | scan every host, not only AI providers |
| `scan.patterns` | `true` | built-in pattern rules |
| `scan.gitleaks` | `true` | bundled gitleaks rules |
| `scan.gitleaks_rules` | bundled file | path to your own gitleaks-compatible TOML |
| `scan.entropy` | `true` | entropy check |
| `scan.entropy_min_length` | `24` | minimum token length for the entropy check |
| `scan.entropy_threshold` | `4.5` | bits per character |
| `scan.entropy_max_length` | `512` | tokens longer than this are treated as encoded data |
| `scan.allowlist` | `[]` | exact values to ignore |
| `audit_log` | `~/.keyfence/audit.log` | where detections are logged |

Environment variables: `KEYFENCE_HOME` sets the state directory (default
`~/.keyfence`), `KEYFENCE_CONFIG` sets the config file path.

The audit log has one JSON line per detection with the host, path, mode,
kind of secret and a masked preview such as `ghp_…6789`. It never contains
the secret.

## Behaviour worth knowing

- If the detector raises an exception, the request gets a 403. A bug in
  keyfence cannot let a secret through.
- Secret values are never written to disk. The vault stores hashes, the
  audit log stores masked previews, and the `exec` environment snapshot is a
  temporary hash file removed on exit.
- Responses that contain no placeholders are streamed without buffering.
- When a request contains placeholders, keyfence sets
  `Accept-Encoding: identity` so the response can be rewritten as it
  streams.

## Limitations

- Apps that pin the server certificate refuse the proxy. They fail instead
  of leaking, but they do not work through keyfence.
- Secrets that are base64 encoded, split into pieces or encrypted are not
  detected. A program that hides secrets on purpose is outside the threat
  model.
- Programs that ignore `HTTPS_PROXY` and the system proxy bypass keyfence.
  Transparent capture by process name is planned.
- Local models such as Ollama do not go through the proxy. Their traffic
  also does not leave the machine.
- If a streamed response ends in the middle of a placeholder, the last
  characters are passed through as they are.

## Other measures

keyfence is the last line. It works best together with:

- Permission rules or hooks in your agent that deny reading `.env`,
  `*.pem` and `**/credentials*`.
- Secrets kept in a password manager or vault and passed as environment
  variables only to the process that needs them.
- Git hooks such as gitleaks or trufflehog for the commit path.

## Development

```bash
pip install -e '.[dev]'
pytest                            # unit tests, coverage must stay above 90%
bash tests/integration_test.sh    # end-to-end test against a real mitmproxy
```

## License

MIT. The bundled rules come from gitleaks, also MIT; see
`keyfence/rules/GITLEAKS-LICENSE`.
