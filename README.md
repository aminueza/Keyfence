# keyfence

**A local proxy that keeps your API keys, passwords and secrets out of LLM
requests. Works with Claude Code, Cursor, Codex, Aider, curl, anything.**

Coding agents read `.env` files, credential stores and logs, and happily ship
whatever they find to the model. keyfence sits between your tools and the
provider and scans every request *before it leaves your machine*. Secrets get
blocked, redacted, or swapped for placeholders that are restored in the
response, so the model never sees them but your workflow keeps working.

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ Claude Code │     │     keyfence      │     │ api.anthropic…  │
│ Cursor, CLI ├────▶│   (local proxy)   ├────▶│ api.openai…     │
│ scripts ... │     │  scans and cleans │     │ ...             │
└─────────────┘     └──────────────────┘     └─────────────────┘
                    secrets never get past here
```

Interception happens at the network layer, so there is nothing to plug into
your editor or agent.

## Quick start

```bash
pip install keyfence

# 1. Teach keyfence YOUR secrets. Only salted hashes are stored, never values.
keyfence import              # reads .env*, ~/.aws/credentials, ~/.netrc, ~/.npmrc, ...

# 2. Run your tool through the fence. Proxy and CA are wired in automatically,
#    and every secret-looking environment variable is protected for the session.
keyfence exec -- claude
```

The first run creates a local CA certificate in `~/.mitmproxy/`. Trust it once
so the proxy can inspect HTTPS (macOS shown; see the mitmproxy docs for other
systems):

```bash
sudo security add-trusted-cert -d -p ssl \
  -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem
```

## What makes it different

- **It knows *your* secrets.** `keyfence import` and `keyfence exec` register
  the actual values from your `.env` files, credential stores and environment
  as HMAC-SHA256 hashes. A database password with no recognisable format is
  caught just as reliably as an AWS key.
- **Fail-closed.** If the detector ever crashes, the request is refused with a
  403. A bug in keyfence can never turn into a leak.
- **Placeholders survive streaming.** In `placeholder` mode the model sees
  `<<SECRET_1>>`, and the real value is put back in the response token by
  token, even when the placeholder is split across SSE events.
- **220+ formats out of the box.** Built-in rules for the major providers plus
  the bundled [gitleaks](https://github.com/gitleaks/gitleaks) ruleset. Bring
  your own gitleaks-compatible TOML if you want.
- **Small and auditable.** About a thousand lines of Python on top of
  mitmproxy. No models to download, no cloud, no telemetry.

## Three layers of detection

1. **Vault**: hashes of the secrets you registered. Catches any exact value,
   whatever its shape.
2. **Known formats**: OpenAI, Anthropic, AWS, GitHub, GitLab, Slack, Google,
   Stripe, Twilio, SendGrid, npm, PyPI, Hugging Face, JWTs, PEM private keys,
   generic `password=` / `api_key:` assignments, secrets in URL query strings,
   and the full gitleaks ruleset.
3. **Entropy**: long high-entropy strings that look like secrets, with filters
   for commit hashes, paths, URLs and UUIDs.

## Three modes (`mode` in the config)

| mode | what happens |
|---|---|
| `block` | request is refused with 403; nothing leaves the machine |
| `redact` *(default)* | secret becomes `[REDACTED:kind]` and the request goes through |
| `placeholder` | secret becomes `<<SECRET_n>>` on the way out and is restored in the response, so code the model writes still works |

## Commands

| command | purpose |
|---|---|
| `keyfence import [files] [--env] [--all]` | register secrets from `.env` files, credential stores or the environment (hashes only) |
| `keyfence add-secret` | register one secret interactively |
| `keyfence exec [-p PORT] [--all-env] -- <cmd>` | start the proxy, run `<cmd>` through it, protect the environment, stop the proxy |
| `keyfence run [-p PORT]` | start the proxy in the foreground for tools you configure manually |
| `keyfence scan 'text'` / `-f file` / stdin | test detection without a proxy |
| `keyfence status` | configuration, vault size, rule count and recent detections |

### Manual proxy setup (instead of `exec`)

```bash
keyfence run                      # port 8888 by default

export HTTPS_PROXY=http://127.0.0.1:8888
export HTTP_PROXY=http://127.0.0.1:8888
export NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem   # Node tools (Claude Code)
export SSL_CERT_FILE=~/.mitmproxy/mitmproxy-ca-cert.pem         # Python tools
export REQUESTS_CA_BUNDLE=~/.mitmproxy/mitmproxy-ca-cert.pem
```

For GUI apps, set the system proxy to `127.0.0.1:8888` in
Settings → Network → Wi-Fi → Details → Proxies.

## Docker

```bash
docker compose up -d                              # proxy on 127.0.0.1:8888
docker compose run --rm keyfence import /data/.env
docker compose run --rm keyfence status
docker compose logs -f
```

State lives in `./data/`: `vault.json` (hashes), `config.yaml`, `audit.log`
and the CA certificate under `certs/`. Trust `./data/certs/mitmproxy-ca-cert.pem`
the same way as above. The vault is reloaded automatically, so `import` and
`add-secret` take effect without a restart.

## Configuration

Copy `config.example.yaml` to `~/.keyfence/config.yaml`. You can change the
mode, add hosts, tune entropy, disable the gitleaks rules or point to your own
ruleset, and allowlist exact values. The major AI providers are monitored by
default; `intercept_all_hosts: true` scans everything.

Environment variables: `KEYFENCE_HOME` (state directory, default
`~/.keyfence`) and `KEYFENCE_CONFIG` (config file path).

Every detection is appended to `~/.keyfence/audit.log` with the **kind** and a
masked preview (`ghp_…6789`), never the secret itself.

## Guarantees

- Secret values are never written to disk by keyfence: the vault holds salted
  HMAC-SHA256 hashes, the audit log holds masked previews, the `exec`
  environment snapshot is a temporary hash file deleted on exit.
- A detector failure blocks the request instead of letting it through.
- Responses that need no restoration are streamed untouched.

## Limitations (please read)

The target is **accidental leakage**, which is the overwhelming majority of
real incidents. Out of scope:

- **Certificate pinning**: apps that pin the server certificate refuse the
  proxy. They fail rather than leak, but they will not work through it.
- **Obfuscation**: a secret in base64, split in pieces or encrypted passes.
  No scanner solves this; a deliberately malicious app is outside the threat
  model.
- **Apps that ignore proxies**: anything that does not honour `HTTPS_PROXY`
  or the system proxy bypasses keyfence. Transparent capture by process name
  (mitmproxy local mode) is on the roadmap.
- **Local models** (Ollama etc.): traffic that never leaves the machine never
  passes the proxy, and never leaks either.
- **Streaming with a partial placeholder at the very end of a message**: the
  last few characters are passed through unchanged rather than guessed.

## Defense in depth (recommended alongside)

- Deny reads at the source: in Claude Code, permission rules or hooks that
  refuse `Read` on `.env`, `*.pem`, `**/credentials*`.
- Keep no plaintext on disk: Keychain, 1Password or a vault, injected as
  environment variables only into the process that needs them (and then
  `keyfence exec` protects them).
- `.gitignore` plus git hooks (gitleaks, trufflehog) for the git path.

## Development

```bash
pip install -e '.[dev]'
pytest                            # unit tests, coverage gate at 90%
bash tests/integration_test.sh    # end-to-end against a real mitmproxy
```

## Credits and license

Bundled detection rules come from [gitleaks](https://github.com/gitleaks/gitleaks)
(MIT, see `keyfence/rules/GITLEAKS-LICENSE`). Interception is powered by
[mitmproxy](https://mitmproxy.org/). keyfence itself is MIT licensed.
