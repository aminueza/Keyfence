# Setup

## Install

```bash
uv tool install keyfence
```

`uv` fetches a suitable Python on its own, so this works on a machine with
no Python installed. `pipx install keyfence` and `pip install keyfence`
(Python 3.12 or newer) work too. To upgrade: `uv tool upgrade keyfence` or
`pipx upgrade keyfence`.

## First run

```bash
keyfence demo                # what each mode does, offline
keyfence import              # register your secrets, hashes only
keyfence exec -- claude      # run a tool through the proxy
keyfence doctor              # check every piece of the setup
```

Start with `mode: audit` in `~/.keyfence/config.yaml` if you want to see
what your tools send before changing anything; `keyfence status` lists what
would have been caught. Switch to `redact` when you are comfortable.

## The CA certificate

mitmproxy creates a certificate authority in `~/.mitmproxy/` the first time
the proxy starts. Tools need to trust it so the proxy can read HTTPS traffic.

`keyfence exec` passes the certificate to the child process through
`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and
`CURL_CA_BUNDLE`, so Claude Code, Codex, Aider, curl and anything on the
Python or Node SDKs work with no further step. Only desktop apps and tools
that ignore those variables, and `--local` capture, need the certificate in
the system store:

macOS:

```bash
sudo security add-trusted-cert -d -p ssl \
  -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem
```

Linux and Windows: see the
[mitmproxy certificate docs](https://docs.mitmproxy.org/stable/concepts-certificates/).

## Commands

| command | description |
|---|---|
| `keyfence import [files] [--env] [--all]` | register secrets from files or the environment |
| `keyfence import --from op\|vault\|doppler\|aws [--path P]` | register secrets read from a secret manager CLI |
| `keyfence doctor [-p PORT]` | check mitmdump, CA, config, vault, proxy, shell, local mode, hook and audit log |
| `keyfence demo` | show what each mode does to a fake request, offline |
| `keyfence add-secret` | register one secret typed at a hidden prompt |
| `keyfence canary [file] [--name VAR]` | append a fake secret to a file (default `.env`) and register it as a canary |
| `keyfence exec [-p PORT] [--all-env] [--local [NAMES]] -- <cmd>` | run a command through the proxy |
| `keyfence run [-p PORT] [--local [NAMES]]` | run the proxy in the foreground on port 8888 |
| `keyfence install-hooks claude-code [--project] [--remove]` | stop Claude Code from reading secret files at all |
| `keyfence hook claude-code` | the hook itself; Claude Code runs it, you do not |
| `keyfence export [--since TS] [--otlp URL] [--header K=V] [--all]` | print the audit log as JSONL or send it to a collector |
| `keyfence scan 'text'`, `keyfence scan -f FILE` | test detection on text, a file or stdin |
| `keyfence status` | show config, vault size, rule count and recent detections |

`keyfence import` with no arguments reads `.env*` files in the current
directory (except `.env.example` and similar) and these files in your home
directory: `.aws/credentials`, `.netrc`, `.npmrc`, `.pypirc`,
`.git-credentials`, `.docker/config.json`. Only values that look like secrets
are registered: names containing key, token, secret, password and similar, or
values with high entropy. Passwords inside connection URLs are extracted too.
`--all` registers every value longer than 8 characters. `--env` adds values
from environment variables.

`keyfence import --from` reads a secret manager through its own CLI, which
must be installed and logged in: `op` (1Password, `--path` is the vault
name, all concealed fields of every item), `vault` (HashiCorp,
`--path secret/myapp`, KV v1 or v2), `doppler` (`--path project/config`,
otherwise the current scope) and `aws` (Secrets Manager, `--path` is the
secret id; JSON secrets contribute every value). Every value read is
registered; only hashes are stored.

`keyfence exec` starts the proxy, sets `HTTPS_PROXY`, `HTTP_PROXY` and the CA
variables for the command, snapshots environment variables with secret-like
names into a temporary vault, runs the command, and stops the proxy when it
exits. `--all-env` snapshots every environment variable value. The snapshot
is a hash file under `~/.keyfence/env/` that the proxy reads once at
startup and deletes. If the command is killed before the proxy gets that
far, the next `keyfence exec` removes anything older than a minute from
that directory. The proxy's own output
goes to `~/.keyfence/proxy.log` so it does not mix with the command's
terminal; detections are in the audit log and `keyfence status`.

To upgrade an isolated install: `uv tool upgrade keyfence` or
`pipx upgrade keyfence`.

## Capturing tools that ignore proxy variables

Some programs do not read `HTTPS_PROXY`. On macOS and Windows, `--local`
makes mitmproxy capture their traffic at the operating system level, by
process name, with no proxy variables involved:

```bash
keyfence run --local                 # every process
keyfence run --local claude,cursor   # only these process names
keyfence exec --local -- claude      # the command's own process name
```

The first time, mitmproxy installs its redirector: on macOS it copies
"Mitmproxy Redirector.app" to `/Applications` and macOS asks you to allow
the network extension in System Settings, under General, Login Items &
Extensions, Network Extensions. Until you allow it, `--local` captures
nothing and the proxy works as before. Tools captured this way do not get
the CA through environment variables, so the certificate has to be trusted
system-wide (the `security add-trusted-cert` step above). Linux is not
supported by mitmproxy's local mode.

## Blocking secret files in Claude Code

The proxy stops secrets from leaving the machine. The hook stops Claude
Code from reading them in the first place:

```bash
keyfence install-hooks claude-code            # all projects (~/.claude/settings.json)
keyfence install-hooks claude-code --project  # this project (./.claude/settings.json)
keyfence install-hooks claude-code --remove
```

The same hook ships as a Claude Code plugin, together with `/keyfence:status`
and `/keyfence:setup`. Inside Claude Code:

```
/plugin marketplace add aminueza/keyfence
/plugin install keyfence@keyfence
```

It adds a `PreToolUse` hook for Read, Edit, Write, MultiEdit, NotebookEdit
and Bash that refuses `.env` files, private keys, `.netrc`, `.npmrc`,
`.pypirc`, `.git-credentials`, `credentials*`, `secrets.*`, `*.tfvars`,
service account files, anything under `.ssh`, `.aws/credentials`,
`.docker/config.json` and `.kube/config`. `.env.example` and `*.pub` are
allowed. Bash commands that mention such a path are refused too. The
refusal message tells the model to ask you instead or to use
`keyfence import`. Existing hooks in the settings file are kept.

## Exporting the audit log

```bash
keyfence export                                  # JSONL on stdout
keyfence export --since 2026-09-08T00:00:00-0300
keyfence export --otlp http://localhost:4318 --header "Authorization=Bearer …"
```

`--otlp` sends the entries as OTLP/HTTP log records to `/v1/logs` on the
collector, with `service.name=keyfence` and attributes `keyfence.host`,
`keyfence.path`, `keyfence.mode`, `keyfence.count`, `keyfence.kinds` and,
for canaries, `keyfence.canary`. Canary hits are `ERROR`, everything else
`WARN`. A cursor in `~/.keyfence/export.cursor` makes repeated runs send
only new entries; `--all` ignores it. Run it from cron or a launchd job to
feed a team collector.

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

## Testing it with Claude Code

```bash
mkdir -p /tmp/kf-test && cd /tmp/kf-test
printf 'GITHUB_TOKEN=ghp_FAKE0000000000000000000000000000000\nDB_PASSWORD=not-a-real-password-2026\n' > .env
keyfence import
keyfence exec -- claude
```

Ask Claude to read `.env` and show the values. It sees `[REDACTED:vault]`
instead. `keyfence status` lists the detections.
