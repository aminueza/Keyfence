# Setup

## Install

```bash
pip install keyfence
```

Isolated installs work too and keep mitmproxy out of your global
site-packages:

```bash
uv tool install keyfence
pipx install keyfence
```

## Trust the CA certificate

mitmproxy creates a certificate authority in `~/.mitmproxy/` the first time
the proxy starts. Tools need to trust it so the proxy can read HTTPS traffic.

`keyfence exec` passes the certificate to the child process through
`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and
`CURL_CA_BUNDLE`, so Node, Python and curl based tools work without a
system-wide trust step. Desktop apps and tools that ignore those variables
need the certificate in the system store:

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
| `keyfence add-secret` | register one secret typed at a hidden prompt |
| `keyfence canary [file] [--name VAR]` | append a fake secret to a file (default `.env`) and register it as a canary |
| `keyfence exec [-p PORT] [--all-env] -- <cmd>` | run a command through the proxy |
| `keyfence run [-p PORT]` | run the proxy in the foreground on port 8888 |
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

`keyfence exec` starts the proxy, sets `HTTPS_PROXY`, `HTTP_PROXY` and the CA
variables for the command, snapshots environment variables with secret-like
names into a temporary vault, runs the command, and stops the proxy when it
exits. `--all-env` snapshots every environment variable value.

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
