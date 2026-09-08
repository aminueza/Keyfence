# keyfence

[![CI](https://github.com/aminueza/keyfence/actions/workflows/ci.yml/badge.svg)](https://github.com/aminueza/keyfence/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/aminueza/keyfence/blob/main/LICENSE)
![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)

A local proxy that stops secrets from reaching LLM APIs. It checks every
request to an AI provider before it leaves your machine and blocks, redacts
or placeholder-swaps API keys, passwords and other secrets. Works with Claude
Code, Cursor, Codex, Aider, curl and anything else that speaks HTTP.

![How keyfence sits between your tools and the provider](https://raw.githubusercontent.com/aminueza/keyfence/main/docs/keyfence-flow.png)

## Install

```bash
pip install keyfence
```

Python 3.12 or newer. mitmproxy comes as a dependency.

## Use

```bash
keyfence import              # register your secrets from .env and credential files (hashes only)
keyfence exec -- claude      # run a tool through the proxy
keyfence canary .env         # plant a fake secret; if a tool ever sends it, you will know
keyfence install-hooks claude-code   # stop Claude Code from reading secret files at all
```

On first run mitmproxy creates a CA certificate in `~/.mitmproxy/`. Trust it
once so HTTPS can be inspected (macOS shown, other systems in the
[setup guide](https://github.com/aminueza/keyfence/blob/main/docs/setup.md)):

```bash
sudo security add-trusted-cert -d -p ssl \
  -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem
```

## Modes

| mode | behaviour |
|---|---|
| `block` | request gets a 403 and is not sent |
| `redact` (default) | secret becomes `[REDACTED:<kind>]` |
| `placeholder` | secret becomes `<<SECRET_id>>` and the real value is restored in the response, streaming included |

## Documentation

- [Setup](https://github.com/aminueza/keyfence/blob/main/docs/setup.md): CA
  certificate, manual proxy setup, Docker, all commands.
- [Detection](https://github.com/aminueza/keyfence/blob/main/docs/detection.md):
  the vault, pattern rules, entropy check, what is excluded, the audit log.
- [Configuration](https://github.com/aminueza/keyfence/blob/main/docs/configuration.md):
  every option, environment variables, the system prompt notice.
- [Benchmark](https://github.com/aminueza/keyfence/blob/main/docs/benchmark.md):
  recall by secret format and false positive rate by content type, against
  gitleaks, reproducible with `python bench/run.py`.
- [Limitations](https://github.com/aminueza/keyfence/blob/main/docs/limitations.md):
  what keyfence does not cover and what to combine it with.
- [Development](https://github.com/aminueza/keyfence/blob/main/docs/development.md):
  tests, coverage gate, integration script, releasing.
- [Changelog](https://github.com/aminueza/keyfence/blob/main/CHANGELOG.md)

## License

MIT. Bundled detection rules come from [gitleaks](https://github.com/gitleaks/gitleaks),
also MIT.
