# keyfence

[![CI](https://github.com/aminueza/keyfence/actions/workflows/ci.yml/badge.svg)](https://github.com/aminueza/keyfence/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/keyfence.svg)](https://pypi.org/project/keyfence/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/aminueza/keyfence/blob/main/LICENSE)

A local proxy that stops secrets from reaching LLM APIs. It checks every
request to an AI provider before it leaves your machine and blocks, redacts
or placeholder-swaps API keys, passwords and other secrets. Coding agents
read `.env` files and credential stores and send what they find to the
model; keyfence makes sure the values never arrive.

![How keyfence sits between your tools and the provider](https://raw.githubusercontent.com/aminueza/keyfence/main/docs/keyfence-flow.png)

## Try it in one minute

```bash
uv tool install keyfence     # or: pipx install keyfence, or pip install keyfence
keyfence demo                # shows what each mode does to a fake request, no network
```

![keyfence demo: the same request in audit, redact, placeholder and block mode](https://raw.githubusercontent.com/aminueza/keyfence/main/docs/keyfence-demo.gif)

## Use it

```bash
keyfence import              # register your own secrets: .env files and credential stores, hashes only
keyfence exec -- claude      # run Claude Code through the proxy
```

That is the whole setup for Claude Code, Codex, Aider, curl and anything
built on the Python or Node SDKs: `keyfence exec` starts the proxy, points
the command at it and hands it the CA certificate, then stops the proxy when
the command exits. No `sudo`, nothing changes on your system.

Not sure it is working? `keyfence doctor` checks every piece and says what
to fix. `keyfence status` shows what has been caught.

Two more layers, both optional:

```bash
keyfence install-hooks claude-code   # Claude Code refuses to read secret files at all
keyfence canary .env                 # plant a fake secret; if a tool ever sends it, you will know
```

## Modes

Set `mode` in `~/.keyfence/config.yaml`.

| mode | behaviour |
|---|---|
| `audit` | log what would have been caught, change nothing; start here to see what your tools send |
| `redact` (default) | secret becomes `[REDACTED:<kind>]` |
| `placeholder` | secret becomes `<<SECRET_id>>` and the real value is restored in the response, streaming included |
| `block` | request gets a 403 and is not sent |

## What it catches

Your own secrets, whatever their format, once registered with
`keyfence import` (from `.env` files, `~/.aws/credentials`, `~/.netrc`,
`~/.npmrc`, `~/.docker/config.json`, or `--from op|vault|doppler|aws`);
240 known formats through built-in rules and the bundled gitleaks ruleset;
and high-entropy strings that look like secrets. Only salted hashes are
stored. Details and numbers in the [benchmark](https://github.com/aminueza/keyfence/blob/main/docs/benchmark.md).

## Verified with

Claude Code (through `exec`, `--local` and the hook), the Anthropic and
OpenAI HTTP APIs, curl, Python and Node clients. GitHub Copilot, Vertex AI
and Azure AI hosts are on the default list but have not been tested end to
end. Cursor and Windsurf route through their own backends and are not on
the list; add their hosts with `extra_hosts` if you want to try, and an
issue with the result helps either way.

## Documentation

- [Setup](https://github.com/aminueza/keyfence/blob/main/docs/setup.md):
  install options, GUI apps and system-wide trust, capturing tools that
  ignore proxies, Docker, all commands.
- [Detection](https://github.com/aminueza/keyfence/blob/main/docs/detection.md):
  the vault, pattern rules, entropy check, what is excluded, the audit log.
- [Configuration](https://github.com/aminueza/keyfence/blob/main/docs/configuration.md):
  every option, environment variables, the system prompt notice.
- [Benchmark](https://github.com/aminueza/keyfence/blob/main/docs/benchmark.md):
  recall by secret format and false positive rate by content type, against
  gitleaks, reproducible with `python bench/run.py`.
- [Limitations](https://github.com/aminueza/keyfence/blob/main/docs/limitations.md):
  what keyfence does not cover and what to combine it with.
- [Claude Code plugin](https://github.com/aminueza/keyfence/blob/main/plugin/README.md):
  the hook and two skills, installable with `/plugin marketplace add aminueza/keyfence`.
- [Security](https://github.com/aminueza/keyfence/blob/main/SECURITY.md):
  what the proxy sees, what it stores, how releases are built.
- [Development](https://github.com/aminueza/keyfence/blob/main/docs/development.md)
  and [Changelog](https://github.com/aminueza/keyfence/blob/main/CHANGELOG.md).

## License

MIT. Bundled detection rules come from [gitleaks](https://github.com/gitleaks/gitleaks),
also MIT.
