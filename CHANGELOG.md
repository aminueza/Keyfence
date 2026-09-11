# Changelog

## Unreleased

- `mode: audit`: log what would be caught and send the request unchanged.
- `keyfence doctor` checks mitmdump, the CA certificate and its system
  trust, config, vault, proxy, shell environment, local capture, the Claude
  Code hook and the audit log, and says what to fix.
- `keyfence demo` shows what each mode does to a fake request, offline.
- `keyfence import --from op|vault|doppler|aws` registers secrets read from
  1Password, HashiCorp Vault, Doppler or AWS Secrets Manager.
- Default hosts include GitHub Copilot, Vertex AI, Azure AI Foundry and
  GitHub Models.
- A Claude Code plugin under `plugin/` ships the hook and the
  `/keyfence:status` and `/keyfence:setup` skills; install with
  `/plugin marketplace add aminueza/keyfence`. The plugin's hook is a
  self-contained Python file, so it protects you before keyfence is
  installed instead of failing open.
- The hook also covers `Grep` on secret files and shell commands that
  print secrets: `env`, `printenv`, `export -p`, `set`, and the read
  commands of the common secret manager CLIs.
- `keyfence doctor` reports what is only relevant outside `keyfence exec`
  as `info`, so a healthy setup no longer looks like four warnings.
- `keyfence import --from op` reads only the categories that hold secrets
  and the help text recommends `--path <vault>`.
- `SECURITY.md`, a CycloneDX SBOM on every CI run, and unit tests on
  Windows.
- README leads with `uv tool install` and `keyfence exec`, shows the demo
  as an animation, and documents the system-wide certificate trust as the
  exception it is.

## 0.3.4 (2026-09-11)

- The `keyfence exec` environment snapshot lives under
  `~/.keyfence/env/`, and each `exec` removes snapshots older than a
  minute, so a command killed before the proxy came up leaves nothing
  behind for long.
- A command waiting for the vault lock says so on stderr, waits up to 30
  seconds, and then fails with instructions instead of hanging silently.
- The vault lock works on Windows through `msvcrt.locking`.

## 0.3.3 (2026-09-09)

- Two `keyfence import` or `add-secret` commands running at the same time
  could lose one of the secrets and crash with a traceback. Vault updates
  now take a file lock, re-read the file under it, and write through a
  uniquely named temporary file.
- The vault file is validated after parsing: wrong field types or an
  out-of-range `min_length` are reported as a corrupted vault instead of
  silently disabling detection.
- A running proxy keeps its configuration when `config.yaml` is emptied
  or removed; it only reloads a file that parses.
- The proxy prints one line and exits when the vault is corrupted at
  startup, instead of two chained tracebacks.
- `keyfence exec` no longer leaves its temporary environment vault behind
  when killed: the proxy reads it once at startup and deletes it.

## 0.3.2 (2026-09-08)

- A corrupted `vault.json` now produces one clear message from the CLI
  and from the proxy at startup instead of a traceback, and the vault is
  written atomically so a running proxy never reads a half-written file.
- In `placeholder` mode, a compressed SSE response is restored correctly
  when the placeholder is split across events; the buffered path now uses
  the same restorer as the streaming path.
- `config.yaml` is reloaded on a running proxy, like the vault.
- `keyfence run` and `keyfence exec` refuse to start on a port that is
  already in use, with a message that names `-p`.
- `pytest` measures coverage by default, as the docs said it did.
- Documented that headers and the query string are not scanned, and why.

## 0.3.1 (2026-09-08)

- `keyfence run` replaces its own process with mitmdump instead of
  spawning it. Killing `keyfence run` used to leave mitmdump running, and
  with `--local` that orphan kept capturing the named processes system-wide.

## 0.3.0 (2026-09-08)

- `--local` on `keyfence run` and `keyfence exec`: capture traffic by
  process name through mitmproxy's local mode, for tools that ignore proxy
  variables. macOS and Windows.
- `keyfence install-hooks claude-code`: a PreToolUse hook that stops Claude
  Code from reading `.env` files, private keys and credential stores, and
  from running shell commands that touch them. `--project` and `--remove`.
- `keyfence export`: the audit log as JSONL, or as OTLP/HTTP log records
  sent to a collector, with a cursor for incremental runs.
- gitleaks rules that use the `\z` anchor now load on Python 3.12, so the
  same 220 rules apply on every supported version.

## 0.2.2 (2026-09-08)

- During `keyfence exec` the proxy's own output goes to
  `~/.keyfence/proxy.log` instead of the wrapped tool's terminal.

## 0.2.1 (2026-09-08)

- The entropy check skips non-ASCII tokens; a run of Japanese text in
  Claude Code's system prompt was flagged.
- The assignment rule ignores values that are already a redaction token;
  the model's own `TOKEN=[REDACTED]` was redacted again.

## 0.2.0 (2026-09-08)

First release on PyPI.

- Local mitmproxy-based proxy with `block`, `redact` and `placeholder`
  modes; placeholders are restored in streamed responses, even when split
  across SSE events, and are deterministic per secret.
- Vault of salted hashes fed by `keyfence import` (`.env` files and common
  credential stores), `keyfence add-secret` and the environment snapshot
  taken by `keyfence exec`.
- Built-in patterns, the bundled gitleaks ruleset, URL query parameters and
  an entropy check with exclusions for API object ids, base64-encoded JSON,
  lockfile hashes and id, signature and binary fields in JSON bodies.
- Fail-closed: a detector error returns 403.
- A system prompt notice tells the model that redaction tokens are expected.
- `keyfence canary` plants a fake secret that reports which file was read.
- Audit log with masked previews, counts and the JSON key of each finding.
- Reproducible benchmark in `bench/`.
