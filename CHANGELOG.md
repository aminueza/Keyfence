# Changelog

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
