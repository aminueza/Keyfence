# Changelog

## Unreleased

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
