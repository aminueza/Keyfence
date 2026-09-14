# Changelog

## Unreleased

- pi support. `keyfence install-hooks pi` installs a pi extension that
  refuses `read`, `write`, `edit`, `grep`, `bash` and `powershell` calls
  aimed at secret files or at commands that print secrets, the same rules
  the Claude Code hook uses; `keyfence hook pi` is the gate it calls, and
  `keyfence doctor` reports whether it is installed. The rules now read
  pi's tool names and its `path` argument as well as Claude Code's.
- The system prompt notice goes into the first system message of an
  OpenAI-style request instead of a new one at the end. Providers and
  local servers that require the system message to come first rejected
  the request with a 400.
- Streamed responses no longer end early. The SSE restorer returned an
  empty byte string whenever it had nothing to emit yet, and mitmproxy
  turns that into the terminating zero-length chunk of a chunked
  response, so the client saw the stream finish in the middle. It now
  yields no chunk at all instead. Hit in placeholder mode whenever a
  placeholder was split across SSE events.
- The Claude Code hook now catches commands on any line of a multi-line
  Bash call, after leading whitespace, inside `$( )` and backticks, and
  file names in any letter case. Before, `cd /tmp` followed by `env` on
  the next line passed.
- `keyfence demo` no longer reads or writes the real keyfence home; the
  mitmproxy addon is only instantiated when mitmproxy loads the script.
- `keyfence import --from` keeps only values that look like secrets, the
  same rule as file import; `--all` registers everything; combining
  `--from` with file paths or `--env` is an error; a CLI that does not
  return JSON gives a one-line error.
- `keyfence hook` starts in a fraction of the time: the console script
  serves it from a minimal entry point that imports only the hook module,
  and the rest of the CLI no longer imports mitmproxy unless a command
  needs it.
- `MITMPROXY_CONFDIR` is passed to mitmdump, so the CA keyfence looks for
  and the CA mitmproxy uses are the same.
- `--record` files are created with mode 0600.
- The plugin skills can run only the keyfence subcommands they need.
- `keyfence exec --record FILE` saves the raw traffic as a mitmproxy flows
  file, and `--linger SECONDS` keeps the proxy up after the command exits
  to capture what is sent afterwards.
- `bench/lab/`: a reproducible agent traffic lab. A toy project with
  generated fake secrets and a canary, a runner that wraps any agent
  command in `keyfence exec` with audit mode, and a report that produces
  the comparison table, per-run JSON and a bytes-by-destination chart.

## 0.4.0 (2026-09-11)

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
  print secrets: `env`, `printenv`, `export`, `set`, `printenv` of a
  secret-looking name, `/proc/*/environ`, session-token commands such as
  `gh auth token`, `gcloud auth print-access-token` and
  `az account get-access-token`, and the read commands of the common
  secret manager CLIs. Listing names without values stays allowed.
- `keyfence install-hooks claude-code` also adds `permissions.deny` rules
  for secret files, Claude Code's declarative mechanism that managed
  settings can enforce organisation-wide.
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
