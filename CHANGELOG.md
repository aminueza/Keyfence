# Changelog

## Unreleased

- A request signed with AWS SigV4 that carries a secret is blocked in
  `redact` and `placeholder` mode instead of rewritten. Bedrock requests
  made with AWS credentials are signed over the body, so any change keyfence
  made to it would have been rejected by AWS with a signature error that
  did not mention keyfence. keyfence now answers with its own 403 that
  names SigV4. Both the `Authorization: AWS4-...` header and presigned URLs
  with `X-Amz-Signature` count as signed; requests with a Bedrock API key
  are redacted as before.
- The benchmark measures every sample as it reaches the proxy, inside a
  JSON request body. Only the tool result template was wrapped before, and
  it used the one assignment form that survives JSON escaping, so the
  published recall for quoted values was higher than what the proxy
  delivers. Plain samples are now the content of a `tool_result`, a third
  of them with `ensure_ascii`; the raw text is still measured, a new table
  shows recall by context with the raw number where it differs, and
  `--json` returns both views under `as_sent` and `raw`.
  `docs/benchmark.md` has the new numbers: 90% instead of 100% for
  secrets in code, 38% instead of 52% for random passwords found by
  patterns alone. The page is no longer one of its own prose samples, so
  regenerating it does not change the counts it publishes, and the output
  names the Python version, since the code samples come partly from its
  standard library.
- Pattern rules see a JSON escape as a separator. In a JSON body `\t` is
  two characters, so the `t` sat right before a secret that followed a
  tab, and a rule that needs a word boundary, such as the built-in
  `github-token`, missed it. The gitleaks twin still caught a GitHub token
  under another label; a rule that exists only as a built-in missed the
  value entirely. Rules now run on a copy of the body where each escape
  that stands for a character is blanked with spaces, which keeps every
  offset, and report the value as sent.
- The system prompt notice matches the mode. It used to tell the model in
  every mode that tokens are restored on the way back, which is true only
  for `placeholder`; in `redact` the model wrote `[REDACTED:...]` into
  code and config files expecting the real value to appear. The `redact`
  notice now says the values are not restored and asks the model to
  reference them the way the project already does.
- Registering a secret while a `keyfence exec` session runs no longer
  blocks every request. On a machine without `~/.keyfence/vault.json`,
  `exec` hashed the environment with a salt it never saved, and the proxy
  then saved the vault with a different one. The next `add-secret`,
  `import` or `canary` reloaded the vault, the two salts could not be
  merged, and the proxy answered 403 to everything until it was
  restarted. `exec` now saves the vault before it hashes the environment,
  so both use the same salt.
- WebSocket frames sent to a monitored host are scanned. The addon only
  implemented `request`, `responseheaders` and `response`, and mitmproxy
  delivers frames through `websocket_message`, so once a connection had
  been upgraded every frame reached the provider unscanned. Several hosts
  on the default list offer a WebSocket API on the same host as their HTTP
  one, which made this a hole in front of a real path. Text frames from the
  client now go through the same detectors as a request body: `audit` logs
  them, `redact` and `placeholder` rewrite them, `block` drops the frame,
  and placeholders are restored in the frames that come back. Audit entries
  for a frame carry `"websocket": true`. Binary frames are still passed
  through, which `docs/limitations.md` now says, next to what each mode
  means on a WebSocket. The addon also turns mitmproxy's `websocket`
  option back on at startup, and says so in the log: with the option off,
  a 101 goes to the raw TCP layer and every frame passes unscanned, and a
  `websocket: false` in `~/.mitmproxy/config.yaml` beats the command line,
  so an argument could not close that hole.
- Secret names are matched word by word. The name test was a plain
  substring search, so `auth` fired on `GIT_AUTHOR_EMAIL`, `key` on
  `KEYBOARD_LAYOUT`, `pass` on `COMPASS_URL` and `api` on `CAPITAL_CITY`.
  `keyfence exec` reads the whole environment, so an author's email was
  registered in the vault and every request carrying `git log` output came
  out with `[REDACTED:vault]` in it. The name is now split on separators
  and camel case, and each segment has to be a secret word or a run of
  them, so `OPENAI_APIKEY`, `authToken` and `aws_secret_access_key` still
  match while `GIT_AUTHOR_EMAIL` does not. A name that glues a word onto a
  secret word without a separator no longer matches by name: `DBPASSWORD`,
  `GITHUBTOKEN` and the `identitytoken` field of the docker config. Long
  random values still reach the vault through the entropy check; a short
  one needs a separator (`DB_PASSWORD`), camel case (`dbPassword`) or
  `keyfence import --all`.

## 0.7.0 (2026-09-24)

- The Claude Code plugin manifest carries the package version. It had
  stayed at 0.2.1 while `plugin/hooks/guard.py` gained the Bash path
  rules, the shell-prefix and catalogue rules and the refusal of
  unreadable input, so the marketplace never offered those to anyone who
  installed the plugin. A test now ties the manifest version to the last
  release, and the release steps say to bump it.
- Two `keyfence exec` sessions can run at once. Each session starts a
  proxy of its own, yet both defaulted to port 8888, so the second one
  died with `Port 8888 is already in use` although it had no reason to
  want that port. Without `-p`, `exec` now takes 8888 when it is free and
  otherwise a free port chosen by the OS, says which on stderr
  (`keyfence: port 8888 is busy, using 51234`) and hands that port to the
  command and the addon probe. An explicit `-p` that is busy still fails
  as before; `keyfence run` and `keyfence doctor` keep 8888, since that is
  the foreground proxy tools are pointed at by hand.
- `keyfence doctor` checks that the paths keyfence baked still work. The
  pi extension calls keyfence by the absolute path resolved when it was
  installed; when that path went away (a rebuilt venv, a file synced from
  another machine) every guarded pi call was refused, the refusal said to
  check `keyfence doctor`, and doctor said `ok` because it only looked
  for its marker in the file. Doctor now reads the baked path out of the
  extension and fails, naming the path, when it does not exist or is not
  executable; the `mitmdump` check does the same for an absolute path,
  which it used to print as `ok` without looking. `keyfence install-hooks
  pi --command PATH` bakes a path of your choice, or a bare `keyfence` to
  be looked up on `PATH` at each call, and the install output says what
  the extension calls. The guard-unavailable reason names
  `keyfence install-hooks pi` as the fix, next to `keyfence doctor`.
- `keyfence exec` hands the CA certificate to git as well, through
  `GIT_SSL_CAINFO`. Git reads none of the four variables that were set, so
  every HTTPS `git` command inside a session, and anything that shells out
  to git such as `uv tool install git+https://...`, failed with a
  certificate error. `keyfence doctor` now checks every CA variable
  `keyfence exec` sets, not only `NODE_EXTRA_CA_CERTS`, and names the
  missing ones.
- A secret right after a JSON escape no longer breaks the request. In a
  JSON body, `\t`, `\n` and the other escapes are two characters, and the
  tokenizer split only at the backslash, so a value following `\t` was
  seen as `t` plus the value: the vault never matched it, and the
  `[REDACTED:...]` or `<<SECRET_...>>` splice started one character into
  the escape, leaving `\[REDACTED:...]`, which the provider rejected with
  `400 invalid escape`. Escapes now separate tokens in JSON bodies, so a
  secret after a tab or a newline is found and replaced with the escape
  kept intact, and the proxy widens any replacement that would still cut
  an escape in half. If a rewrite would leave the body unparsable anyway,
  the request is refused with a 403 that says so, instead of being sent
  broken.
- CI and release workflows run `actions/checkout@v7`,
  `actions/setup-python@v7`, `actions/upload-artifact@v7` and
  `actions/download-artifact@v8`, the current majors built for Node 24,
  and pin the Linux jobs to `ubuntu-24.04` instead of `ubuntu-latest`,
  which GitHub moves to Ubuntu 26 in October 2026.
- The agent hook refuses a tool call it cannot read. Empty stdin,
  unparsable JSON or a JSON value that is not an object exited 0, which
  means "allowed", so a serialisation bug in an agent integration let
  every call through. They now exit 2 with a reason on stderr, the same
  path the pi extension and Claude Code already handle for a refusal. A
  valid object with a tool name the rules do not inspect still exits 0.
- Git for Windows reads the CA inside a `keyfence exec` session. Its
  default schannel backend ignores `GIT_SSL_CAINFO` unless
  `http.schannelUseSSLCAInfo` is set, so on Windows `keyfence exec` now
  sets that option for its session through `GIT_CONFIG_COUNT`,
  `GIT_CONFIG_KEY_n` and `GIT_CONFIG_VALUE_n`, appended after any entries
  already in the environment. `keyfence doctor` on Windows warns, with the
  `git config --global` command, when a shell points git at a proxy and
  the option is set neither in git's config nor in the environment.

## 0.6.0 (2026-09-24)

- `keyfence demo` tells the story in plain words and names no provider or
  agent: the request goes to a generic chat endpoint, each mode gets a
  one-line description, and the closing lines point at `keyfence import`,
  `keyfence exec -- <agent>` and `keyfence selftest`. On a terminal the
  secret values are red and the replacements green; `NO_COLOR` and a
  non-tty output keep it plain. The README animation is rendered from the
  new output.
- `keyfence install-hooks --list` prints the supported agents and, for
  each, whether the hook is installed globally and in the current project,
  with the file it looked at. `keyfence doctor` already knew, but it runs
  every other check too and its line does not name the file. `--list`
  takes no agent and refuses `--project`, `--remove` and `--force` with
  exit code 2; `install-hooks` with neither an agent nor `--list` is an
  error as well. The detection is the one `doctor` uses, factored out so
  the two cannot drift. The hook's contract is written down in
  `docs/agents.md`: the JSON object on stdin, the exit codes and why
  anything but 0 and 2 has to count as "guard unavailable", the tool names
  and input fields the rules read for Claude Code and for pi, what each
  integration provides, what the agent argument of `keyfence hook` is for,
  a shell and a Node example, and a checklist for wiring up another
  agent. Until now that was only visible by reading `hooks.py` and
  `pi.py`.
- `keyfence selftest` proves end to end that the proxy is protecting
  traffic. `keyfence doctor` checks the pieces one by one, so a proxy that
  starts and scans nothing passes every check. The new command starts a
  proxy the way `keyfence exec` does, on a free port, with a copy of your
  config and a throwaway vault in a temporary home (your config, vault and
  audit log are not touched, your configured mode is), sends one request
  carrying a throwaway secret through it to a listener it starts on
  127.0.0.1, never to a provider, and checks the outcome for the mode: a
  403 in `block`, `[REDACTED:vault]` at the listener in `redact`, a
  `<<SECRET_...>>` placeholder at the listener and the real value back in
  the response in `placeholder`, the value unchanged in `audit`, plus an
  audit entry in every mode and the CA at the path `keyfence exec` hands to
  child processes. It prints one line per step in the `doctor` style and
  exits 1 on the first step that fails, naming it: mitmdump missing, proxy
  not up, addon not answering the probe, config not applied, value reached
  the listener unchanged, placeholder not restored, no audit entry, each
  with the tail of the proxy log. The request is plain HTTP, so TLS
  interception and CA trust are not exercised; the output says so.
  `keyfence exec` and `selftest` now share one proxy start-up path in
  `runner.start_proxy`, and `keyfence doctor` points to `selftest` when
  nothing is wrong.
- `docs/setup.md` no longer says that `keyfence import --from` registers
  every value read. Since 0.5.0 the values go through the same
  secret-looking filter as file import, `--all` registers everything, and
  `--from` cannot be combined with file paths or `--env`.
- `ignore_keys` and `ignore_values` in `config.yaml` say "this one is not
  a secret". `keyfence import` registers a value when its name looks like
  a secret or when it has high entropy, so `DB_HOST=db.internal.example.com`
  landed in the vault and, in `block` mode, turned every request that
  mentioned the hostname into a 403; the only way out was editing
  `vault.json`, which holds hashes. A pair whose name matches
  `ignore_keys` (case-insensitive, `*` and `?` as in shell globs) is not
  registered by `import` from files, `--env` or `--from`, nor by the
  environment snapshot of `keyfence exec`, even with `--all`, and a
  finding under that JSON key is dropped at detection time. A value in
  `ignore_values` is never registered and never reported by any check:
  vault, patterns, gitleaks rules, URL query or entropy. The values are
  written in clear in the config file, but keyfence hashes them with the
  vault salt when it reads the file and compares hashes from then on, so
  they never reach `vault.json`, the audit log or the console. Ignored
  findings are dropped before overlapping findings are merged, so an
  ignored value cannot shadow a longer secret it sits inside. A running
  proxy picks up changes to either list without a restart. `keyfence
  status` shows the size of each list, `keyfence scan` says how many
  findings it dropped, and an audit entry carries `suppressed: n` when a
  request had other findings besides the ignored ones. A list that is
  not a list of non-empty strings is a config error.
- `keyfence exec --record` says when the flows file will hold secrets in
  clear text, and SECURITY.md lists every file keyfence writes. "What
  keyfence sees and stores" named `vault.json`, `audit.log`, `env/` and
  `~/.mitmproxy/` and stressed that values are never written, but left
  out `~/.keyfence/proxy.log` and the `--record` flows file. Measured on
  a real mitmdump, the flows file holds every request as it left
  keyfence, headers included: in `redact` and `placeholder` mode the
  secrets are already replaced, in `audit` mode they are in clear text,
  and in `block` mode the blocked request is stored as the command sent
  it, so in clear text too. Responses are streamed through and not kept
  unless keyfence produced or rewrote them, so the old help text's "full
  request and response bodies" was wrong in both directions.
  `bench/lab/run.py`, the shipped example of `--record`, runs in
  `mode: audit`, so pointing the lab at a real agent recorded that session
  unredacted without a word. `keyfence exec --record` now prints one line
  on stderr naming the file and what it will hold when the mode is
  `audit` or `block`, the `--record` help text and the lab README say the
  same, and SECURITY.md describes both files: `proxy.log` holds the
  startup summary and one line per detection with host, count and kinds,
  the `CANARY tripped` line names the canary's file, never a value.
- The agent hook recognises a secret-printing command behind the shell
  constructs that wrap one. `env` was refused but `sudo env`, `LC_ALL=C
  env`, `/usr/bin/env`, `eval env`, `command env`, `xargs env`, `bash -c
  env`, `{ env; }` and `env` after `then` or `do` were not, because the
  rule only looked at the start of a line or after `;`, `&`, `|`, `(` and
  a backtick. The same start rule now also accepts `{` and the keywords
  `then`, `do` and `else`, and skips `sudo`, `command`, `eval`, `exec`,
  `xargs`, `nohup`, `time`, `bash -c` and the like, a `VAR=value`
  assignment and an absolute path to the binary, for the environment dumps
  and for the secret manager catalogue alike. The catalogue gains `aws sts
  get-session-token`, `get-federation-token` and `assume-role*`, `aws ecr
  get-login-password`, `aws configure export-credentials`, `gh auth status
  --show-token`, `bw list items`, `kubectl get secret -o custom-columns`,
  and `echo` or `printf` of a `$VARIABLE` whose name looks like a secret.
  `doppler secrets --only-names` prints no values and is no longer
  refused; `doppler secrets`, `download` and `get` still are.
- `keyfence install-hooks claude-code --remove` no longer deletes deny
  rules you wrote yourself when `keyfence-deny-rules.json` is missing.
  0.5.0 started recording the rules it adds in that file and removing only
  those, but with no record, which is the state of every install made with
  0.4.0, it fell back to removing every rule in its own list, so a
  `Read(./.env)` you had added by hand went with them. Without a record
  `--remove` now takes out the hook, leaves the deny rules alone, prints
  the ones that match keyfence's and says there is no way to tell who
  added them; `--remove --force` removes all of those. `--force` without
  `--remove` is an error, and a record that cannot be parsed counts as
  missing. `--remove` also reports how many deny rules it removed.
- The proxy's own log lines are visible again. mitmdump was started with
  `-q`, which silences every log line including keyfence's, so
  `keyfence run` printed nothing after its banner, `~/.keyfence/proxy.log`
  stayed empty on a healthy `keyfence exec`, and the `CANARY tripped`
  warning the docs promised never appeared outside the audit log. mitmdump
  now runs with `termlog_verbosity=warn` and `flow_detail=0`: the
  `REDACT`, `PLACEHOLDER`, `BLOCKED`, `AUDIT` and `CANARY tripped` lines
  and mitmproxy's own warnings (a client that does not trust the CA, for
  instance) show up, while mitmproxy's per-request output and info chatter
  stay out. The startup summary is logged at that level too and carries
  the version, so it is the first line on the terminal for `keyfence run`
  and in `proxy.log` for `keyfence exec`.
- The agent hook refuses the same files in Bash commands as in file tools.
  Paths inside a command were matched by a second, shorter list, so
  `secrets.yaml`, `service-account*.json`, `kubeconfig`, `.envrc`,
  `id_dsa`, `_netrc`, `*.keystore` and files under `.gnupg` were refused
  for `Read` and allowed for `cat`. Every word of the command that looks
  like a path now goes through the one list the file tools use, including
  words inside quotes, after `=` in options and assignments, and in
  `volume:mount` pairs. Relative paths under `.ssh`, `.kube`, `.docker`,
  `.aws` and `.gnupg` are recognised too. A bare name without `/`, `.` or
  `_` such as `cat credentials` is still not treated as a path, so that
  `rg credentials src/` keeps working.
- `keyfence import --from op` raises a clean error when an item from `op item list`
  has no `id` field instead of crashing with a `KeyError` traceback.
- The mitmproxy addon no longer depends on the name mitmproxy gives the
  script module. `keyfence/addon.py` declared the addon only when the module
  name started with `__mitmproxy_script__`, an undocumented detail of
  mitmproxy's loader; on a mismatch mitmdump ran as a plain proxy and every
  request reached the provider unscanned, with nothing on stderr and a
  healthy `keyfence doctor`. The addon is now always declared and reads the
  config and the vault in mitmproxy's `load` hook, so importing
  `keyfence.addon` still touches no files.
- `keyfence exec` checks that the addon is live before starting the
  command: it sends a request for `http://keyfence.invalid/` through the
  proxy, which only the addon answers, and refuses to start the command if
  the answer does not come. `keyfence doctor` runs the same probe against a
  proxy that is already listening and warns when whatever is on the port
  is not keyfence.

## 0.5.0 (2026-09-24)

- `main` carries a `.dev0` version between releases, so `keyfence doctor`
  on a checkout of `main` no longer prints the same version as the build
  published on PyPI.
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
