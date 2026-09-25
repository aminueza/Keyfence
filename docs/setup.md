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
keyfence selftest            # prove the proxy changes or stops a secret, end to end
```

Start with `mode: audit` in `~/.keyfence/config.yaml` if you want to see
what your tools send before changing anything; `keyfence status` lists what
would have been caught. Switch to `redact` when you are comfortable.

## The CA certificate

mitmproxy creates a certificate authority in `~/.mitmproxy/` the first time
the proxy starts. Tools need to trust it so the proxy can read HTTPS traffic.

`keyfence exec` hands the child process a CA bundle at
`~/.keyfence/ca-bundle.pem` through `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`,
`CURL_CA_BUNDLE` and `GIT_SSL_CAINFO`, and the mitmproxy certificate itself
through `NODE_EXTRA_CA_CERTS`, so Claude Code, Codex, Aider, curl, git and
anything on the Python or Node SDKs work with no further step. The first
four replace the trust store rather than add to it, so the
bundle is the system roots with the mitmproxy CA appended: a host the
child reaches directly, through a `NO_PROXY` you set, is then validated
against the public roots it was issued from. The bundle is written on the
first `keyfence exec` and rewritten whenever the mitmproxy CA or the
system roots change; `keyfence doctor` and `keyfence selftest` name the
file and say where the roots came from. Git
for Windows uses the schannel backend by default, which ignores
`GIT_SSL_CAINFO` unless `http.schannelUseSSLCAInfo` is set, so on Windows
`keyfence exec` also sets that option for its session through
`GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_0` and `GIT_CONFIG_VALUE_0` (read by
git 2.31 and later, appended after any entries you already export). A git
pointed at a `keyfence run` proxy by hand needs
`git config --global http.schannelUseSSLCAInfo true` instead, and
`keyfence doctor` says so on Windows when it is missing. Only desktop apps
and tools that ignore those variables, and `--local` capture, need the
certificate in the system store:

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
| `keyfence selftest [-p PORT] [--timeout SECONDS]` | start a proxy, send a throwaway secret through it to a local listener and check the outcome for your mode |
| `keyfence demo` | show what each mode does to a fake request, offline |
| `keyfence add-secret` | register one secret typed at a hidden prompt |
| `keyfence canary [file] [--name VAR]` | append a fake secret to a file (default `.env`) and register it as a canary |
| `keyfence exec [-p PORT] [--all-env] [--local [NAMES]] -- <cmd>` | run a command through its own proxy on port 8888, or a free port when that one is taken |
| `keyfence run [-p PORT] [--local [NAMES]]` | run the proxy in the foreground on port 8888 |
| `keyfence install-hooks claude-code\|pi [--project] [--remove [--force]] [--command PATH]` | stop the agent from reading secret files at all |
| `keyfence install-hooks --list` | show the supported agents and whether the hook is installed for each, globally and in this project |
| `keyfence hook claude-code\|pi` | the hook itself; the agent runs it, you do not |
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
name; without it every item in the account is fetched one at a time, so
pass a vault; only the API Credential, Login, Password, Secure Note,
Database and Server categories are read, concealed fields only), `vault`
(HashiCorp, `--path secret/myapp`, KV v1 or v2, one path, no recursion),
`doppler` (`--path project/config`,
otherwise the current scope) and `aws` (Secrets Manager, `--path` is the
secret id; JSON secrets contribute every value). The values read go through
the same filter as file import: only the ones that look like secrets, by
name or by entropy, are registered, and `--all` registers every value. The
command prints how many values were read, how many looked like secrets and
how many were new. Only hashes are stored. `--from` cannot be combined with
file paths or `--env`; run those as separate commands.

`keyfence exec` starts a proxy of its own on port 8888, or on a free port
chosen by the OS when 8888 is taken, for example by another `keyfence exec`
session (it says so on stderr: `keyfence: port 8888 is busy, using 51234`;
`-p PORT` pins the port instead and fails if that one is busy), waits
until the keyfence addon answers a
request for `http://keyfence.invalid/` sent through it (mitmdump listening
is not enough: without the addon it would be a plain proxy), sets
`HTTPS_PROXY`, `HTTP_PROXY` and the CA variables for the command, snapshots
environment variables with secret-like names into a temporary vault, runs
the command, and stops the proxy when it exits. If the addon never answers,
the command is not started and the reason is in `~/.keyfence/proxy.log`.
`keyfence doctor` sends the same probe to a proxy that is already running. `--all-env` snapshots every environment variable value. The snapshot
is a hash file under `~/.keyfence/env/` that the proxy reads once at
startup and deletes. If the command is killed before the proxy gets that
far, the next `keyfence exec` removes anything older than a minute from
that directory. The proxy's own output
goes to `~/.keyfence/proxy.log` so it does not mix with the command's
terminal: a startup line with the version, mode, host count, rule count
and vault size, one line per detection (`REDACT`, `PLACEHOLDER`,
`BLOCKED`, `AUDIT`, `CANARY tripped`), and mitmproxy's own warnings, such
as a client that does not trust the CA. Detections are also in the audit
log and `keyfence status`.

To upgrade an isolated install: `uv tool upgrade keyfence` or
`pipx upgrade keyfence`.

## Proving that the proxy protects traffic

`keyfence doctor` looks at the pieces one by one, so a proxy that starts
and scans nothing passes every check. `keyfence selftest` proves the whole
chain instead:

```
$ keyfence selftest
ok    mitmdump: /opt/keyfence/bin/mitmdump
ok    config: mode=redact, 20 hosts from ~/.keyfence/config.yaml; copied to a temporary home with 127.0.0.1 added to the hosts, your config and vault untouched
ok    proxy: mitmdump up on 127.0.0.1:55460
ok    addon: answering the probe for http://keyfence.invalid/
ok    CA certificate: ~/.mitmproxy/mitmproxy-ca-cert.pem, the path keyfence exec hands to child processes
ok    CA bundle: ~/.keyfence/ca-bundle.pem, /etc/ssl/certs/ca-certificates.crt (a system path) plus ~/.mitmproxy/mitmproxy-ca-cert.pem
ok    mode: the proxy reports redact, as configured, with 127.0.0.1 monitored
ok    request: the listener received [REDACTED:vault] instead of the value
ok    response: HTTP 200 passed back with the redaction in place
ok    audit log: 1 entry(ies) with a vault finding written for the request
ok    TLS: handshake to proxy succeeded with mitmproxy's certificate, body redacted

The proxy is protecting traffic in redact mode.
```

It starts a proxy the way `keyfence exec` does, on a free port, with a copy
of your config and a vault holding one throwaway value in a temporary
directory, so your config, vault and audit log are not touched while your
configured mode, hosts and scan settings are the ones under test. It then
starts a small HTTP listener on 127.0.0.1, adds that address to the
monitored hosts of the copy, sends one request carrying the throwaway
value through the proxy to the listener, never to a provider, and checks
what came out: a 403 and an empty listener in `block`, `[REDACTED:vault]`
at the listener in `redact`, a `<<SECRET_...>>` placeholder at the listener
and the real value restored in the response in `placeholder`, the value
unchanged at the listener in `audit`, plus an audit entry in every mode.
The exit code is 0 when the outcome matches the mode and 1 otherwise, and
the first `FAIL` line says which step broke: mitmdump missing, the proxy
not coming up, the addon not answering the probe, the config not applied
(mode or host count differ from what the proxy reports), the value reaching
the listener unchanged, the placeholder not restored, no audit entry. The
last lines of the proxy's own log are printed under the failed step; the
full log is in `~/.keyfence/selftest.log`.

What is not covered: the upstream leg (proxy to listener) uses `ssl_insecure` because the listener's self-signed certificate is not in any trust store; the client-to-proxy leg verifies for real against the CA bundle. `--local` capture and the agent hooks are not part of it either; `keyfence doctor` reports on those. `-p` picks the proxy port instead of a free one, and `--timeout` how long to wait for the proxy and the addon.

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

## Blocking secret files in your agent

The proxy stops secrets from leaving the machine. The hook stops the agent
from reading them in the first place. `keyfence install-hooks --list`
shows, for each supported agent, whether the hook is installed globally
and in the current project and which file it looked at. The hook's
contract (what goes on stdin, what the exit codes mean, which tool names
and fields each agent sends, and how to wire up another agent) is in
[agents.md](agents.md).

### Claude Code

```bash
keyfence install-hooks claude-code            # all projects (~/.claude/settings.json)
keyfence install-hooks claude-code --project  # this project (./.claude/settings.json)
keyfence install-hooks claude-code --remove           # takes out only what keyfence added
keyfence install-hooks claude-code --remove --force   # also deny rules an install before 0.5.0 left unrecorded
```

The same hook ships as a Claude Code plugin, together with `/keyfence:status`
and `/keyfence:setup`. In the plugin the hook is a self-contained Python 3
file, so it protects you even before keyfence itself is installed. Inside
Claude Code:

```
/plugin marketplace add aminueza/keyfence
/plugin install keyfence@keyfence
```

It adds a `PreToolUse` hook for Read, Edit, Write, MultiEdit, NotebookEdit,
Grep and Bash that refuses `.env` files, private keys, `.netrc`, `.npmrc`,
`.pypirc`, `.git-credentials`, `credentials*`, `secrets.*`, `*.tfvars`,
service account files, anything under `.ssh`, `.aws/credentials`,
`.docker/config.json` and `.kube/config`. `.env.example` and `*.pub` are
allowed. Bash commands that mention such a path are refused too, and so
are commands that print secrets: `env`, `printenv`, `export`, `set`,
`declare -x`, `printenv NAME` when the name looks like a secret, `echo` or
`printf` of a `$VARIABLE` whose name looks like a secret,
`/proc/*/environ`, and the read commands of `aws secretsmanager`, `aws ssm`
with decryption, `aws configure get` of a key, `aws configure
export-credentials`, `aws sts get-session-token`, `get-federation-token`
and `assume-role*`, `aws ecr get-login-password`, `op read`, `op item get`
with `--reveal`, `--fields` or JSON output, `vault`, `doppler`, `kubectl`
secrets with `-o yaml|json|jsonpath|go-template|custom-columns`, `kubectl
config view --raw`, `gcloud secrets`, `gcloud auth print-*-token`, `az
keyvault`, `az account get-access-token`, `gh auth token`, `gh auth status
--show-token`, `heroku config`, `infisical`, `bw get` and `bw list items`.
The command is recognised at the start of a line, after `;`, `&&`, `||`,
`|`, `(`, `{`, a backtick, `then`, `do` or `else`, and behind `sudo`,
`command`, `eval`, `exec`, `xargs`, `nohup`, `time`, `bash -c` and the
like, a `VAR=value` assignment, or an absolute path to the binary, so
`sudo env`, `LC_ALL=C env` and `/usr/bin/env` are refused like `env`.
Listing names without values, such as `kubectl get secrets`, `gh secret
list` or `doppler secrets --only-names`, is allowed. The refusal message
tells the model to ask you instead or to use `keyfence import`.

`keyfence install-hooks claude-code` also adds `permissions.deny` rules
for `Read` on `.env` files, `*.pem`, `*.key`, `credentials*`, `secrets.*`,
`*.tfvars` and the home-directory credential stores. These are Claude
Code's own declarative rules: they need no Python on the path, and they
are what managed settings can enforce for a whole organisation. Existing
hooks and rules in the settings file are kept, and `--remove` takes out
only what keyfence added: the rules it adds are listed in
`keyfence-deny-rules.json` next to the settings file, and rules that were
already there stay, even when they are identical to keyfence's.

Installations made with 0.4.0 have no such list. There `--remove` takes
out the hook, leaves every deny rule in place, prints the ones that match
keyfence's and says that there is no way to tell who added them.
`--remove --force` removes all of those, yours included, so read the list
first. `--force` without `--remove` is an error.

### pi

```bash
keyfence install-hooks pi            # all projects (~/.pi/agent/extensions/keyfence.ts)
keyfence install-hooks pi --project  # this project (./.pi/extensions/keyfence.ts)
keyfence install-hooks pi --remove
```

pi has no declarative permission rules, so the gate is a pi extension: a
small TypeScript file that handles `tool_call` and asks `keyfence hook pi`
about every `read`, `write`, `edit`, `grep`, `bash` and `powershell` call
before it runs. The rules are the ones above, and the refusal reaches the
model with the same message. The extension calls keyfence by absolute
path, resolved when you install it, so reinstalling keyfence somewhere
else means running `install-hooks pi` again; `--command PATH` bakes a
path of your choice instead, for a file shared between machines, and a
bare `--command keyfence` makes the extension look keyfence up on `PATH`
at each call. If the guard cannot run at all, the call is refused rather
than allowed, and the reason says so. `keyfence doctor` checks that the
baked path still exists and is executable, and names it either way, so a
deleted venv or a file synced from another machine shows up as a failure
there instead of as refusals in pi.

`--project` writes to `./.pi/extensions/`, which pi loads only after you
trust the project; it asks on the first interactive start. The global
location needs no trust.

`find` and `ls` are not gated: they return file names, not contents.

For the proxy layer, start pi with `keyfence exec -- pi`. pi reads
`HTTPS_PROXY` and `NODE_EXTRA_CA_CERTS` from its environment, which is
what `keyfence exec` sets, so no further configuration is needed.

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

SYSTEM_ROOTS=$(python3 -c "import ssl; print(ssl.get_default_verify_paths().cafile)")
mkdir -p ~/.keyfence
cat "$SYSTEM_ROOTS" ~/.mitmproxy/mitmproxy-ca-cert.pem > ~/.keyfence/ca-bundle.pem

export HTTPS_PROXY=http://127.0.0.1:8888
export HTTP_PROXY=http://127.0.0.1:8888
export NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem   # Node tools, e.g. Claude Code
export SSL_CERT_FILE=~/.keyfence/ca-bundle.pem                  # Python tools
export REQUESTS_CA_BUNDLE=~/.keyfence/ca-bundle.pem
export CURL_CA_BUNDLE=~/.keyfence/ca-bundle.pem
export GIT_SSL_CAINFO=~/.keyfence/ca-bundle.pem                # git over HTTPS
```

The first four replace the trust store, so they need the system roots with
the mitmproxy CA appended, which is what `keyfence exec` writes for you
under `~/.keyfence/ca-bundle.pem`. Pointing them at
`~/.mitmproxy/mitmproxy-ca-cert.pem` on its own works only while everything
goes through the proxy: a host you put in `NO_PROXY` is then validated
against a trust store that holds one certificate.

For desktop apps, set the system proxy to `127.0.0.1:8888`.

`keyfence run` prints the same startup line and detection lines that
`keyfence exec` writes to `~/.keyfence/proxy.log`, and nothing per
request otherwise.

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

## Testing it with an agent

```bash
mkdir -p /tmp/kf-test && cd /tmp/kf-test
printf 'GITHUB_TOKEN=ghp_FAKE0000000000000000000000000000000\nDB_PASSWORD=not-a-real-password-2026\n' > .env
keyfence import
keyfence exec -- claude          # or: keyfence exec -- pi
```

Ask the agent to read `.env` and show the values. It sees
`[REDACTED:vault]` instead. `keyfence status` lists the detections. With
the hook installed as well, it does not get to read the file at all.
