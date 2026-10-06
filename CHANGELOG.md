# Changelog

## Unreleased

## 0.10.0 (2026-10-06)

- `keyfence exec` and `keyfence run` now configure mitmproxy's `tcp_timeout`
  from a new `proxy_tcp_timeout` key in `~/.keyfence/config.yaml`, which
  defaults to 3600 seconds. mitmproxy closes a TCP connection across which
  no data has moved for longer than `tcp_timeout`, and its built-in default
  of 600 seconds silently kills long LLM requests: a model that takes more
  than ten minutes to produce the first token, or a non-streaming request
  whose reasoning sends nothing until it is done, sees the request fail from
  the client side with no sign in the audit log that the proxy was the one
  that dropped it. Both entry points
  now pass `--set tcp_timeout=<value>` to mitmdump, so the value in the
  config file is honoured by `keyfence exec` (which builds its own mitmdump
  command) and by `keyfence run` (which replaces the current process with
  mitmdump and previously started the proxy with no timeout override at
  all). The key is read like the other top-level keys and validated when the
  file is loaded: a value that is not an integer, or that is zero or
  negative, is an error that names the key and the offending value instead of
  falling back to the default, so a typo cannot quietly re-enable the
  600-second cutoff. `keyfence selftest` starts a proxy too, but its single
  request completes in seconds, so it keeps mitmproxy's own default and is
  unchanged. Review of the change widened who reports a bad config and who
  shows the timeout: a config file that fails to load now makes every
  command print one `error: <message>` line on stderr and exit 1 instead of
  a traceback, because `keyfence main` catches `ValueError` beside the
  existing `VaultError` handler, so `status`, `scan`, `import`, `export`,
  `doctor` and `selftest` report the same one-line error `exec` and `run`
  already did, and `keyfence status` prints the configured timeout in its
  summary (`TCP timeout:     3600 s`), so a session that drops long requests
  can be diagnosed by reading one command's output.

- `keyfence exec` puts `localhost`, `127.0.0.1` and `::1` in `NO_PROXY` and
  `no_proxy` for the command it starts: set when the variable is empty,
  appended without repeating an entry the exported list already holds, and
  each variable keeps its own entries when you exported both. Loopback
  requests therefore bypass the proxy by default instead of paying a hop
  through mitmdump that did nothing, because the default config does not
  put those hosts in `hosts` and `intercept_all_hosts` is off, so the
  addon never scanned them. This is what made a local model server show up
  in `ss -tnp` as a connection from `mitmdump` and hit long requests with
  the 600 s inactivity timeout of #135, and what made podman fail inside
  containers (with `--http-proxy=false` as the way out, now written down
  in `docs/limitations.md`). The entries are left out when the config asks
  to scan the loopback: `intercept_all_hosts` on, or a `hosts` pattern
  that matches a loopback name the way the addon would (`127.0.0.1`,
  `127.0.0.*`) or that merely mentions one as a suffix (`api.localhost`,
  `*.localhost`, where `NO_PROXY=localhost` would bypass the match), so a
  config that asks to scan loopback still gets loopback scanned and
  nothing silently skips it: `keyfence selftest` relies on the first,
  adding `127.0.0.1` to `hosts`, and scanning a local service stays an
  explicit choice. `keyfence doctor` now warns when the shell has a proxy
  set but `NO_PROXY` leaves out the loopback entries, naming the export
  that adds them, for the manual `keyfence run` setup where exec does not
  fill them in for you.

## 0.9.0 (2026-09-29)

- A URL in a command is no longer read as a local path, so
  `curl https://x.com/secrets.json`, `curl https://x.com/.env` and
  `wget http://host/id_rsa` are allowed. The word splitter breaks on `:`, so
  what used to reach the sensitive-name check was the remainder
  `//x.com/secrets.json`, whose basename matches the `secrets.*` rule, even
  though nothing on this machine is named that and the command only fetches
  it. The guard now finds the spans in the raw command that carry a scheme
  and drops those exact characters before the words are split, so the split
  never sees them. Only the schemes that fetch something remote are masked,
  `http`, `https`, `ftp`, `ftps`, `ws` and `wss`, matched without regard to
  case; anything else falls through to the path check, because the mask
  that fixes a false positive must not become the way to read a key.
  `curl file:///root/.ssh/id_rsa` and `FILE:///root/.ssh/id_rsa` read a local
  file through the scheme, so they stay refused, and so does the next
  scheme nobody has heard of that turns out to read local files, which an
  allowlist refuses by default and a denylist would have allowed. A span runs
  from `scheme://` to the end of the shell word, which stops at whitespace
  and at the shell metacharacters, so a path typed after one is still
  decided: `curl https://x.com/a && cat .env` and
  `wget http://host/id_rsa;cat .env` stay refused. The scheme has to come
  from the raw text because the split erases it: `wget http://host/id_rsa`
  and `cat http //root/.ssh/id_rsa` come out of the splitter with the same
  words in the same order, and a rule that recovered the scheme from the
  previous word would let the second one through, which is one line of
  command away from someone's private key. A word that starts with `//` is
  a filesystem path and nothing else, so `cat //evil.com/../.env`,
  `cat //host/.env` and `cat //my.dir/.env` stay refused, and so does
  `cat http //root/.ssh/id_rsa`, which carries no scheme at all.

- `keyfence install-hooks claude-code` now prints the Claude Code versions its
  deny rules need, next to the count of rules it wrote and also when the hook
  was already in place. `Read` deny rules cover `Edit` only from 2.1.208 and
  `Write` only from 2.1.228, so on older versions the declarative layer misses
  those two tools and only the Python hook refuses them. `--remove` does not
  print it. The two versions have one definition in `keyfence/cli.py` and a test
  checks `docs/setup.md` names the same two.
- `docs/configuration.md` now says that `hosts` and `extra_hosts` are
  read when the proxy starts, so under `keyfence exec` editing either takes
  effect on the next session and not during a running one. `keyfence run`
  intercepts every host, so the addon reloads a new entry without a restart.
  The behaviour shipped in 0.8.0 and the caveat was never written down.

- `certifi` is now declared in `pyproject.toml`. `keyfence/runner.py`
  imports it as the first source of system roots for the CA bundle, but
  it was only present because mitmproxy depends on it; on Windows the
  other fallbacks are unlikely to answer, so the bundle rested on a
  transitive dependency. The floor is `2026.1.4`, the first release of
  the current year, and not an older one: certifi is a trust store
  rather than an API, so an old release is an old set of roots, and a
  resolver free to pick one hands the child process a bundle that
  rejects perfectly good certificates, which reads as keyfence's fault
  rather than as a root that expired. `certifi.where()` has pointed at
  the bundled `cacert.pem` since 0.0.4, so the call was never the
  constraint; the roots were.

- The declarative deny rules installed by `keyfence install-hooks
  claude-code` now include `NotebookEdit` rules alongside the existing
  `Read` rules, covering `.env` files, private keys, credentials and other
  secret paths. Carve-outs for safe `.env` names (`.env.example`,
  `.env.sample`, `.env.template`, `.env.dist`) are added for both `Read`
  and `NotebookEdit`. A version note documents that `Read` deny rules only
  cover `Edit` on Claude Code 2.1.208+ and `Write` on 2.1.228+; on older
  versions those tools are not blocked by the declarative rules, though the
  Python hook still refuses them.

- A URL that contains a query parameter whose name matches a sensitive
  pattern is no longer refused. The unglob logic that strips `*` and `?`
  from words now skips words that start with `http://`, `https://`, or `//`
  (the latter covers the scheme-less remainder after word splitting), so
  `curl https://x.com/?credentials=1` and `curl 'https://x.com/?credentials=1'`
  are allowed while `cat .env*`, `rm .env*`, and `cat id_rsa*` are still
  refused. A test pins the URL case. A bracket glob is refused when the
  class expands to a secret name, and every character of every class in the
  word is tried, so `cat .[e]nv`, `cat .[ce]nv`, `cat .[abcde]nv`,
  `cat ~/.ssh/id_[r]sa` and `cat id_rs[a]` are all refused. Where a word
  carries more than one class, every combination of them is tried, because
  `cat .[e]n[v]` and `cat i[d]_rs[a]` each reach a secret name only once
  both classes are resolved at the same time. A class that expands to no
  sensitive name stays allowed: a character class inside a `sed` expression
  or a `grep` pattern is not a path, so `sed -i '' 's/[abc]/x/' file.txt`,
  `grep '[0-9]' data.csv` and `cat notes[1].md` still pass, because the
  expansion still has to match a sensitive name. The expansion is bounded at
  10000 candidates per word, because the combinations multiply: a word
  carrying six classes of ten characters is a million candidates, which took
  the hook about eighteen seconds to decide and would have run into the hook
  timeout. A word past that bound is refused outright rather than decided on
  a partial expansion, so the guard fails closed instead of quietly allowing
  a word it could not resolve.

- `cat [c]redentials` stays allowed, because a word with no `/`, `.` or `_`
  is never treated as a path. That predates this release and is the known
  limit of the word filter, recorded here so the bracket claim above is not
  read as complete.

- The private files keyfence writes are set private through the handle it
  already had open, not through the path. The audit log, the proxy log, the
  CA bundle, the vault and the file `keyfence exec --record` writes each went
  through `os.chmod(path, ...)`, which resolves the path a second time: a
  path swapped between the open and the chmod sent the mode change to
  whatever now answered that name, which is how a file holding secrets in
  clear text ends up with the mode of a file the caller never wrote. Each of
  the five now calls `os.fchmod(handle.fileno(), ...)`, so the mode lands on
  the file the descriptor already refers to. Two of them, the bundle and the
  vault, chmod'd after closing the handle, so those calls moved inside the
  block that holds it, and the record file, whose `touch` opened and closed
  it, is now opened once and set private on that descriptor. The outcome is
  the same mode as before; what changed is that it can no longer land
  somewhere else.

- Placeholder restoration in buffered JSON bodies decides the escaping level
  from the key instead of the first character of the value, which is the rule
  the streamed path already follows. A secret containing newlines, restored
  into a value that merely starts with `{` or `[`, came back escaped one
  level too deep: prose under `content` that quotes an object, such as
  `{"content": "{\"example\": \"<<SECRET_1>>\"} explained above"}`, showed a
  literal `\n` where the newline was, because the leading brace read as "this
  string holds a nested JSON document". The key now decides that question, and
  the value's first character only breaks the tie inside `partial_json` and
  `arguments`, where both shapes genuinely occur, so a nested JSON document
  still gets the second level while prose keeps its real newlines.
- The last docstrings and comments under `tests/` are gone. The branch
  that introduced them ended with a commit called "Remove docstrings and
  comments per convention" and missed the three streaming tests, so they
  were an oversight rather than a deliberate exception. `test_blocker1_...`
  and `test_blocker3_...` were renamed because their docstrings carried
  information the names did not, `test_blocker2_...` was renamed only to
  drop the `blocker2` prefix, and `test_blocker3_...` was split into three
  named tests so that the case labels its comments carried live in the names.
  No behaviour changed.
- `keyfence_path()` is now defined in `keyfence.hooks` and re-exported by
  `keyfence.pi`, removing the duplicate implementation. The hook guard
  (`plugin/hooks/guard.py`) remains a byte-identical copy of `keyfence/hooks.py`
  and runs standalone without importing the package.

- The release gate waits for the CI run to finish instead of reading it once.
  A tag pushed while the `main` run for the release commit was still going
  read `conclusion: null`, which is not `success`, and the release failed
  with nothing wrong: the same suite went green a minute later. The
  `check-ci` job now polls the workflow runs for the tagged SHA every 20
  seconds until one of them reaches `status: completed`, and gives up after
  30 minutes, so a queued or running suite is left to finish while a red one
  still stops the release. The failure says which of the three things
  happened: no run was ever registered for the commit, a run was registered
  and never finished inside the window (`was still queued`, `was still
  in_progress`, with the run id), or a run finished on something other than
  `success` (`concluded with failure`, `concluded with cancelled`). Waiting
  before reporting a missing run is part of the fix, because the API can
  answer empty for a commit whose run has not been registered yet, which is
  the same race that failed the release.
  `tests/test_release_notes.py` pins the shape of the gate by parsing
  `.github/workflows/release.yml` the way the other release tests do: the
  read happens inside a loop that waits for `completed`, the three messages
  stay distinct, `success` is the only conclusion that passes, and the wait
  expires on a named `POLL_TIMEOUT_MS`.

- `.github/PULL_REQUEST_TEMPLATE.md` carries the four sections every merged
  pull request here already used — Problem, What changed, How to test and
  Verification — as prompts under each heading instead of a form, so a
  first-time contributor meets the convention instead of having it
  explained in review. Verification asks for the commit SHA, the date and
  the test counts from the run, because a body carrying those can be
  checked against the diff while a body without them cannot be told from
  a stale one. The code of conduct question and the review-turnaround
  question that #108 raised are deliberately left unanswered here; neither
  is the filer's to decide.

## 0.8.1 (2026-09-28)

- A path written with a trailing glob is refused again. `cat .env*` is how
  an agent asks for `.env` and `.env.local` in one command, and the hook
  let it through: matching splits the command into words and hands each to
  `is_sensitive`, which compares the word as literal text, so `.env*` is
  not `.env`, does not match `.env.*`, which wants a dot after `env`, and
  does not match `*.env`, which wants the name to end there. A word that
  carries `*` or `?` is now also tested with those characters removed, so
  `cat .env*`, `ls .env*`, `rm .env*`, `cat .env?` and `cat id_rsa*` are
  refused while `cat *.md` and `ls *.py` still pass. A glob that stands in
  for a character of the name itself, such as `credential?`, is not
  recovered by that and is still allowed.
- `keyfence hook --help` prints the usage for `hook` instead of
  `unknown agent: --help`. The fast path that serves the hook without
  loading the rest of the CLI read the first argument as the agent name,
  so the one subcommand a person is most likely to try by hand answered as
  if keyfence were broken. `-h` and `--help` now fall through to the
  parser that holds the text, and a hook call with a payload still takes
  the fast path, with argparse and the CLI left unimported.

## 0.8.0 (2026-09-28)

- Placeholder restoration in streamed and buffered responses now decides the
  escaping level from the event or field type, not from the first character
  of the value. This fixes three regressions:
  1. A visible text delta starting with `{` no longer gets an extra level of
     escaping (previously `_looks_like_json` misclassified it as nested JSON).
  2. Object keys in JSON bodies are now restored with the same escaping level
     as values (previously keys got no escaping, breaking JSON parsing when
     the secret contained control characters).
  3. The dead branch in `restore_json` where both `key in NESTED_JSON_FIELDS`
     and the `else` arm assigned `extra=1` is removed; the escaping level is
     now value-based (JSON-like values get double escaping, others get single).
  The Responses API's `response.function_call_arguments.delta` event is now
  recognized as carrying nested JSON and receives the nested escaping level.
- `keyfence exec` tunnels the hosts it does not monitor instead of
  intercepting every HTTPS connection the child made. It never passed
  `--allow-hosts` to mitmdump, so the proxy installed its own
  certificate for every host and decrypted all of them, and the
  `hosts` list only decided whether a finding was reported, never what
  was intercepted: a request to a host outside the list was decrypted
  for nothing, and the certificate the tool saw was not the one the
  host presented. With `intercept_all_hosts` false, which is the
  default, each monitored host is now passed as an allow entry and
  every other host is tunneled with the real certificate, so a session
  outside the list is not decrypted, and `--record` holds only the
  configured hosts. The cost is that `allow_hosts` is read when the
  proxy starts, so editing `hosts` takes effect on the next
  `keyfence exec` and not during the session. The addon still reloads
  its own list, so a host added mid-session is monitored but still
  tunneled, which is the one case where a secret can leave unseen;
  warning on it is left to a follow-up. Intercepting every host when a
  pattern is hard to convert was left out on purpose, because it would
  hide the same bug from a session that set `hosts` on purpose. A
  client that opens the tunnel by address with no SNI has no hostname
  for the list to match and is tunneled now, where it used to be
  decrypted. `keyfence run` and `keyfence selftest` are unchanged and
  keep intercepting every host.
- `keyfence selftest` reaches the listener through `CONNECT`, the way every
  client `keyfence exec` wires up does, instead of opening TLS straight at
  the proxy port with an absolute-form request line inside it. The old
  shape could pass while the tunnel a real tool uses was broken.
- `keyfence selftest` reads the CA variables of the session it runs in. Each
  of `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`,
  `GIT_SSL_CAINFO`, `CARGO_HTTP_CAINFO` and `NODE_EXTRA_CA_CERTS` that is
  set has to be a file that holds the mitmproxy CA, and the TLS step fails
  with the name of the first one that is not, so a session whose variables
  point at a path that does not exist no longer comes out green. When
  `SSL_CERT_FILE` is set, the handshake is verified against the file it
  names rather than against the bundle keyfence writes, so the check tests
  the session and not only keyfence's own state.
- `keyfence selftest` now exercises TLS through the proxy. It used to send
  its request over plain HTTP and print `info  TLS: not exercised`, so it
  proved the addon scans and rewrites but never that a TLS client trusts the
  CA the way `keyfence exec` hands it out. It now starts an HTTPS listener
  with a self-signed certificate, sends the request with `HTTPSConnection`
  configured with the CA bundle (the system roots plus the mitmproxy CA, the
  way `keyfence exec` hands it to child processes), and asserts the handshake
  to the proxy succeeds with mitmproxy's minted certificate while the body is
  still redacted. The upstream leg (proxy to listener) uses `ssl_insecure`
  because the listener's certificate is self-signed and not in any trust
  store; the client-to-proxy leg verifies for real against the bundle. The
  TLS line changes from `info  TLS: not exercised` to an `ok` line naming
  the tunnel, the certificate and the file the handshake was verified
  against. A deliberately wrong CA bundle path makes the step fail with a
  message that names the path, proving the check is not vacuous. Issues #35 and #41 were
  both TLS-only failures that `keyfence doctor` reported as fine; this
  change catches that class of problem. There is no cost to the user: the
  selftest still runs in a temporary home with a throwaway secret and leaves
  your config, vault and audit log untouched.
- `keyfence doctor` checks that a keyfence proxy answers where
  `HTTPS_PROXY` points, instead of comparing that variable against
  8888. `keyfence exec` falls back to a free port when 8888 is busy but
  doctor compared against its own `-p`, which defaults to 8888, so
  every session that took the fallback was warned about its own proxy
  variable, and with two sessions running the output contradicted
  itself two lines apart: the proxy line confirmed the other session's
  keyfence on 8888 and the environment line warned about this one.
  Reading the port back out of `HTTPS_PROXY` would compare the variable
  against itself and never warn again, so doctor takes the host and
  the port from it and probes there, and the `proxy` line follows the
  same endpoint instead of reporting a different session's keyfence as
  this one's. This changes one case from ok to warn: a shell that
  exports `HTTPS_PROXY=http://127.0.0.1:8888` from a profile, with the
  CA variables set and no keyfence running, used to pass and now warns,
  because the variable names a proxy and nothing answers there.
- `keyfence run` checks the port before it prints the banner, and says
  in `--help` why it keeps 8888 while `keyfence exec` picks a free port.
  The banner printed the two `export` lines and then refused the port
  it had just announced. An explicit `-p` still fails with the same
  message on both commands: a port the user typed is a choice.
- Child processes get a CA bundle instead of the single mitmproxy
  certificate. `keyfence exec` pointed `SSL_CERT_FILE`,
  `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `GIT_SSL_CAINFO` at
  `~/.mitmproxy/mitmproxy-ca-cert.pem`, which holds one certificate, and
  those four replace the trust store rather than add to it, unlike
  `NODE_EXTRA_CA_CERTS`. A host reached directly, through a `NO_PROXY` the
  user set, had its perfectly good public certificate rejected by curl,
  Python, requests and git. Those four now point at
  `~/.keyfence/ca-bundle.pem`, the system roots with the mitmproxy CA
  appended, and `NODE_EXTRA_CA_CERTS` keeps the single certificate. The
  roots come from `certifi` when it is importable, then from
  `ssl.get_default_verify_paths().cafile`, then from the usual Linux
  paths. The bundle is rewritten whenever its content would differ, so a
  changed mitmproxy CA or a rotated root is picked up on the next `exec`.
  With no system roots anywhere keyfence says which sources it looked at,
  writes no bundle and does not start the command, because a bundle with
  the mitmproxy CA alone is the bug this fixes. It is written with mode
  0644: it holds no secret, but a permissive umask must not make it
  world-writable. `keyfence doctor` and `keyfence selftest` name the
  bundle and the file the roots came from, and the shell environment check
  now wants them at the bundle rather than at the certificate.
- cargo can reach crates.io inside `keyfence exec`. It could not before,
  failing with "SSL certificate problem: unable to get local issuer
  certificate" even though `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`,
  `CURL_CA_BUNDLE` and `GIT_SSL_CAINFO` were all exported, because cargo
  reads none of them: it sets `CURLOPT_CAINFO` from `http.cainfo`, and
  libcurl only falls back to its own `CURL_CA_BUNDLE` default when no CA
  file was set, while `SSL_CERT_FILE` is read by the curl command line
  tool and never by libcurl. `CARGO_HTTP_CAINFO` now points at the CA
  bundle. It replaces the trust store rather than adding to it, so it
  joins the variables that take the bundle rather than the single
  certificate `NODE_EXTRA_CA_CERTS` gets. `AWS_CA_BUNDLE` was considered
  and left out: botocore reads it, but only as an override, and with it
  unset it already falls back to `REQUESTS_CA_BUNDLE`, which keyfence
  sets, so the AWS CLI did not have this bug.
- `install-hooks claude-code` no longer refuses a project's example env
  file. The `permissions.deny` block it writes covered `.env.example` with
  `Read(./.env.*)`, so Claude Code would not read it and would not let the
  agent create one either, failing with "File is covered by a Read deny
  rule". The hook already let the same file through on both the Read and
  the Bash path, so the two layers disagreed about whether an example env
  file is a secret and the stricter one won. An `allow` rule would not have
  fixed it: Claude Code evaluates deny, then ask, then allow, and no allow
  rule re-permits what a deny rule matches. The block now ends in one
  `Read(!.env.example)`-style carve-out per safe env name, taken from the
  list the hook already keeps, so the two layers read from one list.
  `.env`, `.env.local` and `.env.production` are still refused, at the
  project root and in a subdirectory. 17 rules become 21.
- `install-hooks claude-code` says what it wrote. The command touches
  three things: the `PreToolUse` hook entry, the `permissions.deny` block
  and the `keyfence-deny-rules.json` record that `--remove` reads back.
  The output named the hook and left the other two to be found by
  diffing the settings file afterwards. It now names all three, with the
  rule count and the full path of the record.

- The claude-code hook no longer refuses a command that mentions
  `mitmproxy-ca-cert.pem`. That is the certificate keyfence hands to every
  child process through `CA_ENV_VARS` and prints as "CA certificate" in
  `keyfence doctor`, so refusing it as a secret worked against keyfence
  itself. It is the only name added to the safe list, matched on the
  basename, so the entry still holds when `MITMPROXY_CONFDIR` moves the
  directory. `mitmproxy-ca.pem` stays refused: it holds the private key,
  which forges TLS for any host.
- The healthcheck only opened port 8888, so a container whose proxy came
  up without the addon reported itself healthy while every request went
  straight through. The check now asks the proxy for
  `http://keyfence.invalid/` and requires a keyfence answer, the same
  one `keyfence doctor` uses, so it fails for as long as the addon is
  not loaded.
- The image ran as root and installed whatever `mitmproxy` and `PyYAML`
  version the day of the build happened to be. It now runs as the
  unprivileged user `keyfence`, uid 1000, gid 1000, and pins both
  dependencies at build time. The versions `mitmproxy` itself depends
  on are still resolved by pip.
- A container that could not write its state directory started anyway
  and only failed later, when it first reached for the vault, or kept
  running while it wrote nothing to the audit log. It now takes the
  directory from `KEYFENCE_HOME` instead of assuming `/data`, checks on
  every start that it can write the directory, the vault and the audit
  log, and stops with the `sudo chown` that fixes it, rather than
  running as root to skip the question.
- The user of the image has no home directory. Every `keyfence`
  command that reached for `~/.mitmproxy` or `~/.claude` failed with a
  `PermissionError`, so `selftest`, `exec`, `doctor` and
  `install-hooks` all broke in there. The state directory is the home
  of that user now, and `MITMPROXY_CONFDIR` points at its `certs`
  subdirectory, so the container keeps one CA and it is the one already
  on the host.
- The audit log previews less of a secret. A preview was the first and last
  four characters of any value over ten characters, so a twelve-character
  password left eight of its twelve characters in a file any user on the
  machine could read. A preview is now two characters at each end of a value
  of 24 characters or more, and a shorter value is logged as its kind and its
  length alone.
- `audit.log` and `proxy.log` are created with mode 0600. Both were opened
  with the plain append mode, so they landed with the umask, 0644 on a
  default machine, while the vault next to them is 0600 and the `--record`
  file is created private. They are now created with `os.open` and
  `O_CREAT | O_APPEND` at 0600, so no other account on the machine can read
  them, and a log an older version left at 0644 is tightened on the next
  write. `keyfence exec` says on stderr when the mode cannot be set. The
  audit log drops the line instead, so a preview never lands in a file it
  cannot prove is private.
- A request signed with AWS SigV4 that carries a secret is blocked in
  `redact` and `placeholder` mode instead of rewritten. Bedrock requests
  made with AWS credentials are signed over the body, so any change keyfence
  made to it would have been rejected by AWS with a signature error that
  did not mention keyfence. keyfence now answers with its own 403 that
  names SigV4. Both the `Authorization: AWS4-...` header and presigned URLs
  with `X-Amz-Signature` count as signed; requests with a Bedrock API key
  are redacted as before.
- Pattern rules see a JSON escape as a separator. In a JSON body `\t` is
  two characters, so the `t` sat right before a secret that followed a
  tab, and a rule that needs a word boundary, such as the built-in
  `github-token`, missed it. The gitleaks twin still caught a GitHub token
  under another label; a rule that exists only as a built-in missed the
  value entirely. Rules now see such an escape as the separator it
  stands for, so the built-in label is the one reported.
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
  match while `GIT_AUTHOR_EMAIL` does not. A segment that ends with
  `token`, `secret` or `password` counts on its own, so `ACCESSTOKEN`,
  `CLIENTSECRET`, `DBPASSWORD` and the `identitytoken` field of the docker
  config keep matching, and so does one that opens with those words and
  closes on a secret word, such as `SECRETACCESSKEY`. `key` is not in that
  list, so `MONKEY_ISLAND` stays out. The names a tool fixes and a
  developer cannot rename are words of their own: `PGPASSWORD`, `SSHPASS`,
  `PASSPHRASE` and `PASSCODE`.

What this costs: a short, low-entropy value under a name that glues an
  ordinary word onto `key` alone, such as `SSHKEY` or `SECKEY`, is no
  longer registered by name. Use a separator (`SSH_KEY`), camel case
  (`sshKey`) or `keyfence import --all`. The matcher now tries two
  splittings of each name (the standard camel-case split and one that keeps
  the trailing capital on an acronym), so the quadratic bound applies to
  both. Names that glue an ordinary word onto `pass`, `passwd` or `senha`
  (`DBPASS`, `SMTPPASS`, `ADMINPASS`, `DBPASSWD`, `KEYSTOREPASS`,
  `DBSENHA`) are recovered with a bounded exception list that keeps
  `COMPASS` and `BYPASS` out; `HTPASSWD` is also excepted because it names
  a file, not a secret.
- The Claude Code hook fails closed. An exception inside `decide()` used
  to exit 1, which Claude Code reads as no opinion, so the call went
  through with the guard half-alive. A hook that never started had the
  same effect: `keyfence hook claude-code` was written into settings.json
  as a bare command, so a keyfence that is not on PATH, as with `uv tool`
  or a project venv, was never found and every call passed unchecked.
  `run_hook` now wraps the decision in `try/except BaseException`, prints
  a reason naming the exception type, and exits 2 on anything,
  `SystemExit` and `KeyboardInterrupt` included. A new install writes the
  absolute path of the running keyfence into settings.json, and
  `keyfence doctor` reads the command out of each settings file and fails,
  naming the command, when its executable does not exist, is not
  executable, or is not on PATH.
  A hook that does not resolve now refuses the call instead of letting it
  through unguarded, so a rebuilt venv or a moved install needs
  `keyfence install-hooks claude-code` again to bake the new path, and a
  bug in the hook blocks calls instead of passing them. The entry is
  written only when no keyfence hook is present, so an install that
  already has one keeps the bare command and relies on the doctor check.
  The 10-second timeout Claude Code applies is still a way to fail open,
  and the hook cannot close it, since a call the hook never answers is
  allowed. Closing it needs a wrapper process or a timeout in the hook
  protocol. The plugin runs `guard.py` with `python3`, which a default
  Windows install does not have, and `plugin/README.md` now says so.
- Text in one Anthropic response no longer jumps between its content blocks.
  Restoring a placeholder the provider split across deltas means holding
  back a trailing `<` until it is clear whether the token continues or the
  model wrote a `<` of its own, and that character was filed under the JSON
  path of the string inside the event. In an Anthropic stream that path is
  `delta.text` for every text block, so two blocks shared it: a `<` held at
  the end of the first was taken out of it and put in front of the next.
  Nothing was written out while anything was held, so the rest of the
  response waited as well, a tool call included, until the next delta on
  that path or the end of the stream. Held text now carries the block's
  `index` next to the path, and a block's held text is released when its
  own `content_block_stop` arrives. OpenAI chunks already had the choice
  index in their path, so two choices were never affected.
  The cost is the mirror of the bug: a placeholder split across two
  content blocks is no longer restored. Holding across a block boundary is
  what let the first block's `<` travel to the second, so releasing at
  `content_block_stop` gives up the cross-block case to fix the
  within-block one. A provider that splits its own echoed placeholder
  exactly on a block boundary now leaves a raw `<<SECRET_...>>` in the
  first block and the tail in the second. No provider was found that does
  this, and the alternative is the bug this change fixes.
- Detection reads a request the way the model reads it. Every provider
  request is JSON, and the detectors ran on the raw body, where a quote
  arrives as `\"`, a newline as `\n` and an accented letter can arrive
  as `\u00e7`. Several detectors assume plain text, so
  `password: "Hunter2Hunter2x"` was missed, because the backslash ends
  the value group of `generic-assignment`; a vault secret holding a
  comma, brackets or a space was split by the tokenizer and only matched
  right after `=` or `:` without quotes, and a passphrase with spaces
  never matched; a non-ASCII vault secret was missed whenever the client
  serialised with `ensure_ascii`; and a builtin rule right after an
  escape lost its `\b` boundary, which is why a `ghp_` token after a tab
  was labelled `github-pat` by the gitleaks twin instead of
  `github-token`. Scanning now runs over the decoded string values and
  maps each finding back to the escaped span it came from, so requests
  are still rewritten where the secret really is and stay valid JSON.
  Placeholder mappings hold the decoded value and it is escaped again
  when a response or a websocket frame is rewritten, so a PEM sent as an
  ordinary JSON string
  comes back byte for byte, buffered or streamed, and a placeholder
  inside a field that carries JSON of its own (`partial_json`,
  `arguments`) is escaped one level more. A secret that was already
  nested that deep in the request keeps one level of escaping, since the
  body is decoded once, so a PEM sent inside `arguments` comes back with
  its newlines still written as `\n`. The `heroku-uuid-key` rule now
  measures its 20-character window across line breaks, because the
  newline it used to reach over is a real one on a decoded body. Decoding the body covers the word-boundary case
  above for every detector, so the pass that blanked escapes with spaces
  is gone. `docs/benchmark.md` is measured again on Python 3.13: the
  `code` context goes from 90% to 100% and pattern-only recall for a
  random password from 38% to 52%, with precision unchanged.
- A release note is one line. The workflow put the whole `CHANGELOG.md`
  section in the release body, which runs to 150 lines for a release like
  0.6.0 and reads as a wall of text on the releases page. The body is now
  the first two entries of the section, the number of changes left out and
  a link to the section itself, so the page skims and the detail stays in
  one place. `tools/release_notes.py --full` still prints the section.

- Every release gets its notes. The workflow published to PyPI and stopped
  there, so the tags carried no GitHub release at all and the releases page
  was a list of bare tags. It now creates the release for the tag with the
  `CHANGELOG.md` section of that version as the body and the sdist and
  wheel attached, after the upload to PyPI succeeds. A tag whose version
  has no section, or an empty one, fails the step instead of publishing an
  empty release. `tools/release_notes.py` prints the same body locally.
- The Tests section of `docs/development.md` says how to check a leak
  from inside `keyfence exec`. The blind spot is the model's, not the
  terminal's: `exec` sets the proxy and CA variables and runs the child
  with `subprocess.call`, so a person sees what the child printed in
  clear, and a secret in a response body is never touched. The output an
  agent read, though, reaches the provider inside the next request, and
  keyfence rewrites that request, so the model reads `[REDACTED:kind]`
  for a leaked value and for a printed marker alike.
  `tests/test_scan_scope.py` pins the claims the page rests on.
- The benchmark measures every sample as it reaches the proxy, inside a
  JSON request body. Only the tool result template was wrapped before, and
  it used the one assignment form that survives JSON escaping, so the
  published recall for quoted values was higher than what the proxy
  delivers. Plain samples are now the content of a `tool_result`, a third
  of them with `ensure_ascii`; the raw text is still measured, a new table
  shows recall by context with the raw number where it differs, and
  `--json` returns both views under `as_sent` and `raw`.
  `docs/benchmark.md` has the numbers for both views. The page is no
  longer one of its own prose samples, so
  regenerating it does not change the counts it publishes, and the output
  names the Python version, since the code samples come partly from its
  standard library.

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
