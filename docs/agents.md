# The agent hook contract

`keyfence hook <agent>` is the gate that stops a coding agent from reading
secret files or running commands that print secrets. The rules live in
`keyfence/hooks.py` and know nothing about any particular agent: they see a
tool name and the tool's input, and answer allow or refuse. Claude Code and
pi are wired up today; this page is what you need to wire up another one
without reading `hooks.py` and `pi.py` first.

## Wire format

The caller runs `keyfence hook <agent>` once per tool call, before the tool
runs, and writes one JSON object to its stdin:

```json
{"tool_name": "Read", "tool_input": {"file_path": "/work/.env"}}
```

- `tool_name`: the tool the agent is about to call, as a string. It is
  compared case-insensitively, so `Read` and `read` are the same tool.
- `tool_input`: the tool's arguments as an object. A missing or null
  `tool_input` is treated as `{}`.

The answer is the exit code. stdout is never used.

| exit | meaning | what the caller does |
|---|---|---|
| `0` | allowed | run the tool |
| `2` | refused | do not run the tool; stderr holds the reason, one paragraph written for the model (it starts with `keyfence blocked`) |
| anything else, or the process could not be started | guard unavailable | refuse the call and say the guard did not run |

Only `0` means yes. `keyfence hook cursor` exits `1` with `unknown agent:
cursor` on stderr because `cursor` is not a known agent, and a missing
binary, a broken install or a timeout are all "unavailable" too. The pi
extension is the reference for that case; its `unavailable()` reason is:

> keyfence blocked this call because its guard could not run (`<path to
> keyfence>`: `<detail>`). Tell the user to run `keyfence doctor`, and
> `keyfence install-hooks pi` again if keyfence moved; until then keyfence
> cannot tell whether this call would expose a secret.

where `<detail>` is the spawn error message, or stderr, or `exit <code>`.
Failing open here would turn a broken install into a silent gap.

The hook is strict about the shape of its input and lenient about its
content. Unparsable JSON, an empty stdin or a JSON value that is not an
object exit `2` with a reason that starts with `keyfence blocked` and says
the tool call could not be read, so a serialisation bug on your side
refuses calls instead of letting them through. Inside a valid object,
anything the rules do not inspect exits `0`: a tool name that is not in
the tables below, a missing `tool_input`, or unknown fields.

Claude Code gives the hook 10 seconds; the pi extension has no timeout of
its own. A decision takes a few milliseconds once Python is up, and the
`hook` subcommand is served by `keyfence/entry.py` before the rest of the
package (mitmproxy included) is imported, so the cost is one interpreter
start.

## What the rules look at

`decide()` in `keyfence/hooks.py` lowercases `tool_name` and sorts it into
one of three groups. Anything else is allowed without looking at the input.

| group | tool names (`hooks.py` constant) | fields read from `tool_input` | refused when |
|---|---|---|---|
| file tools | `read`, `edit`, `write`, `multiedit`, `notebookedit` (`FILE_TOOLS`) | the first non-empty of `file_path`, `notebook_path`, `path` (`PATH_KEYS`, in that order) | the path is a secret file |
| search tools | `grep` (`GREP_TOOLS`) | `path` and `glob`, both checked | either names a secret file or pattern |
| shell tools | `bash`, `powershell` (`SHELL_TOOLS`) | `command` | any word of the command that looks like a path is a secret file, or the command prints secrets |

"Secret file" is `is_sensitive()`: the name patterns in `SENSITIVE_NAMES`
and the directory patterns in `SENSITIVE_PATHS`, minus `SAFE_NAMES`
(`.env.example`, `*.pub` and friends). Matching is case-insensitive and
backslashes count as slashes, so `C:\Users\u\.NETRC` is refused like
`~/.netrc`. The command rules are described in
[setup.md](setup.md#claude-code); `powershell` runs through exactly the
same rules as `bash`, which are shaped for a POSIX shell, so a
PowerShell-only way of printing the environment is not caught.

## Tool names and fields per agent

Claude Code:

| tool | field the hook reads | how the hook is attached |
|---|---|---|
| `Read`, `Edit`, `Write`, `MultiEdit` | `file_path` | `PreToolUse` hook, matcher `Read\|Edit\|Write\|MultiEdit\|NotebookEdit\|Grep\|Bash` |
| `NotebookEdit` | `notebook_path` | same |
| `Grep` | `path`, `glob` | same |
| `Bash` | `command` | same |

Claude Code sends `tool_name` and `tool_input` on stdin under exactly those
keys, which is where the wire format comes from.

pi:

| tool | field the hook reads | how the hook is attached |
|---|---|---|
| `read`, `edit`, `write` | `path` | extension `keyfence.ts`, `tool_call` event |
| `grep` | `path`, `glob` | same |
| `bash`, `powershell` | `command` | same |

pi's `tool_call` event carries `toolName` and `input`; the extension
renames them to `tool_name` and `tool_input` before writing them to stdin.
pi's `find` and `ls` are not gated because they return names, not
contents. The list of gated tools is `GUARDED_TOOLS` in `keyfence/pi.py`
and is embedded in the extension when it is installed.

## What an integration provides

Claude Code has declarative hooks and permissions, so
`keyfence install-hooks claude-code` writes into `settings.json`
(`~/.claude/settings.json`, or `./.claude/settings.json` with `--project`):

- a `PreToolUse` entry with the matcher above and the command
  `keyfence hook claude-code`, timeout 10;
- `permissions.deny` rules for `Read` on `.env` files, `*.pem`, `*.key`,
  `credentials*`, `secrets.*`, `*.tfvars` and the home-directory
  credential stores (`DENY_RULES` in `hooks.py`). These need no Python on
  the path and are what managed settings can enforce; the rules keyfence
  added are recorded in `keyfence-deny-rules.json` next to the settings
  file so `--remove` takes out only those. The block ends in one
  `Read(!.env.example)`-style carve-out per safe env name, so the two
  layers agree that an example env file is not a secret. A carve-out
  cancels only the rules listed before it, which is why they come last.

The Claude Code plugin in `plugin/` attaches the same rules through
`plugin/hooks/hooks.json`, running `plugin/hooks/guard.py` with `python3`.
That file is a byte-for-byte copy of `keyfence/hooks.py` (a test checks
this) so the plugin works before keyfence is installed.

pi has no declarative rules, so `keyfence install-hooks pi` writes an
extension (`~/.pi/agent/extensions/keyfence.ts`, or
`./.pi/extensions/keyfence.ts` with `--project`) rendered from the template
in `keyfence/pi.py`. It handles `tool_call`, ignores tools outside
`GUARDED_TOOLS`, spawns keyfence by the absolute path resolved at install
time (or the one given with `--command PATH`) and maps the exit code as
in the table above. The file carries a `Generated by keyfence` marker;
`install-hooks pi` overwrites only files that carry it and refuses to
touch anything else. `keyfence doctor` reads the baked path back out of
the file and fails when it no longer exists or is not executable, since
that is the state in which every guarded call is refused.

Any other agent needs the same two things: somewhere to run a command
before each tool call, and a few lines that serialise the call, spawn
`keyfence hook <agent>` and map the exit code. `keyfence install-hooks
--list` shows what is installed for each agent and where it looked.

## `keyfence hook <agent>`

The agent argument must be one of `claude-code` and `pi`, the `AGENTS`
tuple that `keyfence/entry.py` and `keyfence/cli.py` both hold. Both
values run the same `decide()` today: the tool-name and field rules above
are the union of what the two agents send, and nothing in the payload
tells the hook which agent it came from. The argument is what makes that
work without guessing. It names the caller, so a hook line in a settings
file or an extension says what it was installed for, and it is the place
where a per-agent mapping (different tool names, differently named fields,
a different refusal message) can be added later without changing what
`install-hooks` has already written into users' settings files and
extensions.

## Worked examples

From a shell, a refusal and an allow. `keyfence hook` reads stdin to the
end, so the pipe has to close:

```bash
printf '%s' '{"tool_name": "Read", "tool_input": {"file_path": ".env"}}' | keyfence hook claude-code
echo "exit $?"
```

prints the reason on stderr and `exit 2`;

```bash
printf '%s' '{"tool_name": "read", "tool_input": {"path": "src/app.py"}}' | keyfence hook pi
echo "exit $?"
```

prints nothing and `exit 0`.

From Node, the same mapping the pi extension uses, in a synchronous form:

```js
import { spawnSync } from "node:child_process";

export function guard(agent, toolName, input) {
  const result = spawnSync("keyfence", ["hook", agent], {
    input: JSON.stringify({ tool_name: toolName, tool_input: input }),
    encoding: "utf8",
    timeout: 10_000,
  });
  if (result.error) return { block: true, reason: `keyfence guard unavailable: ${result.error.message}` };
  if (result.status === 0) return undefined;
  if (result.status === 2) return { block: true, reason: result.stderr.trim() };
  return { block: true, reason: `keyfence guard unavailable: exit ${result.status}` };
}
```

`guard("pi", "read", { path: ".env" })` returns a block with the keyfence
reason; `guard("pi", "read", { path: "src/app.py" })` returns `undefined`.
A timeout surfaces as `result.error`, so it is refused as unavailable. The
asynchronous version with `spawn` is the extension template in
`keyfence/pi.py`.

## Adding an agent

1. Tool names. Check the agent's names against `FILE_TOOLS`, `GREP_TOOLS`
   and `SHELL_TOOLS` in `keyfence/hooks.py` and the field names against
   `PATH_KEYS`, `path`, `glob` and `command`. Add lowercased names where
   the agent's differ. `plugin/hooks/guard.py` must stay identical to
   `hooks.py`, so copy it over after any change.
2. Agent name. Add it to `AGENTS` in both `keyfence/entry.py` and
   `keyfence/cli.py`; the first validates `keyfence hook <agent>`, the
   second validates `install-hooks <agent>` and drives `--list`.
3. Install. Write a module like `keyfence/pi.py`: a function that returns
   the path for the global and the project scope, `install`, `uninstall`
   and an `is_ours` that recognises what keyfence wrote. Add a branch to
   `cmd_install_hooks` in `keyfence/cli.py`, an entry for the agent in
   `installed_scopes` in `keyfence/doctor.py` and a check in
   `run_checks`. `install-hooks --list` then reports it on its own.
4. Tests. Model a `tests/test_<agent>.py` on `tests/test_pi.py`: real
   payloads of the agent through `hooks.decide()`, refused and allowed;
   path resolution for both scopes with `Path.home` monkeypatched to
   `tmp_path`; install idempotent, uninstall, and a refusal to overwrite a
   file keyfence did not write; `cli.main(["install-hooks", "<agent>"])`
   and `--remove` through the CLI with the `home` fixture; the entry point
   in a subprocess, expecting exit `2` and `keyfence blocked` on stderr;
   and, if the agent has a list of gated tools, that every one of them is
   a tool the rules inspect. Add the doctor check to
   `tests/test_doctor.py` and the new `--list` lines to `tests/test_cli.py`.
5. Docs. A section in [setup.md](setup.md#blocking-secret-files-in-your-agent),
   a table on this page, the README's Documentation list and a
   CHANGELOG entry.
