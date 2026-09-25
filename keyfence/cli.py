from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import secrets
import sys
from collections import Counter
from pathlib import Path

from . import doctor, export, hooks, pi, runner, sources
from .config import Config
from .detectors import scan_report
from .importer import default_paths, env_values, import_files, looks_secret
from .vault import DEFAULT_DIR, Vault, VaultError

AGENTS = ("claude-code", "pi")


def cmd_add_secret(_args) -> int:
    vault = Vault()
    print("Paste the secret to protect (hidden; only its hash is stored):")
    value = getpass.getpass("> ")
    if not value.strip():
        print("Nothing entered, aborting.")
        return 1
    if not vault.add(value):
        print(f"Secret too short (minimum {vault.min_length} characters); "
              "shorter values would cause too many false positives.")
        return 1
    print(f"OK. Vault now holds {vault.count()} secret(s) (hashes only, in {vault.path}).")
    return 0


def cmd_import(args) -> int:
    vault = Vault()
    ignore = Config.load().ignore_list(vault)
    if ignore.key_count or ignore.value_count:
        print(f"Ignore lists: {ignore.key_count} key(s), {ignore.value_count} value(s) from {Config.path()}")
    if args.source:
        if args.paths or args.env:
            print("error: --from cannot be combined with file paths or --env; run them as separate commands", file=sys.stderr)
            return 2
        try:
            pairs = sources.fetch(args.source, args.path)
        except sources.SourceError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        values = [v for k, v in pairs
                  if not ignore.ignores(k, v) and (args.all or looks_secret(k, v, vault.min_length))]
        added = vault.add_many(values)
        print(f"{args.source}: {len(pairs)} value(s) read, {len(values)} looked like secrets, "
              f"{added} new; vault now holds {vault.count()} (hashes only). Use --all to register every value.")
        return 0
    paths = [Path(p).expanduser() for p in args.paths] or default_paths()
    missing = [p for p in paths if not p.is_file()]
    for p in missing:
        print(f"skip: {p} (not a file)")
    paths = [p for p in paths if p.is_file()]
    if not paths and not args.env:
        print("Nothing to import. Pass file paths, or use --env to import from the environment.")
        return 1
    total = 0
    for path, added in import_files(vault, paths, everything=args.all, ignore=ignore):
        total += added
        print(f"{path}: {added} new secret(s)")
    if args.env:
        added = vault.add_many(env_values(os.environ, vault.min_length, everything=args.all, ignore=ignore))
        total += added
        print(f"environment: {added} new secret(s)")
    print(f"Done. {total} new secret(s); vault now holds {vault.count()} (hashes only).")
    return 0


def cmd_canary(args) -> int:
    path = Path(args.file)
    name = args.name
    existing = path.read_text(errors="replace") if path.exists() else ""
    if re.search(rf"^\s*(?:export\s+)?{re.escape(name)}\s*=", existing, re.MULTILINE):
        print(f"{path} already defines {name}. Pick another name with --name.")
        return 1
    value = secrets.token_urlsafe(24)
    vault = Vault()
    vault.add_canary(value, str(path.resolve()))
    prefix = "" if not existing or existing.endswith("\n") else "\n"
    with path.open("a") as fh:
        fh.write(f"{prefix}{name}={value}\n")
    print(f"Canary planted in {path} as {name} and registered in the vault (hash only).")
    print("If it ever shows up in a request, keyfence logs a 'canary' detection with this file's path.")
    return 0


def cmd_scan(args) -> int:
    if args.file:
        text = Path(args.file).read_text(errors="replace")
    elif args.text:
        text = args.text
    else:
        text = sys.stdin.read()
    cfg = Config.load()
    vault = Vault()
    report = scan_report(text, vault=vault, config=cfg.scan, ignore=cfg.ignore_list(vault))
    if report.suppressed:
        print(f"{report.suppressed} finding(s) ignored by the ignore lists in {Config.path()}")
    if not report.findings:
        print("No secrets detected.")
        return 0
    print(f"{len(report.findings)} secret(s) detected:")
    for f in report.findings:
        where = f" in \"{f.key}\"" if f.key else ""
        print(f"  - [{f.kind}] {f.masked} (offset {f.start}-{f.end}{where})")
    return 2


def cmd_run(args) -> int:
    if runner.port_open(args.port):
        print(f"Port {args.port} is already in use. Pick another one with -p.")
        return 1
    print(f"Starting keyfence on http://127.0.0.1:{args.port}")
    if args.local is not None:
        target = "all processes" if args.local in ("", "*") else f"processes named {args.local}"
        print(f"Local capture on for {target}: no proxy variables needed, "
              "but the CA certificate must be trusted system-wide.")
    print("Point your tools at it, e.g.:")
    print(f"  export HTTPS_PROXY=http://127.0.0.1:{args.port}")
    print(f"  export HTTP_PROXY=http://127.0.0.1:{args.port}")
    print("or run them through it directly: keyfence exec -- <command>")
    print("(Ctrl+C to stop)\n", flush=True)
    command = runner.proxy_command(args.port, local=args.local)
    try:
        os.execvp(command[0], command)
    except FileNotFoundError:
        print("mitmdump not found. Install it with: pip install mitmproxy")
        return 1


def cmd_exec(args) -> int:
    command = list(args.argv)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("usage: keyfence exec [-p PORT] [--all-env] [--local [NAMES]] [--record FILE] [--linger SECONDS] -- <command> [args...]")
        return 1
    return runner.run(command, args.port, everything=args.all_env, local=args.local,
                      record=Path(args.record) if args.record else None, linger=args.linger)


def cmd_hook(_args) -> int:
    return hooks.run_hook()


def _install_pi(args) -> int:
    path = pi.extension_path(args.project)
    if args.remove:
        changed = pi.uninstall(path)
        print(f"Extension removed from {path}." if changed else f"No keyfence extension in {path}.")
        return 0
    try:
        changed = pi.install(path, args.pi_command)
    except FileExistsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    scope = "this project" if args.project else "all projects"
    if changed:
        print(f"Extension installed in {path} for {scope}.")
        print("pi will refuse to read .env files, private keys and credential files.")
        command = pi.baked_command(path)
        problem = doctor.command_problem(command)
        print(f"It calls {command}" + (f", which {problem}; fix that or run this again with --command PATH."
                                       if problem else "; keyfence doctor checks that this path stays valid."))
        if args.project:
            print("Project extensions load only once you trust the project; pi asks on startup.")
    else:
        print(f"Extension already up to date in {path}.")
    return 0


def _remove_claude_code(path: Path, force: bool) -> int:
    result = hooks.uninstall(path, force=force)
    print(f"Hook removed from {path}." if result.hook else f"No keyfence hook in {path}.")
    if result.rules:
        print(f"{result.rules} deny rule(s) removed.")
    if result.unrecorded:
        print(f"{len(result.unrecorded)} deny rule(s) in {path} match the ones keyfence installs, but there is "
              "no record of which ones keyfence added (installs before 0.5.0 kept none), so they were left in place:")
        for rule in result.unrecorded:
            print(f"  {rule}")
        print("Re-run with --remove --force to remove all of them.")
    return 0


def _list_hooks() -> int:
    for agent in AGENTS:
        print(agent)
        for scope, path, installed in doctor.installed_scopes(agent):
            print(f"  {scope:<8} {'installed' if installed else 'not installed':<14} {path}")
    return 0


def cmd_install_hooks(args) -> int:
    if args.pi_command and (args.list or args.remove or args.agent != "pi"):
        print("error: --command only applies to `install-hooks pi`", file=sys.stderr)
        return 2
    if args.list:
        if args.agent or args.project or args.remove or args.force:
            print("error: --list takes no agent and cannot be combined with --project, --remove or --force",
                  file=sys.stderr)
            return 2
        return _list_hooks()
    if not args.agent:
        print("error: install-hooks needs an agent (claude-code or pi), or --list", file=sys.stderr)
        return 2
    if args.force and not (args.remove and args.agent == "claude-code"):
        print("error: --force only applies to `install-hooks claude-code --remove`", file=sys.stderr)
        return 2
    if args.agent == "pi":
        return _install_pi(args)
    path = hooks.settings_path(args.project)
    if args.remove:
        return _remove_claude_code(path, args.force)
    changed = hooks.install(path)
    scope = "this project" if args.project else "all projects"
    if changed:
        print(f"Hook installed in {path} for {scope}.")
        print("Claude Code will refuse to read .env files, private keys and credential files.")
    else:
        print(f"Hook already present in {path}.")
    return 0


def cmd_doctor(args) -> int:
    checks = doctor.run_checks(args.port)
    print(doctor.render(checks))
    return 1 if any(c.status == doctor.FAIL for c in checks) else 0


def cmd_selftest(args) -> int:
    from . import selftest
    report = selftest.run(port=args.port, timeout=args.timeout)
    print(selftest.render(report))
    return 0 if report.ok else 1


def cmd_demo(_args) -> int:
    from . import demo
    return demo.run()


def cmd_export(args) -> int:
    cfg = Config.load()
    log = Path(cfg.audit_log)
    cursor = DEFAULT_DIR / "export.cursor"
    since = None
    if args.since:
        since = export.parse_ts(args.since)
    elif not args.all and args.otlp:
        since = export.read_cursor(cursor)
    entries = list(export.read_entries(log, since))
    if args.otlp:
        headers = dict(h.split("=", 1) for h in args.header)
        sent = export.send_otlp(args.otlp, entries, headers)
        export.write_cursor(cursor, entries)
        print(f"Sent {sent} entr{'y' if sent == 1 else 'ies'} to {args.otlp}.")
        return 0
    for entry in entries:
        print(json.dumps(entry, ensure_ascii=False))
    return 0


def cmd_status(_args) -> int:
    cfg = Config.load()
    vault = Vault()
    print(f"Mode:            {cfg.mode}")
    print(f"Hosts:           {len(cfg.hosts)} monitored"
          + (" (intercepting ALL hosts)" if cfg.intercept_all_hosts else ""))
    print(f"Vault:           {vault.count()} secret(s), {vault.canary_count()} canary(ies) in {vault.path}")
    print(f"Rules:           {len(cfg.scan.rules)} gitleaks rules"
          + ("" if cfg.scan.gitleaks else " (disabled)"))
    print(f"Entropy:         {'on' if cfg.scan.entropy_enabled else 'off'}"
          f" (min_len={cfg.scan.entropy_min_length}, threshold={cfg.scan.entropy_threshold})")
    print(f"Ignore lists:    {len(cfg.ignore_keys)} key(s), {len(cfg.ignore_values)} value(s)")
    print(f"Audit log:       {cfg.audit_log}")
    log = Path(cfg.audit_log)
    if log.exists():
        lines = log.read_text().strip().splitlines()[-5:]
        if lines:
            print("\nRecent detections:")
            for line in lines:
                try:
                    e = json.loads(line)
                    counts = Counter(f["kind"] for f in e["findings"])
                    kinds = ", ".join(
                        f"{kind} x{n}" if n > 1 else kind for kind, n in counts.most_common())
                    total = e.get("count", len(e["findings"]))
                    suffix = f"  {total} total" if total > len(e["findings"]) else ""
                    print(f"  {e['ts']}  {e['host']}  [{kinds}]{suffix}  ({e['mode']})")
                except (json.JSONDecodeError, KeyError):
                    pass
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keyfence",
        description="Local proxy that keeps your secrets out of LLM requests.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("add-secret", help="register one of your secrets in the vault (hash only)")

    p_import = sub.add_parser(
        "import", help="register secrets found in .env files, credential stores or the environment")
    p_import.add_argument("paths", nargs="*", help="files to read (default: .env* and common credential files)")
    p_import.add_argument("--env", action="store_true", help="also import values from environment variables")
    p_import.add_argument("--all", action="store_true", help="import every value, not only secret-looking ones")
    p_import.add_argument("--from", dest="source", choices=sources.SOURCES,
                          help="read from a secret manager CLI instead of files: op (1Password), vault, doppler, aws")
    p_import.add_argument("--path", help="op: vault name, strongly recommended, otherwise every item in the account is fetched one by one; "
                                         "vault, aws: secret path; doppler: project/config")

    p_canary = sub.add_parser(
        "canary", help="plant a fake secret in a file; keyfence reports if a tool ever sends it")
    p_canary.add_argument("file", nargs="?", default=".env", help="file to append to (default: .env)")
    p_canary.add_argument("--name", default="INTERNAL_API_TOKEN", help="variable name to use")

    p_scan = sub.add_parser("scan", help="test detection on text, a file or stdin")
    p_scan.add_argument("text", nargs="?", help="text to scan")
    p_scan.add_argument("-f", "--file", help="file to scan")

    p_run = sub.add_parser("run", help="start the proxy")
    p_run.add_argument("-p", "--port", type=int, default=8888,
                      help="port for the proxy (default: 8888, never a free one: run prints the port to export, "
                           "so a session that moved on its own would leave the shell pointing at the previous one; "
                           "keyfence exec picks a free port because it wires the command itself)")
    p_run.add_argument("--local", nargs="?", const="*", metavar="NAMES",
                       help="also capture traffic without proxy variables (macOS/Windows); "
                            "optional comma-separated process names, default all")

    p_exec = sub.add_parser("exec", help="run a command with the proxy already wired in")
    p_exec.add_argument("-p", "--port", type=int, default=None)
    p_exec.add_argument("--all-env", action="store_true",
                        help="treat every environment variable value as a secret, not only secret-looking names")
    p_exec.add_argument("--local", nargs="?", const="", metavar="NAMES",
                        help="also capture the command's traffic without proxy variables "
                             "(macOS/Windows); default: the command's own process name")
    p_exec.add_argument("--record", metavar="FILE",
                        help="save the raw traffic to a mitmproxy flows file "
                             "(full request bodies and headers; secrets unredacted in audit and block mode)")
    p_exec.add_argument("--linger", type=float, default=0.0, metavar="SECONDS",
                        help="keep the proxy up this long after the command exits, to see what is sent afterwards")
    p_exec.add_argument("argv", nargs=argparse.REMAINDER, metavar="command")

    p_hook = sub.add_parser("hook", help="agent hook entry point; reads the tool call from stdin")
    p_hook.add_argument("agent", choices=AGENTS)

    p_hooks = sub.add_parser("install-hooks", help="install the hook that stops an agent from reading secret files")
    p_hooks.add_argument("agent", nargs="?", choices=AGENTS)
    p_hooks.add_argument("--list", action="store_true",
                         help="show the supported agents and whether the hook is installed for each, then exit")
    p_hooks.add_argument("--project", action="store_true",
                         help="install in ./.claude or ./.pi instead of the home directory")
    p_hooks.add_argument("--remove", action="store_true", help="remove the hook")
    p_hooks.add_argument("--command", dest="pi_command", metavar="PATH",
                         help="with pi: the keyfence executable the extension calls, baked into the file "
                              "(default: the one running now); a bare name is looked up on PATH at each call")
    p_hooks.add_argument("--force", action="store_true",
                         help="with claude-code --remove: also remove every deny rule keyfence installs when "
                              "there is no record of which ones it added (installs before 0.5.0)")

    p_doctor = sub.add_parser("doctor", help="check the installation and say what is missing")
    p_doctor.add_argument("-p", "--port", type=int, default=8888,
                          help="port to check when the shell has no proxy variable; when it has one, the host and "
                               "port it names are what get checked (default: 8888)")

    p_selftest = sub.add_parser("selftest", help="start a proxy on a free port, send a throwaway secret through it "
                                                 "to a local listener and check that the configured mode was applied")
    p_selftest.add_argument("-p", "--port", type=int, default=None, help="proxy port for the test (default: a free one)")
    p_selftest.add_argument("--timeout", type=float, default=20.0, metavar="SECONDS",
                            help="how long to wait for the proxy and the addon (default: 20)")

    sub.add_parser("demo", help="show what each mode does to a fake request, without any network")

    p_export = sub.add_parser("export", help="print the audit log as JSONL or send it to an OTLP collector")
    p_export.add_argument("--since", help="only entries after this timestamp (YYYY-MM-DDTHH:MM:SS+ZZZZ)")
    p_export.add_argument("--all", action="store_true", help="ignore the export cursor")
    p_export.add_argument("--otlp", metavar="URL", help="OTLP/HTTP endpoint, e.g. http://localhost:4318")
    p_export.add_argument("--header", action="append", default=[], metavar="K=V", help="extra HTTP header")

    sub.add_parser("status", help="show configuration and recent detections")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    DEFAULT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        return _dispatch(args)
    except VaultError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _dispatch(args) -> int:
    return {
        "add-secret": cmd_add_secret,
        "import": cmd_import,
        "canary": cmd_canary,
        "scan": cmd_scan,
        "run": cmd_run,
        "exec": cmd_exec,
        "hook": cmd_hook,
        "install-hooks": cmd_install_hooks,
        "doctor": cmd_doctor,
        "selftest": cmd_selftest,
        "demo": cmd_demo,
        "export": cmd_export,
        "status": cmd_status,
    }[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
