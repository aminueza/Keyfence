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

from . import doctor, export, hooks, runner, sources
from .config import Config
from .detectors import scan
from .importer import default_paths, env_values, import_files, looks_secret
from .vault import DEFAULT_DIR, Vault, VaultError


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
    if args.source:
        if args.paths or args.env:
            print("error: --from cannot be combined with file paths or --env; run them as separate commands", file=sys.stderr)
            return 2
        try:
            pairs = sources.fetch(args.source, args.path)
        except sources.SourceError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        values = [v for k, v in pairs if args.all or looks_secret(k, v, vault.min_length)]
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
    for path, added in import_files(vault, paths, everything=args.all):
        total += added
        print(f"{path}: {added} new secret(s)")
    if args.env:
        added = vault.add_many(env_values(os.environ, vault.min_length, everything=args.all))
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
    findings = scan(text, vault=Vault(), config=cfg.scan)
    if not findings:
        print("No secrets detected.")
        return 0
    print(f"{len(findings)} secret(s) detected:")
    for f in findings:
        where = f" in \"{f.key}\"" if f.key else ""
        print(f"  - [{f.kind}] {f.masked} (offset {f.start}-{f.end}{where})")
    return 2


def cmd_run(args) -> int:
    print(f"Starting keyfence on http://127.0.0.1:{args.port}")
    if args.local is not None:
        target = "all processes" if args.local in ("", "*") else f"processes named {args.local}"
        print(f"Local capture on for {target}: no proxy variables needed, "
              "but the CA certificate must be trusted system-wide.")
    print("Point your tools at it, e.g.:")
    print(f"  export HTTPS_PROXY=http://127.0.0.1:{args.port}")
    print(f"  export HTTP_PROXY=http://127.0.0.1:{args.port}")
    print("or run them through it directly: keyfence exec -- <command>")
    if runner.port_open(args.port):
        print(f"Port {args.port} is already in use. Pick another one with -p.")
        return 1
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


def cmd_hook(args) -> int:
    if args.agent != "claude-code":
        print(f"unknown agent: {args.agent}")
        return 1
    return hooks.run_hook()


def cmd_install_hooks(args) -> int:
    if args.agent != "claude-code":
        print(f"unknown agent: {args.agent}")
        return 1
    path = hooks.settings_path(args.project)
    if args.remove:
        changed = hooks.uninstall(path)
        print(f"Hook removed from {path}." if changed else f"No keyfence hook in {path}.")
        return 0
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
    p_run.add_argument("-p", "--port", type=int, default=8888)
    p_run.add_argument("--local", nargs="?", const="*", metavar="NAMES",
                       help="also capture traffic without proxy variables (macOS/Windows); "
                            "optional comma-separated process names, default all")

    p_exec = sub.add_parser("exec", help="run a command with the proxy already wired in")
    p_exec.add_argument("-p", "--port", type=int, default=8888)
    p_exec.add_argument("--all-env", action="store_true",
                        help="treat every environment variable value as a secret, not only secret-looking names")
    p_exec.add_argument("--local", nargs="?", const="", metavar="NAMES",
                        help="also capture the command's traffic without proxy variables "
                             "(macOS/Windows); default: the command's own process name")
    p_exec.add_argument("--record", metavar="FILE",
                        help="save the raw traffic to a mitmproxy flows file (contains full request and response bodies)")
    p_exec.add_argument("--linger", type=float, default=0.0, metavar="SECONDS",
                        help="keep the proxy up this long after the command exits, to see what is sent afterwards")
    p_exec.add_argument("argv", nargs=argparse.REMAINDER, metavar="command")

    p_hook = sub.add_parser("hook", help="agent hook entry point; reads the tool call from stdin")
    p_hook.add_argument("agent", choices=["claude-code"])

    p_hooks = sub.add_parser("install-hooks", help="install the hook that stops an agent from reading secret files")
    p_hooks.add_argument("agent", choices=["claude-code"])
    p_hooks.add_argument("--project", action="store_true", help="install in ./.claude instead of ~/.claude")
    p_hooks.add_argument("--remove", action="store_true", help="remove the hook")

    p_doctor = sub.add_parser("doctor", help="check the installation and say what is missing")
    p_doctor.add_argument("-p", "--port", type=int, default=8888)

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
        "demo": cmd_demo,
        "export": cmd_export,
        "status": cmd_status,
    }[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
