from __future__ import annotations

import argparse
import getpass
from collections import Counter
import json
import os
import subprocess
import sys
from pathlib import Path

from . import runner
from .config import Config
from .detectors import scan
from .importer import default_paths, env_values, import_files
from .vault import DEFAULT_DIR, Vault


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
    print("Point your tools at it, e.g.:")
    print(f"  export HTTPS_PROXY=http://127.0.0.1:{args.port}")
    print(f"  export HTTP_PROXY=http://127.0.0.1:{args.port}")
    print("or run them through it directly: keyfence exec -- <command>")
    print("(Ctrl+C to stop)\n")
    try:
        return subprocess.call(runner.proxy_command(args.port))
    except FileNotFoundError:
        print("mitmdump not found. Install it with: pip install mitmproxy")
        return 1


def cmd_exec(args) -> int:
    command = list(args.argv)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("usage: keyfence exec [-p PORT] [--all-env] -- <command> [args...]")
        return 1
    return runner.run(command, args.port, everything=args.all_env)


def cmd_status(_args) -> int:
    cfg = Config.load()
    vault = Vault()
    print(f"Mode:            {cfg.mode}")
    print(f"Hosts:           {len(cfg.hosts)} monitored"
          + (" (intercepting ALL hosts)" if cfg.intercept_all_hosts else ""))
    print(f"Vault:           {vault.count()} secret(s) in {vault.path}")
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

    p_scan = sub.add_parser("scan", help="test detection on text, a file or stdin")
    p_scan.add_argument("text", nargs="?", help="text to scan")
    p_scan.add_argument("-f", "--file", help="file to scan")

    p_run = sub.add_parser("run", help="start the proxy")
    p_run.add_argument("-p", "--port", type=int, default=8888)

    p_exec = sub.add_parser("exec", help="run a command with the proxy already wired in")
    p_exec.add_argument("-p", "--port", type=int, default=8888)
    p_exec.add_argument("--all-env", action="store_true",
                        help="treat every environment variable value as a secret, not only secret-looking names")
    p_exec.add_argument("argv", nargs=argparse.REMAINDER, metavar="command")

    sub.add_parser("status", help="show configuration and recent detections")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    DEFAULT_DIR.mkdir(parents=True, exist_ok=True)
    return {
        "add-secret": cmd_add_secret,
        "import": cmd_import,
        "scan": cmd_scan,
        "run": cmd_run,
        "exec": cmd_exec,
        "status": cmd_status,
    }[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
