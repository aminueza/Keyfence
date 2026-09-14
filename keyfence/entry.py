from __future__ import annotations

import sys

AGENTS = ("claude-code", "pi")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args[:1] == ["hook"]:
        from .hooks import run_hook
        if len(args) != 2 or args[1] not in AGENTS:
            print(f"unknown agent: {' '.join(args[1:]) or '(none)'}", file=sys.stderr)
            return 1
        return run_hook()
    from .cli import main as cli_main
    return cli_main(args)
