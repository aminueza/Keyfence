from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args[:1] == ["hook"]:
        from .hooks import run_hook
        if args[1:] != ["claude-code"]:
            print(f"unknown agent: {' '.join(args[1:]) or '(none)'}", file=sys.stderr)
            return 1
        return run_hook()
    from .cli import main as cli_main
    return cli_main(args)
