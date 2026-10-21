from __future__ import annotations

import io
import json
import sys

AGENTS = ("claude-code", "pi")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args[:1] == ["hook"]:
        if len(args) != 2 or args[1] not in AGENTS:
            print(f"unknown agent: {' '.join(args[1:]) or '(none)'}", file=sys.stderr)
            return 1
        agent = args[1]
        if agent == "claude-code":
            text = sys.stdin.read()
            try:
                payload = json.loads(text)
            except ValueError:
                payload = None
            if isinstance(payload, dict) and payload.get("hook_event_name") == "UserPromptSubmit":
                from .prompt import run as run_prompt
                return run_prompt(stdin=io.StringIO(text))
            from .hooks import run_hook
            return run_hook(stdin=io.StringIO(text))
        from .hooks import run_hook
        return run_hook()
    from .cli import main as cli_main
    return cli_main(args)
