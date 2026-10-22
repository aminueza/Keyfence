from __future__ import annotations

import io
import json
import sys

AGENTS = ("claude-code", "pi")
HELP_FLAGS = ("-h", "--help")


def _block(reason: str) -> int:
    print(json.dumps({"decision": "block", "reason": reason,
                      "hookSpecificOutput": {"hookEventName": "UserPromptSubmit",
                                             "suppressOriginalPrompt": True}}))
    return 0


def _read_stdin() -> str | None:
    # Claude Code sends UTF-8, but sys.stdin decodes with the locale codec,
    # an ANSI code page on Windows that raises on valid UTF-8 (cp1252 chokes
    # on the bytes of U+1F44D). Refusing there would block every prompt, so
    # read the bytes and decode them explicitly; undecodable input stays
    # fail-closed through run_hook().
    stream = getattr(sys.stdin, "buffer", None)
    try:
        data = stream.read() if stream is not None else sys.stdin.read()
    except BaseException:
        return None  # run_hook() reads stdin itself and refuses with exit 2
    if isinstance(data, bytes):
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return None
    return data


def _is_prompt_event(text: str) -> bool:
    try:
        payload = json.loads(text)
    except Exception:  # ValueError, RecursionError: run_hook reports it as before
        return False
    return isinstance(payload, dict) and payload.get("hook_event_name") == "UserPromptSubmit"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args[:1] == ["hook"] and not any(arg in HELP_FLAGS for arg in args[1:]):
        if len(args) != 2 or args[1] not in AGENTS:
            print(f"unknown agent: {' '.join(args[1:]) or '(none)'}", file=sys.stderr)
            return 1
        if args[1] == "claude-code":
            text = _read_stdin()
            if text is not None and _is_prompt_event(text):
                try:
                    from .prompt import run as run_prompt
                except BaseException as exc:  # a broken install must not pass the prompt
                    return _block(f"keyfence blocked this prompt because its guard crashed: {type(exc).__name__}")
                return run_prompt(stdin=io.StringIO(text))
            from .hooks import run_hook
            return run_hook(stdin=io.StringIO(text)) if text is not None else run_hook()
        from .hooks import run_hook
        return run_hook()
    from .cli import main as cli_main
    return cli_main(args)
