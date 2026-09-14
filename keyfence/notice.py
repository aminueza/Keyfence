from __future__ import annotations

import json

NOTICE = (
    "Note from keyfence, a local proxy on the user's machine: before this request "
    "reached you, keyfence replaced secrets such as API keys and passwords with "
    "[REDACTED:<kind>] or <<SECRET_id>> tokens. This is expected and configured by the "
    "user. It is not tampering and not a sign that files or credentials were "
    "compromised, so do not warn the user about it and do not suggest rotating "
    "credentials because of it. If you need one of these values in code or commands, "
    "write the token exactly as shown; the real value is restored automatically on "
    "the way back."
)

ANTHROPIC_HOSTS = ("anthropic.com", "amazonaws.com")
GEMINI_HOSTS = ("googleapis.com",)
SYSTEM_ROLES = ("system", "developer")


def _append_text(value, text: str):
    if isinstance(value, str):
        return f"{value}\n\n{text}" if value else text
    if isinstance(value, list):
        return [*value, {"type": "text", "text": text}]
    return value


def _is_host(host: str, suffixes: tuple[str, ...]) -> bool:
    return any(host == s or host.endswith("." + s) for s in suffixes)


def _with_system(messages: list, text: str) -> list:
    first = messages[0] if messages else None
    if (isinstance(first, dict) and first.get("role") in SYSTEM_ROLES
            and isinstance(first.get("content"), (str, list))):
        return [{**first, "content": _append_text(first["content"], text)}, *messages[1:]]
    return [{"role": "system", "content": text}, *messages]


def add_notice(body: str, host: str, text: str = NOTICE) -> str:
    try:
        obj = json.loads(body)
    except ValueError:
        return body
    if not isinstance(obj, dict):
        return body
    host = host.lower()
    if "system" in obj or _is_host(host, ANTHROPIC_HOSTS):
        obj["system"] = _append_text(obj.get("system", ""), text)
    elif "instructions" in obj and isinstance(obj["instructions"], str):
        obj["instructions"] = _append_text(obj["instructions"], text)
    elif "systemInstruction" in obj or _is_host(host, GEMINI_HOSTS):
        instruction = obj.get("systemInstruction") or {"parts": []}
        parts = instruction.get("parts")
        if not isinstance(parts, list):
            return body
        instruction["parts"] = [*parts, {"text": text}]
        obj["systemInstruction"] = instruction
    elif isinstance(obj.get("messages"), list):
        obj["messages"] = _with_system(obj["messages"], text)
    else:
        return body
    return json.dumps(obj, ensure_ascii=False)
