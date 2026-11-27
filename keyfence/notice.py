from __future__ import annotations

import json

_PREAMBLE = (
    "Note from keyfence, a local proxy on the user's machine: before this request "
    "reached you, keyfence replaced secrets such as API keys and passwords with "
    "{tokens} tokens. This is expected and configured by the user. It is not tampering "
    "and not a sign that files or credentials were compromised, so do not warn the user "
    "about it and do not suggest rotating credentials because of it. "
)
NOTICES = {
    "redact": _PREAMBLE.format(tokens="[REDACTED:<kind>]") + (
        "The real values are not restored: never write these tokens into code, files or "
        "commands as if they were the value. Where a value is needed, reference it the way "
        "the project already does, for example an environment variable, or ask the user."
    ),
    "placeholder": _PREAMBLE.format(tokens="<<SECRET_id>>") + (
        "If you need one of these values in code or commands, write the token exactly as "
        "shown; the real value is restored automatically on the way back."
    ),
}


ANTHROPIC_HOSTS = ("anthropic.com",)
BEDROCK_HOSTS = ("amazonaws.com",)
SYSTEM_ROLES = ("system", "developer")


def _append_text(value, text: str):
    if isinstance(value, str):
        return f"{value}\n\n{text}" if value else text
    if isinstance(value, list):
        if value and all(isinstance(block, dict) and "type" not in block for block in value):
            return [*value, {"text": text}]
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


def add_notice(body: str, host: str, mode: str = "redact", path: str = "") -> str:
    text = NOTICES[mode]
    try:
        obj = json.loads(body)
    except ValueError:
        return body
    if not isinstance(obj, dict):
        return body
    host = host.lower()
    path = path.split("?", 1)[0].lower()
    messages = obj.get("messages")
    if path.endswith(("/converse", "/converse-stream")):
        system = obj.get("system", [])
        if not isinstance(system, list):
            return body
        obj["system"] = [*system, {"text": text}]
    elif ("system" in obj or "anthropic_version" in obj or "/publishers/anthropic/" in path
          or (_is_host(host, ANTHROPIC_HOSTS) and isinstance(messages, list))):
        obj["system"] = _append_text(obj.get("system", ""), text)
    elif "instructions" in obj and isinstance(obj["instructions"], str):
        obj["instructions"] = _append_text(obj["instructions"], text)
    elif "systemInstruction" in obj or isinstance(obj.get("contents"), list):
        instruction = obj.get("systemInstruction") or {"parts": []}
        parts = instruction.get("parts")
        if not isinstance(parts, list):
            return body
        instruction["parts"] = [*parts, {"text": text}]
        obj["systemInstruction"] = instruction
    elif isinstance(messages, list) and not _is_host(host, BEDROCK_HOSTS):
        obj["messages"] = _with_system(messages, text)
    else:
        return body
    return json.dumps(obj, ensure_ascii=False).encode("utf-8", "backslashreplace").decode("utf-8")
