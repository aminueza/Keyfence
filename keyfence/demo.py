from __future__ import annotations

import json
import logging
import os
import re
import sys
import tempfile
from pathlib import Path

from mitmproxy import http
from mitmproxy.test import tflow, tutils

from .config import Config
from .rules import load_rules
from .vault import Vault

DEMO_TOKEN = "ghp_" + "DemoDemoDemoDemoDemoDemoDemoDemo1234"
DEMO_PASSWORD = "correct-horse-battery-staple-2026"
HOST = "api.provider.example"
MODES = (
    ("audit", "watch first, change nothing"),
    ("redact", "the default: the values are cut out"),
    ("placeholder", "the model works with tokens, you get the values back"),
    ("block", "nothing leaves the machine"),
)
INDENT = "    "
CODES = {"title": "1", "mode": "1", "dim": "2", "secret": "31", "safe": "32"}
HIGHLIGHT = re.compile(
    r"\[REDACTED:[a-z-]+\]|<<SECRET_[0-9a-f]+>>|HTTP 403|" + "|".join(map(re.escape, (DEMO_TOKEN, DEMO_PASSWORD))))
TOOL_RESULT = f"GITHUB_TOKEN={DEMO_TOKEN}\nDB_PASSWORD={DEMO_PASSWORD}\n"


def _flow(body: str) -> http.HTTPFlow:
    return tflow.tflow(req=tutils.treq(
        host=HOST, method=b"POST", path=b"/v1/chat/completions", content=body.encode()))


def _body() -> str:
    return json.dumps({
        "model": "demo-model",
        "messages": [
            {"role": "system", "content": "You are a coding agent."},
            {"role": "tool", "tool_call_id": "call_demo", "content": TOOL_RESULT},
            {"role": "user", "content": "Read .env and use the token to push."},
        ],
    })


def _content(body: str) -> str:
    messages = json.loads(body)["messages"]
    tool = next(m for m in messages if m.get("role") == "tool")
    return tool["content"].rstrip("\n")


def _reply(text: str) -> bytes:
    return json.dumps({"choices": [{"message": {"role": "assistant", "content": text}}]}).encode()


def _answer(flow: http.HTTPFlow) -> str:
    return json.loads(flow.response.get_text())["choices"][0]["message"]["content"]


def wants_colour(out, environ=os.environ) -> bool:
    if environ.get("NO_COLOR") or environ.get("TERM") == "dumb":
        return False
    return bool(getattr(out, "isatty", lambda: False)())


def lines() -> list[tuple[str, str]]:
    logging.getLogger("keyfence").disabled = True
    try:
        with tempfile.TemporaryDirectory() as tmp:
            return _lines(Path(tmp))
    finally:
        logging.getLogger("keyfence").disabled = False


def _lines(tmp: Path) -> list[tuple[str, str]]:
    from .addon import KeyFence, MAPPING_KEY

    vault = Vault(path=tmp / "vault.json")
    vault.add(DEMO_PASSWORD)
    rules = load_rules()
    original = _body()
    out: list[tuple[str, str]] = [
        ("title", "keyfence demo"),
        ("blank", ""),
        ("text", "Your coding agent just read .env to finish a task. This is the tool result"),
        ("text", "it is about to send to the model provider:"),
        ("blank", ""),
        *(("body", INDENT + line) for line in _content(original).splitlines()),
        ("blank", ""),
        ("text", "The token has a known format, so the built-in rules catch it. The password"),
        ("text", "could be anything, so it was registered with keyfence import, as a hash."),
        ("text", "Here is what leaves the machine in each mode."),
        ("blank", ""),
    ]
    for mode, description in MODES:
        cfg = Config(mode=mode, audit_log=tmp / "audit.log")
        cfg.hosts.append(HOST)
        cfg.scan.rules = rules
        fence = KeyFence(config=cfg, vault=vault)
        flow = _flow(original)
        fence.request(flow)
        out.append(("mode", f"{mode}\t{description}"))
        if mode == "block":
            out.append(("dim", INDENT + f"your agent gets HTTP {flow.response.status_code}, the provider gets nothing:"))
            out.append(("body", INDENT + json.loads(flow.response.get_text())["error"]["message"]))
            out.append(("blank", ""))
            continue
        out.extend(("body", INDENT + line) for line in _content(flow.request.get_text()).splitlines())
        if mode == "audit":
            out.append(("dim", INDENT + "both values went through unchanged; the audit log has the entry"))
        if mode == "placeholder":
            mapping = flow.metadata[MAPPING_KEY]
            token = next(t for t, v in mapping.items() if v == DEMO_TOKEN)
            flow.response = tutils.tresp(
                headers=http.Headers([(b"content-type", b"application/json")]),
                content=_reply(f"git push https://{token}@github.com/you/repo"))
            fence.response(flow)
            out.append(("dim", INDENT + f"the model answers with the token: git push https://{token}@github.com/you/repo"))
            out.append(("dim", INDENT + "your agent receives the real value:"))
            out.append(("body", INDENT + _answer(flow)))
        out.append(("blank", ""))
    entries = [json.loads(line) for line in (tmp / "audit.log").read_text().splitlines()]
    kinds = sorted({f["kind"] for e in entries for f in e["findings"]})
    out.extend([
        ("text", f"Every run above was written to the audit log: {len(entries)} entries, kinds"),
        ("text", f"{' and '.join(kinds)}, masked previews only, never a value."),
        ("blank", ""),
        ("text", "Next:"),
        ("text", INDENT + "keyfence import              register your own secrets, hashes only"),
        ("text", INDENT + "keyfence exec -- <agent>     run any coding agent through the proxy"),
        ("text", INDENT + "keyfence selftest            prove the proxy works on this machine"),
    ])
    return out


def _paint(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def _highlight(text: str, base: str | None = None) -> str:
    out: list[str] = []
    pos = 0
    for m in HIGHLIGHT.finditer(text):
        plain = text[pos:m.start()]
        out.append(_paint(plain, base) if base and plain else plain)
        token = m.group()
        code = CODES["secret"] if token in (DEMO_TOKEN, DEMO_PASSWORD, "HTTP 403") else CODES["safe"]
        out.append(_paint(token, code))
        pos = m.end()
    rest = text[pos:]
    out.append(_paint(rest, base) if base and rest else rest)
    return "".join(out)


def render(items: list[tuple[str, str]], styled: bool) -> str:
    rendered: list[str] = []
    for kind, text in items:
        if kind == "mode":
            name, description = text.split("\t", 1)
            line = f"{name:<12} {description}"
            if styled:
                line = f"{_paint(f'{name:<12}', CODES['mode'])} {_paint(description, CODES['dim'])}"
        elif not styled:
            line = text
        elif kind == "title":
            line = _paint(text, CODES["title"])
        elif kind == "dim":
            line = _highlight(text, CODES["dim"])
        elif kind == "body":
            line = _highlight(text)
        else:
            line = text
        rendered.append(line)
    return "\n".join(rendered) + "\n"


def run(out=None) -> int:
    out = out or sys.stdout
    out.write(render(lines(), wants_colour(out)))
    return 0
