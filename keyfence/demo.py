from __future__ import annotations

import json
import logging
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
HOST = "api.anthropic.com"


def _flow(body: str) -> http.HTTPFlow:
    return tflow.tflow(req=tutils.treq(
        host=HOST, method=b"POST", path=b"/v1/messages", content=body.encode()))


def _body() -> str:
    return json.dumps({
        "model": "claude-fable-5-1",
        "system": "You are a coding agent.",
        "messages": [{"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_01DemoDemoDemoDemoDemoDemo",
             "content": f"GITHUB_TOKEN={DEMO_TOKEN}\nDB_PASSWORD={DEMO_PASSWORD}\n"},
            {"type": "text", "text": "Read .env and use the token to push."},
        ]}],
    })


def _content(body: str) -> str:
    return json.loads(body)["messages"][0]["content"][0]["content"].rstrip("\n")


def run(out=None) -> int:
    from .addon import KeyFence, MAPPING_KEY

    write = (out or sys.stdout).write
    logging.getLogger("keyfence").disabled = True
    with tempfile.TemporaryDirectory() as tmp:
        vault = Vault(path=Path(tmp) / "vault.json")
        vault.add(DEMO_PASSWORD)
        rules = load_rules()
        original = _body()
        write("A request from a coding agent to api.anthropic.com. The tool result it carries:\n\n")
        write("    " + _content(original).replace("\n", "\n    ") + "\n\n")
        write(f"The token has a known format. The password does not, but it was registered with keyfence import.\n\n")

        for mode in ("audit", "redact", "placeholder", "block"):
            cfg = Config(mode=mode, audit_log=Path(tmp) / "audit.log")
            cfg.scan.rules = rules
            fence = KeyFence(config=cfg, vault=vault)
            flow = _flow(original)
            fence.request(flow)
            write(f"mode: {mode}\n")
            if mode == "block":
                write(f"    provider receives nothing; the client gets HTTP {flow.response.status_code}:\n")
                write("    " + json.loads(flow.response.get_text())["error"]["message"] + "\n\n")
                continue
            sent = _content(flow.request.get_text())
            write("    provider receives:\n    " + sent.replace("\n", "\n    ") + "\n")
            if mode == "placeholder":
                mapping = flow.metadata[MAPPING_KEY]
                token = next(t for t, v in mapping.items() if v == DEMO_TOKEN)
                flow.response = tutils.tresp(
                    headers=http.Headers([(b"content-type", b"application/json")]),
                    content=json.dumps({"content": [{"type": "text", "text": f"git push https://{token}@github.com/you/repo"}]}).encode())
                fence.response(flow)
                reply = json.loads(flow.response.get_text())["content"][0]["text"]
                write("    model answers with the placeholder; the client receives:\n    " + reply + "\n")
            write("\n")

        entries = [json.loads(l) for l in (Path(tmp) / "audit.log").read_text().splitlines()]
        kinds = sorted({f["kind"] for e in entries for f in e["findings"]})
        write(f"Every run above was recorded in the audit log: {len(entries)} entries, kinds {', '.join(kinds)}, "
              "previews only, never the values.\n")
        write("\nTry it for real: keyfence import, then keyfence exec -- claude\n")
    logging.getLogger("keyfence").disabled = False
    return 0
