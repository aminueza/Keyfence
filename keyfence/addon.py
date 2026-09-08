from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path

_PKG_PARENT = str(Path(__file__).resolve().parent.parent)
if _PKG_PARENT not in sys.path:
    sys.path.insert(0, _PKG_PARENT)

from mitmproxy import http  # noqa: E402

from keyfence.config import Config  # noqa: E402
from keyfence.detectors import Finding, scan  # noqa: E402
from keyfence.streaming import SSERestorer, restore  # noqa: E402
from keyfence.vault import Vault  # noqa: E402

log = logging.getLogger("keyfence")
ENV_VAULT_VAR = "KEYFENCE_ENV_VAULT"
MAPPING_KEY = "keyfence_mapping"
STREAMED_KEY = "keyfence_streamed"


class KeyFence:
    def __init__(self):
        self.config = Config.load()
        self.vault = self._load_vault()
        self._vault_mtime = self._mtime(self.vault.path)
        self.stats = {"scanned": 0, "findings": 0, "blocked": 0, "errors": 0}

    @staticmethod
    def _mtime(path: Path) -> float:
        try:
            return Path(path).stat().st_mtime
        except OSError:
            return 0.0

    def _load_vault(self) -> Vault:
        vault = Vault()
        extra = os.environ.get(ENV_VAULT_VAR)
        if extra and Path(extra).exists():
            vault.merge(Vault(path=Path(extra)))
        return vault

    def _maybe_reload_vault(self) -> None:
        mtime = self._mtime(self.vault.path)
        if mtime != self._vault_mtime:
            self.vault = self._load_vault()
            self._vault_mtime = mtime
            log.info("vault reloaded: %d secret(s)", self.vault.count())

    def load(self, loader):
        log.info("mode=%s | %d hosts monitored | %d rules | vault with %d secret(s)",
                 self.config.mode, len(self.config.hosts),
                 len(self.config.scan.rules), self.vault.count())

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        if not self.config.host_matches(host):
            return
        try:
            self._inspect(flow, host)
        except Exception as exc:
            self.stats["errors"] += 1
            log.error("detector failure, failing closed for %s: %r", host, exc)
            flow.response = self._blocked_response(
                f"keyfence internal error ({type(exc).__name__}); request not sent.")

    def _inspect(self, flow: http.HTTPFlow, host: str) -> None:
        text = flow.request.get_text(strict=False)
        if not text:
            return
        self._maybe_reload_vault()
        self.stats["scanned"] += 1
        findings = scan(text, vault=self.vault, config=self.config.scan)
        if not findings:
            return

        self.stats["findings"] += len(findings)
        self._audit(flow, findings)

        if self.config.mode == "block":
            self.stats["blocked"] += 1
            kinds = sorted({f.kind for f in findings})
            flow.response = self._blocked_response(
                f"Request blocked by keyfence: {len(findings)} secret(s) detected "
                f"({', '.join(kinds)}). Nothing was sent to the provider.")
            log.warning("BLOCKED -> %s: %d secret(s)", host, len(findings))
            return

        mapping: dict[str, str] = {}
        new_text = text
        ordered = sorted(findings, key=lambda f: f.start)
        for index, f in reversed(list(enumerate(ordered, start=1))):
            if self.config.mode == "placeholder":
                token = f"<<SECRET_{index}>>"
                mapping[token] = f.value
            else:
                token = f"[REDACTED:{f.kind}]"
            new_text = new_text[:f.start] + token + new_text[f.end:]

        flow.request.set_text(new_text)
        if mapping:
            flow.metadata[MAPPING_KEY] = mapping
            flow.request.headers["accept-encoding"] = "identity"
        log.warning("%s -> %s: %d secret(s) removed from request",
                    self.config.mode.upper(), host, len(findings))

    @staticmethod
    def _blocked_response(message: str) -> http.Response:
        return http.Response.make(
            403,
            json.dumps({"error": {"type": "keyfence_blocked", "message": message}},
                       ensure_ascii=False),
            {"Content-Type": "application/json"},
        )

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        mapping = flow.metadata.get(MAPPING_KEY)
        if not mapping:
            flow.response.stream = True
            return
        content_type = flow.response.headers.get("content-type", "")
        encoding = flow.response.headers.get("content-encoding", "identity")
        if "text/event-stream" in content_type and encoding in ("identity", ""):
            flow.response.stream = SSERestorer(mapping).feed
            flow.metadata[STREAMED_KEY] = True

    def response(self, flow: http.HTTPFlow) -> None:
        mapping = flow.metadata.get(MAPPING_KEY)
        if not mapping or flow.metadata.get(STREAMED_KEY) or flow.response is None:
            return
        text = flow.response.get_text(strict=False)
        if not text:
            return
        restored = restore(text, mapping)
        if restored != text:
            flow.response.set_text(restored)
            log.info("placeholders restored in response")

    def _audit(self, flow: http.HTTPFlow, findings: list[Finding]) -> None:
        try:
            path = Path(self.config.audit_log)
            path.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "host": flow.request.pretty_host,
                "path": flow.request.path.split("?")[0],
                "mode": self.config.mode,
                "findings": [{"kind": f.kind, "preview": f.masked} for f in findings],
            }
            with path.open("a") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError as exc:
            log.warning("could not write audit log: %s", exc)


addons = [KeyFence()]
