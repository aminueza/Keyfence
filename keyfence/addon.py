from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from bisect import bisect_right
from pathlib import Path

_PKG_PARENT = str(Path(__file__).resolve().parent.parent)
if _PKG_PARENT not in sys.path:
    sys.path.insert(0, _PKG_PARENT)

from mitmproxy import http  # noqa: E402
from mitmproxy.websocket import WebSocketMessage  # noqa: E402

from keyfence import __version__  # noqa: E402
from keyfence.config import Config  # noqa: E402
from keyfence.detectors import Finding, ScanReport, scan_report  # noqa: E402
from keyfence.ignore import IgnoreList  # noqa: E402
from keyfence.notice import add_notice  # noqa: E402
from keyfence.runner import PROBE_HOST  # noqa: E402
from keyfence.streaming import SSERestorer, restore  # noqa: E402
from keyfence.vault import Vault, VaultError  # noqa: E402

log = logging.getLogger("keyfence")
ENV_VAULT_VAR = "KEYFENCE_ENV_VAULT"
MAPPING_KEY = "keyfence_mapping"
STREAMED_KEY = "keyfence_streamed"
AUDIT_PREVIEW_LIMIT = 50
PLACEHOLDER_ID_LENGTH = 10
_JSON_ESCAPE = re.compile(r"\\(?:u[0-9a-fA-F]{4}|.)", re.DOTALL)
SIGV4_PREFIX = "AWS4-"
SIGV4_QUERY = "X-Amz-Signature"


def is_sigv4_signed(request: http.Request) -> bool:
    return (request.headers.get("authorization", "").startswith(SIGV4_PREFIX)
            or SIGV4_QUERY in request.query)


def parses_as_json(text: str) -> bool:
    try:
        json.loads(text)
    except ValueError:
        return False
    return True


def json_escapes(text: str) -> tuple[list[int], list[int]]:
    starts: list[int] = []
    ends: list[int] = []
    for m in _JSON_ESCAPE.finditer(text):
        starts.append(m.start())
        ends.append(m.end())
    return starts, ends


def whole_escapes(start: int, end: int, escapes: tuple[list[int], list[int]]) -> tuple[int, int]:
    starts, ends = escapes
    i = bisect_right(starts, start) - 1
    if i >= 0 and starts[i] < start < ends[i]:
        start = starts[i]
    j = bisect_right(starts, end) - 1
    if j >= 0 and starts[j] < end < ends[j]:
        end = ends[j]
    return start, end


class KeyFence:
    def __init__(self, config: Config | None = None, vault: Vault | None = None):
        self.config = config
        self.vault = vault
        self.ignore = IgnoreList()
        self._fixed = config is not None or vault is not None
        self._config_path = Config.path()
        self._config_mtime = 0.0
        self._vault_mtime = 0.0
        self._env_vault = None
        self.stats = {"scanned": 0, "findings": 0, "suppressed": 0, "blocked": 0, "errors": 0, "canaries": 0}
        if self._fixed:
            self._setup()

    def _setup(self) -> None:
        if self.config is None:
            self._config_path = Config.path()
            self.config = Config.load()
            self._config_mtime = self._mtime(self._config_path)
        if self.vault is None:
            self.vault = self._load_vault()
            self._vault_mtime = self._mtime(self.vault.path)
        self._refresh_ignore()

    def _refresh_ignore(self) -> None:
        self.ignore = self.config.ignore_list(self.vault)

    @staticmethod
    def _mtime(path: Path) -> float:
        try:
            return Path(path).stat().st_mtime
        except OSError:
            return 0.0

    def _load_vault(self) -> Vault:
        vault = Vault()
        vault.ensure_saved()
        if self._env_vault is None:
            self._env_vault = self._consume_env_vault()
        if self._env_vault is not None:
            vault.merge(self._env_vault)
        return vault

    @staticmethod
    def _consume_env_vault() -> Vault | None:
        extra = os.environ.get(ENV_VAULT_VAR)
        if not extra or not Path(extra).exists():
            return None
        env_vault = Vault(path=Path(extra))
        env_vault.remove_files()
        return env_vault

    def _maybe_reload_vault(self) -> None:
        if self._fixed:
            return
        mtime = self._mtime(self.vault.path)
        if mtime != self._vault_mtime:
            self.vault = self._load_vault()
            self._vault_mtime = mtime
            self._refresh_ignore()
            log.info("vault reloaded: %d secret(s)", self.vault.count())

    def _maybe_reload_config(self) -> None:
        if self._fixed:
            return
        mtime = self._mtime(self._config_path)
        if mtime == self._config_mtime:
            return
        self._config_mtime = mtime
        if not self._config_path.exists() or self._config_path.stat().st_size == 0:
            log.warning("config file %s is missing or empty, keeping the previous configuration",
                        self._config_path)
            return
        try:
            self.config = Config.load()
            self._refresh_ignore()
            log.info("config reloaded: mode=%s | %d hosts | %d rules | ignoring %d key(s), %d value(s)",
                     self.config.mode, len(self.config.hosts), len(self.config.scan.rules),
                     self.ignore.key_count, self.ignore.value_count)
        except Exception as exc:
            log.error("config reload failed, keeping the previous one: %s", exc)

    def load(self, loader):
        try:
            self._setup()
        except VaultError as exc:
            print(f"keyfence: {exc}", file=sys.stderr, flush=True)
            os._exit(1)
        log.warning("keyfence %s: mode=%s | %d hosts monitored | %d rules | vault with %d secret(s)",
                    __version__, self.config.mode, len(self.config.hosts),
                    len(self.config.scan.rules), self.vault.count())

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        try:
            self._setup()
            self._maybe_reload_config()
            if host == PROBE_HOST:
                flow.response = self._probe_response()
                return
            if not self.config.host_matches(host):
                return
            self._inspect(flow, host)
        except Exception as exc:
            self.stats["errors"] += 1
            log.error("detector failure, failing closed for %s: %r", host, exc)
            flow.response = self._blocked_response(
                f"keyfence internal error ({type(exc).__name__}); request not sent.")

    def _probe_response(self) -> http.Response:
        body = {"keyfence": __version__, "mode": self.config.mode, "hosts": len(self.config.hosts)}
        return http.Response.make(200, json.dumps(body), {"Content-Type": "application/json"})

    def _scan(self, text: str, host: str) -> ScanReport:
        self._maybe_reload_vault()
        self.stats["scanned"] += 1
        report = scan_report(text, vault=self.vault, config=self.config.scan, ignore=self.ignore)
        if report.suppressed:
            self.stats["suppressed"] += report.suppressed
            log.info("%d finding(s) ignored by config for %s", report.suppressed, host)
        return report

    def _record(self, flow: http.HTTPFlow, findings: list[Finding], suppressed: int, host: str,
                websocket: bool = False) -> None:
        self.stats["findings"] += len(findings)
        self._audit(flow, findings, suppressed, websocket)
        tripped = sorted({self.vault.canary_label(f.value) for f in findings if f.kind == "canary"})
        if tripped:
            self.stats["canaries"] += len(tripped)
            log.warning("CANARY tripped -> %s: %s was read and sent", host, ", ".join(tripped))

    def _rewrite(self, text: str, findings: list[Finding], mapping: dict[str, str]) -> str | None:
        was_json = parses_as_json(text)
        escapes = json_escapes(text) if was_json else None
        new_text = text
        for f in sorted(findings, key=lambda f: f.start, reverse=True):
            if self.config.mode == "placeholder":
                token = self._placeholder(f.value, mapping)
                mapping[token] = f.value
            else:
                token = f"[REDACTED:{f.kind}]"
            start, end = (f.start, f.end) if escapes is None else whole_escapes(f.start, f.end, escapes)
            new_text = new_text[:start] + token + new_text[end:]
        if was_json and not parses_as_json(new_text):
            return None
        return new_text

    def _inspect(self, flow: http.HTTPFlow, host: str) -> None:
        text = flow.request.get_text(strict=False)
        if not text:
            return
        report = self._scan(text, host)
        findings = report.findings
        if not findings:
            return

        self._record(flow, findings, report.suppressed, host)

        if self.config.mode == "audit":
            kinds = sorted({f.kind for f in findings})
            log.warning("AUDIT -> %s: %d secret(s) sent unchanged (%s)",
                        host, len(findings), ", ".join(kinds))
            return

        if self.config.mode == "block":
            self.stats["blocked"] += 1
            kinds = sorted({f.kind for f in findings})
            flow.response = self._blocked_response(
                f"Request blocked by keyfence: {len(findings)} secret(s) detected "
                f"({', '.join(kinds)}). Nothing was sent to the provider.")
            log.warning("BLOCKED -> %s: %d secret(s)", host, len(findings))
            return

        if is_sigv4_signed(flow.request):
            self.stats["blocked"] += 1
            kinds = sorted({f.kind for f in findings})
            flow.response = self._blocked_response(
                f"Request blocked by keyfence: {len(findings)} secret(s) detected "
                f"({', '.join(kinds)}). The request is signed with AWS SigV4, so removing them "
                f"would invalidate the signature. Nothing was sent to the provider.")
            log.warning("BLOCKED -> %s: %d secret(s) in a SigV4-signed request, which %s mode cannot rewrite",
                        host, len(findings), self.config.mode)
            return

        mapping: dict[str, str] = {}
        new_text = self._rewrite(text, findings, mapping)
        if new_text is None:
            self.stats["errors"] += 1
            log.error("rewriting the JSON body for %s would break it, failing closed", host)
            flow.response = self._blocked_response(
                "keyfence could not remove the secrets from this request without breaking its JSON; "
                "request not sent.")
            return

        if self.config.notice:
            new_text = add_notice(new_text, host, self.config.mode)
        flow.request.set_text(new_text)
        if mapping:
            flow.metadata[MAPPING_KEY] = mapping
            flow.request.headers["accept-encoding"] = "identity"
        log.warning("%s -> %s: %d secret(s) removed from request",
                    self.config.mode.upper(), host, len(findings))

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        if flow.websocket is None or not flow.websocket.messages:
            return
        message = flow.websocket.messages[-1]
        host = flow.request.pretty_host
        try:
            self._setup()
            self._maybe_reload_config()
            if not self.config.host_matches(host):
                return
            if message.from_client:
                self._inspect_frame(flow, message, host)
            else:
                self._restore_frame(flow, message)
        except Exception as exc:
            self.stats["errors"] += 1
            log.error("detector failure, failing closed for %s: %r", host, exc)
            message.drop()

    def _inspect_frame(self, flow: http.HTTPFlow, message: WebSocketMessage, host: str) -> None:
        if not message.is_text or not message.text:
            return
        text = message.text
        report = self._scan(text, host)
        findings = report.findings
        if not findings:
            return

        self._record(flow, findings, report.suppressed, host, websocket=True)
        kinds = sorted({f.kind for f in findings})

        if self.config.mode == "audit":
            log.warning("AUDIT -> %s: %d secret(s) sent unchanged in a websocket frame (%s)",
                        host, len(findings), ", ".join(kinds))
            return

        if self.config.mode == "block":
            self.stats["blocked"] += 1
            message.drop()
            log.warning("BLOCKED -> %s: %d secret(s) in a websocket frame (%s); frame not sent",
                        host, len(findings), ", ".join(kinds))
            return

        mapping = dict(flow.metadata.get(MAPPING_KEY) or {})
        new_text = self._rewrite(text, findings, mapping)
        if new_text is None:
            self.stats["errors"] += 1
            log.error("rewriting the JSON websocket frame for %s would break it, failing closed", host)
            message.drop()
            return

        message.text = new_text
        if mapping:
            flow.metadata[MAPPING_KEY] = mapping
        log.warning("%s -> %s: %d secret(s) removed from a websocket frame",
                    self.config.mode.upper(), host, len(findings))

    def _restore_frame(self, flow: http.HTTPFlow, message: WebSocketMessage) -> None:
        mapping = flow.metadata.get(MAPPING_KEY)
        if not mapping or not message.is_text:
            return
        restored = restore(message.text, mapping)
        if restored != message.text:
            message.text = restored
            log.info("placeholders restored in a websocket frame")

    def _placeholder(self, value: str, mapping: dict[str, str]) -> str:
        digest = self.vault.placeholder_digest(value)
        length = PLACEHOLDER_ID_LENGTH
        token = f"<<SECRET_{digest[:length]}>>"
        while token in mapping and mapping[token] != value:
            length += 2
            token = f"<<SECRET_{digest[:length]}>>"
        return token

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
            flow.response.stream = SSERestorer(mapping).stream
            flow.metadata[STREAMED_KEY] = True

    def response(self, flow: http.HTTPFlow) -> None:
        mapping = flow.metadata.get(MAPPING_KEY)
        if not mapping or flow.metadata.get(STREAMED_KEY) or flow.response is None:
            return
        text = flow.response.get_text(strict=False)
        if not text:
            return
        if "text/event-stream" in flow.response.headers.get("content-type", ""):
            restorer = SSERestorer(mapping)
            restored = (restorer.feed(text.encode("utf-8")) + restorer.feed(b"")).decode("utf-8")
        else:
            restored = restore(text, mapping)
        if restored != text:
            flow.response.set_text(restored)
            log.info("placeholders restored in response")

    def _audit_finding(self, f: Finding) -> dict:
        entry = {"kind": f.kind, "preview": f.masked, "key": f.key}
        if f.kind == "canary":
            entry["label"] = self.vault.canary_label(f.value)
        return entry

    def _audit(self, flow: http.HTTPFlow, findings: list[Finding], suppressed: int = 0,
               websocket: bool = False) -> None:
        try:
            path = Path(self.config.audit_log)
            path.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "host": flow.request.pretty_host,
                "path": flow.request.path.split("?")[0],
                "mode": self.config.mode,
                "count": len(findings),
                "findings": [self._audit_finding(f) for f in findings[:AUDIT_PREVIEW_LIMIT]],
            }
            if suppressed:
                entry["suppressed"] = suppressed
            if websocket:
                entry["websocket"] = True
            with path.open("a") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError as exc:
            log.warning("could not write audit log: %s", exc)


addons = [KeyFence()]
