from __future__ import annotations

import http.client
import json
import os
import re
import secrets
import ssl
import tempfile
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import yaml

from . import runner
from . import vault as vault_module
from .config import Config
from .doctor import FAIL, INFO, OK, Check, check_mitmdump, format_checks
from .vault import Vault

LISTENER_HOST = "127.0.0.1"
REQUEST_PATH = "/v1/selftest"
LOG_NAME = "selftest.log"
LOG_TAIL = 8
REQUEST_TIMEOUT = 10.0
REDACTED = "[REDACTED:vault]"
PLACEHOLDER = "<<SECRET_"
PLACEHOLDER_RE = re.compile(r"<<SECRET_[0-9a-f]{10,}>>")
STAGE_LABELS = {runner.MISSING: "mitmdump", runner.NOT_UP: "proxy", runner.NOT_LIVE: "addon"}


def _make_self_signed_cert() -> tuple[bytes, bytes]:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime
    import ipaddress

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "keyfence-selftest")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


class Listener:
    def __init__(self, use_tls: bool = False):
        self.received: list[bytes] = []
        self.use_tls = use_tls
        received = self.received

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                received.append(body)
                payload = json.dumps({"selftest": body.decode("utf-8", "replace")}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        self.server = HTTPServer((LISTENER_HOST, 0), Handler)
        if self.use_tls:
            cert_pem, key_pem = _make_self_signed_cert()
            self._cert_pem = cert_pem
            self._key_pem = key_pem
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".pem") as cert_file:
                cert_file.write(cert_pem)
                cert_path = cert_file.name
            with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".pem") as key_file:
                key_file.write(key_pem)
                key_path = key_file.name
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
            self._cert_path = cert_path
            self._key_path = key_path
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.server.server_port

    @property
    def url(self) -> str:
        scheme = "https" if self.use_tls else "http"
        return f"{scheme}://{LISTENER_HOST}:{self.port}{REQUEST_PATH}"

    @property
    def cert_pem(self) -> bytes | None:
        return getattr(self, "_cert_pem", None)

    def text(self) -> str:
        return b"\n".join(self.received).decode("utf-8", "replace")

    def __enter__(self) -> "Listener":
        self.thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self.server.shutdown()
        self.server.server_close()
        for attr in ("_cert_path", "_key_path"):
            path = getattr(self, attr, None)
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)
    mode: str | None = None

    @property
    def ok(self) -> bool:
        return not any(c.status == FAIL for c in self.checks)

    def failed(self) -> list[str]:
        return [c.label for c in self.checks if c.status == FAIL]


def throwaway_value() -> str:
    return f"keyfence-selftest-{secrets.token_hex(8)}"


def send_through(proxy_port: int, url: str, body: bytes, timeout: float = REQUEST_TIMEOUT, ca_bundle: Path | None = None) -> tuple[int, str]:
    host = url.split("/")[2]
    if url.startswith("https://"):
        context = ssl.create_default_context()
        if ca_bundle:
            context.load_verify_locations(cafile=str(ca_bundle))
        conn = http.client.HTTPSConnection(LISTENER_HOST, proxy_port, timeout=timeout, context=context)
    else:
        conn = http.client.HTTPConnection(LISTENER_HOST, proxy_port, timeout=timeout)
    try:
        conn.request("POST", url, body=body, headers={"Host": host, "Content-Type": "application/json"})
        resp = conn.getresponse()
        return resp.status, resp.read().decode("utf-8", "replace")
    finally:
        conn.close()


def write_home(root: Path, value: str) -> Path:
    source = Config.path()
    data = (yaml.safe_load(source.read_text()) or {}) if source.exists() else {}
    data["extra_hosts"] = [*(data.get("extra_hosts") or []), LISTENER_HOST]
    data["audit_log"] = str(root / "audit.log")
    path = root / "config.yaml"
    path.write_text(yaml.safe_dump(data))
    Vault(path=root / "vault.json").add(value)
    return path


def log_tail(path: Path, limit: int = LOG_TAIL) -> str:
    try:
        lines = [line for line in path.read_text(errors="replace").splitlines() if line.strip()]
    except OSError:
        return ""
    if not lines:
        return f"; {path} is empty"
    return f"; last lines of {path}:\n" + "\n".join(f"      {line}" for line in lines[-limit:])


def audit_entries(path: Path, mode: str) -> int:
    if not path.exists():
        return 0
    count = 0
    for line in path.read_text().splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if entry.get("host") == LISTENER_HOST and entry.get("mode") == mode \
                and any(f.get("kind") == "vault" for f in entry.get("findings", [])):
            count += 1
    return count


def verify(mode: str, value: str, status: int, response: str, received: str) -> list[Check]:
    if mode == "audit":
        if value not in received:
            return [Check(FAIL, "request", f"the value did not reach the listener unchanged (HTTP {status}); "
                                           "audit mode must not alter requests, so the config was not applied")]
        return [Check(OK, "request", "the value reached the listener unchanged, as audit mode should"),
                Check(OK, "response", f"HTTP {status} passed back to the client")]
    if value in received:
        return [Check(FAIL, "request", f"the value reached the listener unchanged (HTTP {status}); "
                                       "the proxy is not scanning this traffic")]
    if mode == "block":
        if status != 403 or "keyfence_blocked" not in response:
            return [Check(FAIL, "request", f"expected HTTP 403 from the proxy, got {status}"
                                           + ("; nothing reached the listener" if not received else
                                              "; the listener received something else"))]
        return [Check(OK, "request", "HTTP 403 from the proxy, nothing reached the listener"),
                Check(OK, "response", "the client got the keyfence_blocked error")]
    if not received:
        return [Check(FAIL, "request", f"nothing reached the listener (HTTP {status}); the proxy did not forward the request")]
    if mode == "redact":
        if REDACTED not in received:
            return [Check(FAIL, "request", f"the listener received neither the value nor {REDACTED}; "
                                           "the request was altered in a way redact mode does not")]
        checks = [Check(OK, "request", f"the listener received {REDACTED} instead of the value")]
        if value in response:
            checks.append(Check(FAIL, "response", "the value came back in the response although the listener never saw it"))
        else:
            checks.append(Check(OK, "response", f"HTTP {status} passed back with the redaction in place"))
        return checks
    tokens = set(PLACEHOLDER_RE.findall(received))
    if not tokens:
        return [Check(FAIL, "request", f"the listener received neither the value nor a {PLACEHOLDER}...>> placeholder; "
                                       "the request was altered in a way placeholder mode does not")]
    checks = [Check(OK, "request", f"the listener received a {PLACEHOLDER}...>> placeholder instead of the value")]
    if value not in response or any(token in response for token in tokens):
        checks.append(Check(FAIL, "response", f"the placeholder was not restored in the response (HTTP {status}); "
                                              f"the client would see {PLACEHOLDER}...>> instead of its value"))
    else:
        checks.append(Check(OK, "response", "the real value was restored in the response"))
    return checks


def run(port: int | None = None, timeout: float = 20.0, ca_cert: Path = runner.CA_CERT,
        home: Path | None = None, value: str | None = None,
        start_proxy: Callable | None = None, stop_proxy: Callable | None = None,
        probe: Callable | None = None, send: Callable | None = None,
        environ: Mapping[str, str] = os.environ) -> Report:
    start_proxy = start_proxy or runner.start_proxy
    stop_proxy = stop_proxy or runner.stop_proxy
    probe = probe or runner.probe
    send = send or send_through
    report = Report()
    checks = report.checks
    checks.append(check_mitmdump())
    if checks[-1].status == FAIL:
        return report
    try:
        cfg = Config.load()
    except Exception as exc:
        checks.append(Check(FAIL, "config", f"{Config.path()}: {exc}"))
        return report
    report.mode = cfg.mode
    where = str(Config.path()) if Config.path().exists() else "defaults (no config file)"
    checks.append(Check(OK, "config", f"mode={cfg.mode}, {len(cfg.hosts)} hosts from {where}; copied to a temporary "
                                      f"home with {LISTENER_HOST} added to the hosts, your config and vault untouched"))
    port = port or runner.free_port()
    if runner.port_open(port):
        checks.append(Check(FAIL, "proxy", f"port {port} is already in use; pick another one with -p"))
        return report
    value = value or throwaway_value()
    with tempfile.TemporaryDirectory(prefix="keyfence-selftest-") as tmp, Listener(use_tls=True) as listener:
        root = home or Path(tmp)
        root.mkdir(parents=True, exist_ok=True)
        config_path = write_home(root, value)
        env = dict(environ, KEYFENCE_HOME=str(root), KEYFENCE_CONFIG=str(config_path))
        env.pop(runner.ENV_VAULT_VAR, None)
        vault_module.DEFAULT_DIR.mkdir(parents=True, exist_ok=True)
        log_path = vault_module.DEFAULT_DIR / LOG_NAME
        with log_path.open("w") as log:
            try:
                proxy = start_proxy(port, env, log, timeout, ca_cert, extra=["--set", "ssl_insecure=true"])
            except runner.ProxyError as exc:
                if exc.stage == runner.NOT_LIVE:
                    checks.append(Check(OK, "proxy", f"mitmdump up on {LISTENER_HOST}:{port}"))
                checks.append(Check(FAIL, STAGE_LABELS[exc.stage], exc.message + log_tail(log_path)))
                return report
            try:
                checks.append(Check(OK, "proxy", f"mitmdump up on {LISTENER_HOST}:{port}"))
                checks.append(Check(OK, "addon", f"answering the probe for {runner.PROBE_URL}"))
                if not ca_cert.exists():
                    checks.append(Check(FAIL, "CA certificate", f"{ca_cert} does not exist; keyfence exec would hand "
                                                                "child processes a path that is not there"))
                    return report
                checks.append(Check(OK, "CA certificate", f"{ca_cert}, the path keyfence exec hands to child processes"))
                try:
                    bundle, label = runner.ensure_bundle(ca_cert)
                except runner.BundleError as exc:
                    checks.append(Check(FAIL, "CA bundle", str(exc)))
                    return report
                checks.append(Check(OK, "CA bundle", f"{bundle}, {label}"))
                info = probe(port)
                if not info:
                    checks.append(Check(FAIL, "addon", "stopped answering the probe" + log_tail(log_path)))
                    return report
                if info.get("mode") != cfg.mode or info.get("hosts") != len(cfg.hosts) + 1:
                    checks.append(Check(FAIL, "mode", f"the proxy reports mode={info.get('mode')} with {info.get('hosts')} "
                                                      f"hosts, the config says mode={cfg.mode} with {len(cfg.hosts) + 1}; "
                                                      "the config was not applied" + log_tail(log_path)))
                    return report
                checks.append(Check(OK, "mode", f"the proxy reports {cfg.mode}, as configured, with {LISTENER_HOST} monitored"))
                body = json.dumps({"messages": [{"role": "user", "content": f"selftest token {value}"}]}).encode("utf-8")
                try:
                    status, response = send(port, listener.url, body, ca_bundle=bundle)
                except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
                    checks.append(Check(FAIL, "TLS", f"TLS handshake to the proxy failed: {exc}" + log_tail(log_path)))
                    return report
                checks.extend(verify(cfg.mode, value, status, response, listener.text()))
                if not report.ok:
                    return report
                entries = audit_entries(root / "audit.log", cfg.mode)
                if not entries:
                    checks.append(Check(FAIL, "audit log", "no entry with a vault finding was written for the request"
                                                           + log_tail(log_path)))
                    return report
                checks.append(Check(OK, "audit log", f"{entries} entry(ies) with a vault finding written for the request"))
                checks.append(Check(OK, "TLS", f"handshake to proxy succeeded with mitmproxy's certificate, body redacted"))
                return report
            finally:
                stop_proxy(proxy)


def render(report: Report) -> str:
    lines = format_checks(report.checks)
    lines.append("")
    if not report.ok:
        lines.append(f"The proxy is NOT protecting traffic: {', '.join(report.failed())} failed. "
                     "Fix the FAIL line above and run keyfence selftest again.")
    elif report.mode == "audit":
        lines.append("The proxy is watching traffic in audit mode: the secret was logged and sent unchanged. "
                     "Switch to redact, placeholder or block to have it changed or stopped.")
    else:
        lines.append(f"The proxy is protecting traffic in {report.mode} mode.")
    return "\n".join(lines)
