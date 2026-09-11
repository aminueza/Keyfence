from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from . import __version__, hooks, runner
from . import vault as vault_module
from .config import Config
from .vault import Vault, VaultError

OK, INFO, WARN, FAIL = "ok", "info", "warn", "fail"


@dataclass
class Check:
    status: str
    label: str
    detail: str = ""


def _run(command: list[str]) -> tuple[int, str]:
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return done.returncode, done.stdout + done.stderr


def check_mitmdump() -> Check:
    path = runner.mitmdump_path()
    if path == "mitmdump" and shutil.which("mitmdump") is None:
        return Check(FAIL, "mitmdump", "not found; reinstall keyfence (pip install keyfence)")
    return Check(OK, "mitmdump", path)


def check_ca(ca_cert: Path = runner.CA_CERT) -> Check:
    if ca_cert.exists():
        return Check(OK, "CA certificate", str(ca_cert))
    return Check(INFO, "CA certificate", f"{ca_cert} not created yet; it appears on the first keyfence exec or run")


def check_ca_trusted(ca_cert: Path = runner.CA_CERT, run: Callable = _run) -> Check:
    if platform.system() != "Darwin":
        return Check(INFO, "CA trusted system-wide", "not checked on this platform; only needed for GUI apps and --local")
    if not ca_cert.exists():
        return Check(INFO, "CA trusted system-wide", "no certificate yet")
    code, _ = run(["security", "find-certificate", "-c", "mitmproxy", "/Library/Keychains/System.keychain"])
    if code == 0:
        return Check(OK, "CA trusted system-wide", "found in the System keychain")
    return Check(INFO, "CA trusted system-wide", "not in the System keychain; needed only for GUI apps and --local, "
                 "keyfence exec passes the CA to its child on its own")


def check_config() -> Check:
    path = Config.path()
    try:
        cfg = Config.load()
    except Exception as exc:
        return Check(FAIL, "config", f"{path}: {exc}")
    where = str(path) if path.exists() else "defaults (no config file)"
    return Check(OK, "config", f"mode={cfg.mode}, {len(cfg.hosts)} hosts, {len(cfg.scan.rules)} rules, {where}")


def check_vault() -> Check:
    try:
        vault = Vault()
    except VaultError as exc:
        return Check(FAIL, "vault", str(exc))
    if vault.is_empty():
        return Check(WARN, "vault", f"empty; run keyfence import so your own secrets are protected ({vault.path})")
    return Check(OK, "vault", f"{vault.count()} secret(s), {vault.canary_count()} canary(ies) in {vault.path}")


def check_proxy(port: int) -> Check:
    if runner.port_open(port):
        return Check(OK, "proxy", f"something is listening on 127.0.0.1:{port}")
    return Check(INFO, "proxy", f"nothing on 127.0.0.1:{port}; keyfence exec starts its own, keyfence run starts one here")


def check_environment(port: int, environ=os.environ, ca_cert: Path = runner.CA_CERT) -> Check:
    proxy = environ.get("HTTPS_PROXY") or environ.get("https_proxy")
    if not proxy:
        return Check(INFO, "shell environment",
                     "HTTPS_PROXY is not set in this shell; fine with keyfence exec or --local, tools started plainly here go direct")
    expected = f"http://127.0.0.1:{port}"
    if proxy.rstrip("/") != expected:
        return Check(WARN, "shell environment", f"HTTPS_PROXY={proxy}, keyfence would be {expected}")
    node = environ.get("NODE_EXTRA_CA_CERTS", "")
    if Path(node) != ca_cert:
        return Check(WARN, "shell environment", f"HTTPS_PROXY is set but NODE_EXTRA_CA_CERTS is not {ca_cert}; Node tools will fail TLS")
    return Check(OK, "shell environment", f"HTTPS_PROXY and NODE_EXTRA_CA_CERTS point at keyfence on port {port}")


def check_local_mode(run: Callable = _run) -> Check:
    system = platform.system()
    if system == "Linux":
        return Check(INFO, "--local capture", "not available on Linux; use keyfence exec or Docker")
    if system != "Darwin":
        return Check(INFO, "--local capture", "not checked on this platform")
    code, out = run(["systemextensionsctl", "list"])
    if code != 0 or "mitmproxy" not in out:
        return Check(INFO, "--local capture", "mitmproxy network extension not installed; the first keyfence run --local installs it")
    line = next((l for l in out.splitlines() if "mitmproxy" in l), "")
    if "enabled" in line and "waiting" not in line:
        return Check(OK, "--local capture", "network extension enabled")
    return Check(WARN, "--local capture", "network extension waiting for approval in System Settings > General > Login Items & Extensions > Network Extensions")


def check_hook(cwd: Path | None = None) -> Check:
    found = []
    for scope, path in (("global", hooks.settings_path(False)), ("project", hooks.settings_path(True, cwd))):
        try:
            data = json.loads(path.read_text()) if path.exists() else {}
        except ValueError:
            continue
        if any(hooks._is_ours(e) for e in data.get("hooks", {}).get("PreToolUse", [])):
            found.append(scope)
    if found:
        return Check(OK, "Claude Code hook", "installed (" + ", ".join(found) + ")")
    return Check(INFO, "Claude Code hook", "not installed; keyfence install-hooks claude-code stops Claude Code from reading secret files")


def check_audit() -> Check:
    try:
        path = Path(Config.load().audit_log)
    except Exception:
        path = vault_module.DEFAULT_DIR / "audit.log"
    if not path.exists():
        return Check(INFO, "audit log", f"{path} does not exist yet; nothing has been detected so far")
    lines = [l for l in path.read_text().splitlines() if l.strip()]
    return Check(OK, "audit log", f"{len(lines)} request(s) with findings in {path}")


def run_checks(port: int, cwd: Path | None = None) -> list[Check]:
    return [
        Check(OK, "keyfence", f"{__version__} on Python {sys.version.split()[0]}, {platform.system()}"),
        check_mitmdump(),
        check_ca(),
        check_ca_trusted(),
        check_config(),
        check_vault(),
        check_proxy(port),
        check_environment(port),
        check_local_mode(),
        check_hook(cwd),
        check_audit(),
    ]


def render(checks: list[Check]) -> str:
    marks = {OK: "ok  ", INFO: "info", WARN: "warn", FAIL: "FAIL"}
    lines = [f"{marks[c.status]}  {c.label}: {c.detail}" for c in checks]
    fails = sum(1 for c in checks if c.status == FAIL)
    warns = sum(1 for c in checks if c.status == WARN)
    infos = sum(1 for c in checks if c.status == INFO)
    lines.append("")
    if fails:
        lines.append(f"{fails} problem(s) to fix, {warns} warning(s).")
    elif warns:
        lines.append(f"No blocking problems, {warns} warning(s).")
    else:
        lines.append("Everything keyfence exec needs is in place.")
    if infos:
        lines.append("info lines are optional: they matter only for tools started outside keyfence exec.")
    return "\n".join(lines)
