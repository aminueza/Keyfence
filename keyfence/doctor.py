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
from urllib.parse import urlsplit

from . import __version__, hooks, pi, runner
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


def command_problem(command: str) -> str | None:
    if os.sep in command or "/" in command:
        path = Path(command)
        if not path.exists():
            return "does not exist"
        if not os.access(path, os.X_OK):
            return "is not executable"
        return None
    if shutil.which(command) is None:
        return "not found on PATH"
    return None


def check_mitmdump() -> Check:
    path = runner.mitmdump_path()
    problem = command_problem(path)
    if problem:
        return Check(FAIL, "mitmdump", f"{path} {problem}; reinstall keyfence (pip install keyfence)")
    return Check(OK, "mitmdump", path)


def check_ca(ca_cert: Path = runner.CA_CERT) -> Check:
    if ca_cert.exists():
        return Check(OK, "CA certificate", str(ca_cert))
    return Check(INFO, "CA certificate", f"{ca_cert} not created yet; it appears on the first keyfence exec or run")


def check_ca_bundle(ca_cert: Path = runner.CA_CERT) -> Check:
    path = runner.bundle_path()
    try:
        roots, kind = runner.system_roots((ca_cert, path))
    except runner.BundleError as exc:
        return Check(FAIL, "CA bundle", str(exc))
    if not path.exists():
        return Check(INFO, "CA bundle", f"{path} does not exist yet; keyfence exec writes it on the first run, with "
                                        f"the system roots from {roots} ({kind}) plus {ca_cert}")
    return Check(OK, "CA bundle", f"{path}, {roots} ({kind}) plus {ca_cert}")


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


def proxy_endpoint(environ, port: int) -> tuple[str, int]:
    proxy = (environ.get("HTTPS_PROXY") or environ.get("https_proxy") or "").strip()
    try:
        parsed = urlsplit(proxy if "//" in proxy else f"//{proxy}")
        host, found = parsed.hostname, parsed.port
    except ValueError:
        host = found = None
    return host or "127.0.0.1", found or port


def check_proxy(host: str, port: int) -> Check:
    if not runner.port_open(port, host):
        return Check(INFO, "proxy", f"nothing on {host}:{port}; keyfence exec starts its own, keyfence run starts one here")
    if runner.addon_live(port, host):
        return Check(OK, "proxy", f"keyfence is answering on {host}:{port}")
    return Check(WARN, "proxy", f"something is listening on {host}:{port} but the keyfence addon is not answering; "
                                "requests through it are not scanned")


def git_config_in_env(environ, key: str) -> str | None:
    try:
        count = int(environ.get("GIT_CONFIG_COUNT", "0"))
    except ValueError:
        return None
    for i in range(count):
        if environ.get(f"GIT_CONFIG_KEY_{i}", "").lower() == key.lower():
            return environ.get(f"GIT_CONFIG_VALUE_{i}")
    return None


def git_ignores_ca(environ=os.environ, run: Callable = _run, system: str | None = None) -> str | None:
    if (system or platform.system()) != "Windows":
        return None
    if (git_config_in_env(environ, runner.GIT_SCHANNEL_KEY) or "").lower() == "true":
        return None
    if shutil.which("git") is None:
        return None
    code, out = run(["git", "config", "--get", "http.sslBackend"])
    backend = out.strip().lower() if code == 0 else "schannel"
    if backend != "schannel":
        return None
    code, out = run(["git", "config", "--get", runner.GIT_SCHANNEL_KEY])
    if code == 0 and out.strip().lower() == "true":
        return None
    return (f"git uses the schannel backend and ignores GIT_SSL_CAINFO until you run "
            f"`git config --global {runner.GIT_SCHANNEL_KEY} true`; keyfence exec sets it for its own session")


def check_environment(host: str, port: int, environ=os.environ, ca_cert: Path = runner.CA_CERT,
                      bundle: Path | None = None, run: Callable = _run,
                      system: str | None = None) -> Check:
    bundle = bundle or runner.bundle_path()
    proxy = environ.get("HTTPS_PROXY") or environ.get("https_proxy")
    if not proxy:
        return Check(INFO, "shell environment",
                     "HTTPS_PROXY is not set in this shell; fine with keyfence exec or --local, tools started plainly here go direct")
    if not runner.addon_live(port, host):
        return Check(WARN, "shell environment",
                     f"HTTPS_PROXY={proxy} does not reach a keyfence proxy on {host}:{port}; keyfence exec wires the "
                     "variables for the command it starts, keyfence run prints the ones to export")
    wanted = {"NODE_EXTRA_CA_CERTS": ca_cert, **{name: bundle for name in runner.BUNDLE_ENV_VARS}}
    missing = [name for name, path in wanted.items() if Path(environ.get(name, "")) != path]
    if missing:
        return Check(WARN, "shell environment",
                     f"HTTPS_PROXY is set but {', '.join(missing)} do not hold what keyfence exec would put there "
                     f"({bundle} for the {len(runner.BUNDLE_ENV_VARS)} that replace the trust store, {ca_cert} for the one that adds to it); "
                     "the tools that read them (Node, Python, curl, git, cargo) will fail TLS")
    detail = f"HTTPS_PROXY and the {len(runner.CA_ENV_VARS)} CA variables point at keyfence on {host}:{port}"
    problem = git_ignores_ca(environ, run, system)
    if problem:
        return Check(WARN, "shell environment", f"{detail}, but {problem}")
    return Check(OK, "shell environment", detail)


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


def hook_installed(path: Path) -> bool:
    try:
        data = json.loads(path.read_text()) if path.exists() else {}
    except ValueError:
        return False
    return any(hooks._is_ours(e) for e in data.get("hooks", {}).get("PreToolUse", []))


def installed_scopes(agent: str, cwd: Path | None = None) -> list[tuple[str, Path, bool]]:
    locate, installed = (pi.extension_path, pi.is_ours) if agent == "pi" else (hooks.settings_path, hook_installed)
    return [(scope, path, installed(path))
            for scope, path in (("global", locate(False)), ("project", locate(True, cwd)))]


def check_hook(cwd: Path | None = None) -> Check:
    found = [scope for scope, _, installed in installed_scopes("claude-code", cwd) if installed]
    if found:
        return Check(OK, "Claude Code hook", "installed (" + ", ".join(found) + ")")
    return Check(INFO, "Claude Code hook", "not installed; keyfence install-hooks claude-code stops Claude Code from reading secret files")


def check_pi_extension(cwd: Path | None = None) -> Check:
    found = [(scope, path) for scope, path, installed in installed_scopes("pi", cwd) if installed]
    if not found:
        return Check(INFO, "pi extension", "not installed; keyfence install-hooks pi stops pi from reading secret files")
    scopes = ", ".join(scope for scope, _ in found)
    commands: list[str] = []
    for scope, path in found:
        command = pi.baked_command(path)
        if command is None:
            return Check(FAIL, "pi extension",
                         f"installed ({scopes}) but {path} holds no keyfence command; every pi tool call is refused "
                         "until keyfence install-hooks pi runs again")
        problem = command_problem(command)
        if problem:
            return Check(FAIL, "pi extension",
                         f"installed ({scopes}) but the {scope} extension calls {command}, which {problem}; every pi "
                         "tool call is refused until keyfence install-hooks pi runs again, with --command PATH to "
                         "pick the keyfence to call")
        if command not in commands:
            commands.append(command)
    return Check(OK, "pi extension", f"installed ({scopes}), calling {' and '.join(commands)}")


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
    host, target = proxy_endpoint(os.environ, port)
    return [
        Check(OK, "keyfence", f"{__version__} on Python {sys.version.split()[0]}, {platform.system()}"),
        check_mitmdump(),
        check_ca(),
        check_ca_bundle(),
        check_ca_trusted(),
        check_config(),
        check_vault(),
        check_proxy(host, target),
        check_environment(host, target),
        check_local_mode(),
        check_hook(cwd),
        check_pi_extension(cwd),
        check_audit(),
    ]


MARKS = {OK: "ok  ", INFO: "info", WARN: "warn", FAIL: "FAIL"}


def format_checks(checks: list[Check]) -> list[str]:
    return [f"{MARKS[c.status]}  {c.label}: {c.detail}" for c in checks]


def render(checks: list[Check]) -> str:
    lines = format_checks(checks)
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
    if not fails:
        lines.append("These checks look at the pieces one by one; keyfence selftest sends a throwaway "
                     "secret through a fresh proxy and checks what comes out the other side.")
    return "\n".join(lines)
