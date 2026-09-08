from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from .importer import env_values
from .vault import DEFAULT_DIR, Vault

ADDON_PATH = Path(__file__).parent / "addon.py"
CA_CERT = Path(os.environ.get("MITMPROXY_CONFDIR", Path.home() / ".mitmproxy")) / "mitmproxy-ca-cert.pem"
ENV_VAULT_VAR = "KEYFENCE_ENV_VAULT"
PROXY_ENV_VARS = ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy")
CA_ENV_VARS = ("NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")


def mitmdump_path() -> str:
    bindir = Path(sys.executable).parent
    for name in ("mitmdump", "mitmdump.exe"):
        candidate = bindir / name
        if candidate.exists():
            return str(candidate)
    return shutil.which("mitmdump") or "mitmdump"


def local_mode(names: str | None) -> list[str]:
    if names is None:
        return []
    spec = "local" if names in ("", "*") else f"local:{names}"
    return ["--mode", "regular", "--mode", spec]


def proxy_command(port: int, addon: Path = ADDON_PATH, extra: Sequence[str] = (),
                  local: str | None = None) -> list[str]:
    return [
        mitmdump_path(), "-q",
        "-s", str(addon),
        "--listen-host", "127.0.0.1",
        "--listen-port", str(port),
        "--set", "block_global=false",
        *local_mode(local),
        *extra,
    ]


def port_open(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def wait_for(predicate: Callable[[], bool], timeout: float, interval: float = 0.1) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def child_env(base: Mapping[str, str], port: int, ca_cert: Path) -> dict[str, str]:
    env = dict(base)
    proxy_url = f"http://127.0.0.1:{port}"
    for name in PROXY_ENV_VARS:
        env[name] = proxy_url
    for name in CA_ENV_VARS:
        env[name] = str(ca_cert)
    return env


def build_env_vault(environ: Mapping[str, str], everything: bool = False) -> Path:
    main = Vault()
    fd, name = tempfile.mkstemp(prefix="keyfence-env-", suffix=".json")
    os.close(fd)
    path = Path(name)
    path.unlink()
    env_vault = Vault(path=path, salt=main.salt)
    env_vault.add_many(env_values(environ, main.min_length, everything))
    return path


def run(command: Sequence[str], port: int, everything: bool = False,
        timeout: float = 20.0, ca_cert: Path = CA_CERT, local: str | None = None) -> int:
    env_vault = build_env_vault(os.environ, everything)
    proxy_env = dict(os.environ, **{ENV_VAULT_VAR: str(env_vault)})
    DEFAULT_DIR.mkdir(parents=True, exist_ok=True)
    proxy_log = (DEFAULT_DIR / "proxy.log").open("a")
    if local == "":
        local = Path(command[0]).name
    try:
        proxy = subprocess.Popen(proxy_command(port, local=local), env=proxy_env,
                                 stdout=proxy_log, stderr=subprocess.STDOUT)
    except FileNotFoundError:
        proxy_log.close()
        env_vault.unlink(missing_ok=True)
        print("mitmdump not found. Install it with: pip install mitmproxy")
        return 1
    try:
        ready = wait_for(lambda: proxy.poll() is None and port_open(port) and ca_cert.exists(), timeout)
        if not ready:
            print(f"keyfence proxy did not come up on port {port} within {timeout:.0f}s; "
                  f"see {DEFAULT_DIR / 'proxy.log'}")
            return 1
        return subprocess.call(list(command), env=child_env(os.environ, port, ca_cert))
    finally:
        if proxy.poll() is None:
            proxy.terminate()
            try:
                proxy.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
        proxy_log.close()
        env_vault.unlink(missing_ok=True)
