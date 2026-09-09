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


def listen_args(port: int, local: str | None) -> list[str]:
    if local is None:
        return ["--listen-host", "127.0.0.1", "--listen-port", str(port)]
    spec = "local" if local in ("", "*") else f"local:{local}"
    return ["--mode", f"regular@127.0.0.1:{port}", "--mode", spec]


def proxy_command(port: int, addon: Path = ADDON_PATH, extra: Sequence[str] = (),
                  local: str | None = None) -> list[str]:
    return [
        mitmdump_path(), "-q",
        "-s", str(addon),
        *listen_args(port, local),
        "--set", "block_global=false",
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


ENV_VAULT_DIR = "env"
STALE_AFTER = 60.0


def sweep_stale_env_vaults(directory: Path, max_age: float = STALE_AFTER) -> int:
    if not directory.is_dir():
        return 0
    cutoff = time.time() - max_age
    removed = 0
    for path in directory.glob("keyfence-env-*"):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        except OSError:
            continue
    return removed


def build_env_vault(environ: Mapping[str, str], everything: bool = False) -> Vault:
    main = Vault()
    directory = DEFAULT_DIR / ENV_VAULT_DIR
    directory.mkdir(parents=True, exist_ok=True)
    sweep_stale_env_vaults(directory)
    fd, name = tempfile.mkstemp(prefix="keyfence-env-", suffix=".json", dir=directory)
    os.close(fd)
    path = Path(name)
    path.unlink()
    env_vault = Vault(path=path, salt=main.salt)
    env_vault.add_many(env_values(environ, main.min_length, everything))
    return env_vault


def run(command: Sequence[str], port: int, everything: bool = False,
        timeout: float = 20.0, ca_cert: Path = CA_CERT, local: str | None = None) -> int:
    if port_open(port):
        print(f"Port {port} is already in use. Pick another one with -p.")
        return 1
    env_vault = build_env_vault(os.environ, everything)
    proxy_env = dict(os.environ, **{ENV_VAULT_VAR: str(env_vault.path)})
    DEFAULT_DIR.mkdir(parents=True, exist_ok=True)
    proxy_log = (DEFAULT_DIR / "proxy.log").open("a")
    if local == "":
        local = Path(command[0]).name
    try:
        proxy = subprocess.Popen(proxy_command(port, local=local), env=proxy_env,
                                 stdout=proxy_log, stderr=subprocess.STDOUT)
    except FileNotFoundError:
        proxy_log.close()
        env_vault.remove_files()
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
        env_vault.remove_files()
