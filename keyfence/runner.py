from __future__ import annotations

import contextlib
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from .config import Config
from .ignore import IgnoreList
from .importer import env_values
from .vault import DEFAULT_DIR, Vault

ADDON_PATH = Path(__file__).parent / "addon.py"
PROBE_HOST = "keyfence.invalid"
PROBE_URL = f"http://{PROBE_HOST}/"
CONFDIR = Path(os.environ["MITMPROXY_CONFDIR"]) if os.environ.get("MITMPROXY_CONFDIR") else None
CA_CERT = (CONFDIR or Path.home() / ".mitmproxy") / "mitmproxy-ca-cert.pem"
ENV_VAULT_VAR = "KEYFENCE_ENV_VAULT"
PROXY_ENV_VARS = ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy")
BUNDLE_ENV_VARS = ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "CARGO_HTTP_CAINFO")
CA_ENV_VARS = ("NODE_EXTRA_CA_CERTS", *BUNDLE_ENV_VARS)
BUNDLE_NAME = "ca-bundle.pem"
BUNDLE_MODE = 0o644
CERT_MARK = "-----BEGIN CERTIFICATE-----"
SYSTEM_CA_PATHS = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/tls/cacert.pem",
    "/etc/ssl/cert.pem",
    "/usr/local/share/certs/ca-root-nss.crt",
    "/etc/ssl/certs/ca-bundle.crt",
)
LOG_ARGS = ("--set", "termlog_verbosity=warn", "--set", "flow_detail=0")
DEFAULT_PORT = 8888


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
                  local: str | None = None, confdir: Path | None = CONFDIR) -> list[str]:
    return [
        mitmdump_path(), *LOG_ARGS,
        "-s", str(addon),
        *listen_args(port, local),
        "--set", "block_global=false",
        *(["--set", f"confdir={confdir}"] if confdir else []),
        *extra,
    ]


def port_open(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def pick_port(preferred: int = DEFAULT_PORT) -> int:
    return free_port() if port_open(preferred) else preferred


def probe(port: int, timeout: float = 1.0) -> dict | None:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("GET", PROBE_URL, headers={"Host": PROBE_HOST})
        resp = conn.getresponse()
        body = json.loads(resp.read().decode("utf-8", "replace"))
        if resp.status == 200 and isinstance(body, dict) and "keyfence" in body:
            return body
        return None
    except (OSError, ValueError, http.client.HTTPException):
        return None
    finally:
        conn.close()


def addon_live(port: int, timeout: float = 1.0) -> bool:
    return probe(port, timeout) is not None


MISSING, NOT_UP, NOT_LIVE = "missing", "not-up", "not-live"


class ProxyError(RuntimeError):
    def __init__(self, stage: str, message: str):
        super().__init__(message)
        self.stage = stage
        self.message = message


def stop_proxy(proxy: subprocess.Popen) -> None:
    if proxy.poll() is None:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def start_proxy(port: int, env: Mapping[str, str], log, timeout: float = 20.0,
                ca_cert: Path = CA_CERT, local: str | None = None,
                extra: Sequence[str] = ()) -> subprocess.Popen:
    try:
        proxy = subprocess.Popen(proxy_command(port, local=local, extra=extra), env=env,
                                 stdout=log, stderr=subprocess.STDOUT)
    except FileNotFoundError:
        raise ProxyError(MISSING, "mitmdump not found. Install it with: pip install mitmproxy") from None
    if not wait_for(lambda: proxy.poll() is None and port_open(port) and ca_cert.exists(), timeout):
        stop_proxy(proxy)
        raise ProxyError(NOT_UP, f"keyfence proxy did not come up on port {port} within {timeout:.0f}s")
    if not wait_for(lambda: proxy.poll() is None and addon_live(port), timeout):
        stop_proxy(proxy)
        raise ProxyError(NOT_LIVE, f"mitmdump is listening on port {port} but the keyfence addon is not answering")
    return proxy


def wait_for(predicate: Callable[[], bool], timeout: float, interval: float = 0.1) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


GIT_SCHANNEL_KEY = "http.schannelUseSSLCAInfo"


def with_git_config(env: dict[str, str], key: str, value: str) -> dict[str, str]:
    try:
        count = max(int(env.get("GIT_CONFIG_COUNT", "0")), 0)
    except ValueError:
        count = 0
    env[f"GIT_CONFIG_KEY_{count}"] = key
    env[f"GIT_CONFIG_VALUE_{count}"] = value
    env["GIT_CONFIG_COUNT"] = str(count + 1)
    return env


class BundleError(RuntimeError):
    pass


def bundle_path(home: Path | None = None) -> Path:
    return (home or DEFAULT_DIR) / BUNDLE_NAME


def _holds_cert(path: Path) -> bool:
    try:
        return path.is_file() and CERT_MARK in path.read_text(errors="replace")
    except OSError:
        return False


def root_sources(exclude: Sequence[Path] = ()) -> list[tuple[Path, str]]:
    candidates: list[tuple[Path, str]] = []
    try:
        import certifi
        candidates.append((Path(certifi.where()), "certifi"))
    except Exception:
        pass
    cafile = ssl.get_default_verify_paths().cafile
    if cafile:
        candidates.append((Path(cafile), "the OpenSSL default"))
    candidates.extend((Path(name), "a system path") for name in SYSTEM_CA_PATHS)
    return [(path, kind) for path, kind in candidates if path not in exclude and _holds_cert(path)]


def system_roots(exclude: Sequence[Path] = ()) -> tuple[Path, str]:
    found = root_sources(exclude)
    if found:
        return found[0]
    raise BundleError(
        f"no system trust store to put in the bundle: certifi is not importable, OpenSSL points at no cafile, "
        f"and none of {', '.join(SYSTEM_CA_PATHS)} holds a certificate. A bundle with only the mitmproxy CA would "
        "reject every public certificate, so the bundle was not written and the command was not started"
    )


def _same_file(path: Path, content: str) -> bool:
    try:
        return path.read_text(errors="replace") == content
    except OSError:
        return False


def ensure_bundle(ca_cert: Path, home: Path | None = None) -> tuple[Path, str]:
    path = bundle_path(home)
    roots, kind = system_roots((ca_cert, path))
    try:
        system = roots.read_text(errors="replace")
        ca = ca_cert.read_text(errors="replace")
    except OSError as exc:
        raise BundleError(f"the bundle could not be read ({exc}); {ca_cert} and {roots} must both exist") from None
    if CERT_MARK not in ca:
        raise BundleError(f"{ca_cert} holds no certificate, so the bundle would add nothing to the system roots")
    content = f"{system.rstrip()}\n{ca.rstrip()}\n"
    if _same_file(path, content):
        return path, f"{roots} ({kind}) plus {ca_cert}"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, BUNDLE_MODE)
    with os.fdopen(fd, "w") as handle:
        handle.write(content)
    os.chmod(path, BUNDLE_MODE)
    return path, f"{roots} ({kind}) plus {ca_cert}"


def child_env(base: Mapping[str, str], port: int, ca_cert: Path, bundle: Path,
              windows: bool = os.name == "nt") -> dict[str, str]:
    env = dict(base)
    proxy_url = f"http://127.0.0.1:{port}"
    for name in PROXY_ENV_VARS:
        env[name] = proxy_url
    for name in BUNDLE_ENV_VARS:
        env[name] = str(bundle)
    env["NODE_EXTRA_CA_CERTS"] = str(ca_cert)
    if windows:
        with_git_config(env, GIT_SCHANNEL_KEY, "true")
    return env


ENV_VAULT_DIR = "env"
STALE_AFTER = 60.0
RECORD_NOTICES = {
    "audit": "every request in full, secrets included, in clear text",
    "block": "every blocked request as the command sent it, secrets included, in clear text",
}


def record_notice(record: Path) -> str | None:
    try:
        mode = Config.load().mode
    except Exception:
        return None
    holds = RECORD_NOTICES.get(mode)
    if holds is None:
        return None
    return f"keyfence: mode is {mode}, so {record} will hold {holds} (file mode 0600)"


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


def build_env_vault(environ: Mapping[str, str], everything: bool = False,
                    config: Config | None = None) -> Vault:
    main = Vault()
    main.ensure_saved()
    ignore = config.ignore_list(main) if config else IgnoreList()
    directory = DEFAULT_DIR / ENV_VAULT_DIR
    directory.mkdir(parents=True, exist_ok=True)
    sweep_stale_env_vaults(directory)
    fd, name = tempfile.mkstemp(prefix="keyfence-env-", suffix=".json", dir=directory)
    os.close(fd)
    path = Path(name)
    path.unlink()
    env_vault = Vault(path=path, salt=main.salt)
    env_vault.add_many(env_values(environ, main.min_length, everything, ignore))
    return env_vault


def run(command: Sequence[str], port: int | None = None, everything: bool = False,
        timeout: float = 20.0, ca_cert: Path = CA_CERT, local: str | None = None,
        record: Path | None = None, linger: float = 0.0) -> int:
    if port is None:
        port = pick_port()
        if port != DEFAULT_PORT:
            print(f"keyfence: port {DEFAULT_PORT} is busy, using {port}", file=sys.stderr, flush=True)
    elif port_open(port):
        print(f"Port {port} is already in use. Pick another one with -p.")
        return 1
    try:
        config = Config.load()
    except ValueError as exc:
        print(f"error: {exc}")
        return 1
    env_vault = build_env_vault(os.environ, everything, config)
    proxy_env = dict(os.environ, **{ENV_VAULT_VAR: str(env_vault.path)})
    DEFAULT_DIR.mkdir(parents=True, exist_ok=True)
    proxy_log = (DEFAULT_DIR / "proxy.log").open("a")
    if local == "":
        local = Path(command[0]).name
    extra = []
    if record:
        notice = record_notice(record)
        if notice:
            print(notice, file=sys.stderr, flush=True)
        record.parent.mkdir(parents=True, exist_ok=True)
        record.touch(mode=0o600)
        with contextlib.suppress(OSError):
            os.chmod(record, 0o600)
        extra = ["-w", str(record)]
    try:
        proxy = start_proxy(port, proxy_env, proxy_log, timeout, ca_cert, local, extra)
    except ProxyError as exc:
        proxy_log.close()
        env_vault.remove_files()
        if exc.stage == MISSING:
            print(exc.message)
        else:
            print(f"{exc.message}, so the command was not started; see {DEFAULT_DIR / 'proxy.log'}")
        return 1
    try:
        try:
            bundle, _ = ensure_bundle(ca_cert)
        except BundleError as exc:
            print(exc)
            return 1
        code = subprocess.call(list(command), env=child_env(os.environ, port, ca_cert, bundle))
        if linger > 0 and proxy.poll() is None:
            print(f"keyfence: command exited, keeping the proxy up for {linger:.0f}s", flush=True)
            time.sleep(linger)
        return code
    finally:
        stop_proxy(proxy)
        proxy_log.close()
        env_vault.remove_files()
