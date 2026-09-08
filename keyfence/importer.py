from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .detectors import shannon_entropy
from .vault import Vault

SECRET_NAME = re.compile(
    r"(?i)(?:key|token|secret|pass|passwd|password|senha|credential|auth|api|"
    r"private|session|cookie|bearer|dsn)")
_KV_LINE = re.compile(r"^\s*(?:export\s+)?(?P<key>[A-Za-z_/][A-Za-z0-9_.\-/:@]*)\s*[=:]\s*(?P<val>.+?)\s*$")
_NETRC_PASSWORD = re.compile(r"\bpassword\s+(\S+)")
_SKIP_VALUE = re.compile(r"^(?:\$\{|\$[A-Za-z_]|<|`|/|~|https?://[^@]*$)")
_EXAMPLE_FILE = re.compile(r"(?i)example|sample|template|dist$")

DEFAULT_LOCATIONS = (
    "~/.aws/credentials",
    "~/.netrc",
    "~/.npmrc",
    "~/.pypirc",
    "~/.git-credentials",
    "~/.docker/config.json",
)
ENV_SKIP_NAMES = frozenset({"KEYFENCE_HOME", "KEYFENCE_CONFIG", "KEYFENCE_ENV_VAULT",
                            "SSH_AUTH_SOCK", "GPG_AGENT_INFO", "PATH", "MANPATH"})


def _clean(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _url_password(value: str) -> str | None:
    if "://" not in value:
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    return unquote(parts.password) if parts.password else None


def looks_secret(key: str, value: str, min_length: int) -> bool:
    if len(value) < min_length:
        return False
    if SECRET_NAME.search(key):
        return True
    return len(value) >= 16 and shannon_entropy(value) >= 3.5


def _collect(key: str, value: str, min_length: int, everything: bool, out: set[str]) -> None:
    if not value or _SKIP_VALUE.match(value):
        return
    if everything and len(value) >= min_length:
        out.add(value)
    elif looks_secret(key, value, min_length):
        out.add(value)
    password = _url_password(value)
    if password and len(password) >= min_length:
        out.add(password)


def values_from_text(text: str, min_length: int, everything: bool = False) -> set[str]:
    found: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        password = _url_password(stripped)
        if password and len(password) >= min_length:
            found.add(password)
        m = _KV_LINE.match(line)
        if m:
            _collect(m["key"], _clean(m["val"]), min_length, everything, found)
            continue
        for pw in _NETRC_PASSWORD.findall(stripped):
            if len(pw) >= min_length:
                found.add(pw)
    return found


def values_from_json(obj, min_length: int, everything: bool = False, key: str = "") -> set[str]:
    found: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            found |= values_from_json(v, min_length, everything, str(k))
    elif isinstance(obj, list):
        for v in obj:
            found |= values_from_json(v, min_length, everything, key)
    elif isinstance(obj, str):
        _collect(key, obj, min_length, everything, found)
    return found


def values_from_file(path: Path, min_length: int, everything: bool = False) -> set[str]:
    text = path.read_text(errors="replace")
    if path.suffix == ".json":
        try:
            return values_from_json(json.loads(text), min_length, everything)
        except ValueError:
            pass
    return values_from_text(text, min_length, everything)


def env_values(environ: Mapping[str, str], min_length: int, everything: bool = False) -> set[str]:
    found: set[str] = set()
    for name, value in environ.items():
        if name in ENV_SKIP_NAMES:
            continue
        _collect(name, value, min_length, everything, found)
    return found


def default_paths(cwd: Path | None = None) -> list[Path]:
    cwd = cwd or Path.cwd()
    paths = [p for p in sorted(cwd.glob(".env*")) if p.is_file() and not _EXAMPLE_FILE.search(p.name)]
    paths.extend(p for p in (Path(loc).expanduser() for loc in DEFAULT_LOCATIONS) if p.is_file())
    return paths


def import_files(vault: Vault, paths: Iterable[Path], everything: bool = False) -> list[tuple[Path, int]]:
    report = []
    for path in paths:
        values = values_from_file(path, vault.min_length, everything)
        report.append((path, vault.add_many(values)))
    return report
