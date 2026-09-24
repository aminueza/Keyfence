from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .detectors import shannon_entropy
from .ignore import IgnoreList
from .vault import Vault

NO_IGNORE = IgnoreList()

SECRET_WORDS = frozenset({
    "key", "token", "secret", "pass", "passwd", "password", "passphrase", "senha",
    "credential", "auth", "authorization", "api", "private", "session", "cookie",
    "bearer", "dsn", "pgpassword", "sshpass",
})
_LONGEST_SECRET_WORD = max(len(word) for word in SECRET_WORDS)
_NAME_SEGMENT = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+")
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


def _joins_secret_words(segment: str) -> bool:
    if not segment:
        return False
    reachable = {0}
    for end in range(1, len(segment) + 1):
        first = max(0, end - _LONGEST_SECRET_WORD)
        if any(start in reachable and segment[start:end] in SECRET_WORDS
               for start in range(first, end)):
            reachable.add(end)
    return len(segment) in reachable


def _segment_is_secret(segment: str) -> bool:
    return _joins_secret_words(segment) or (
        segment.endswith("s") and _joins_secret_words(segment[:-1]))


def _has_secret_name(key: str) -> bool:
    return any(_segment_is_secret(segment.lower()) for segment in _NAME_SEGMENT.findall(key))


def looks_secret(key: str, value: str, min_length: int) -> bool:
    if len(value) < min_length:
        return False
    if _has_secret_name(key):
        return True
    return len(value) >= 16 and shannon_entropy(value) >= 3.5


def _add(out: set[str], value: str | None, min_length: int, ignore: IgnoreList) -> None:
    if value and len(value) >= min_length and not ignore.ignores_value(value):
        out.add(value)


def _collect(key: str, value: str, min_length: int, everything: bool, out: set[str],
             ignore: IgnoreList = NO_IGNORE) -> None:
    if not value or _SKIP_VALUE.match(value) or ignore.ignores_key(key):
        return
    if (everything and len(value) >= min_length) or looks_secret(key, value, min_length):
        _add(out, value, min_length, ignore)
    _add(out, _url_password(value), min_length, ignore)


def values_from_text(text: str, min_length: int, everything: bool = False,
                     ignore: IgnoreList = NO_IGNORE) -> set[str]:
    found: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        _add(found, _url_password(stripped), min_length, ignore)
        m = _KV_LINE.match(line)
        if m:
            _collect(m["key"], _clean(m["val"]), min_length, everything, found, ignore)
            continue
        for pw in _NETRC_PASSWORD.findall(stripped):
            _add(found, pw, min_length, ignore)
    return found


def values_from_json(obj, min_length: int, everything: bool = False, key: str = "",
                     ignore: IgnoreList = NO_IGNORE) -> set[str]:
    found: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            found |= values_from_json(v, min_length, everything, str(k), ignore)
    elif isinstance(obj, list):
        for v in obj:
            found |= values_from_json(v, min_length, everything, key, ignore)
    elif isinstance(obj, str):
        _collect(key, obj, min_length, everything, found, ignore)
    return found


def values_from_file(path: Path, min_length: int, everything: bool = False,
                     ignore: IgnoreList = NO_IGNORE) -> set[str]:
    text = path.read_text(errors="replace")
    if path.suffix == ".json":
        try:
            return values_from_json(json.loads(text), min_length, everything, ignore=ignore)
        except ValueError:
            pass
    return values_from_text(text, min_length, everything, ignore)


def env_values(environ: Mapping[str, str], min_length: int, everything: bool = False,
               ignore: IgnoreList = NO_IGNORE) -> set[str]:
    found: set[str] = set()
    for name, value in environ.items():
        if name in ENV_SKIP_NAMES:
            continue
        _collect(name, value, min_length, everything, found, ignore)
    return found


def default_paths(cwd: Path | None = None) -> list[Path]:
    cwd = cwd or Path.cwd()
    paths = [p for p in sorted(cwd.glob(".env*")) if p.is_file() and not _EXAMPLE_FILE.search(p.name)]
    paths.extend(p for p in (Path(loc).expanduser() for loc in DEFAULT_LOCATIONS) if p.is_file())
    return paths


def import_files(vault: Vault, paths: Iterable[Path], everything: bool = False,
                 ignore: IgnoreList = NO_IGNORE) -> list[tuple[Path, int]]:
    report = []
    for path in paths:
        values = values_from_file(path, vault.min_length, everything, ignore)
        report.append((path, vault.add_many(values)))
    return report
