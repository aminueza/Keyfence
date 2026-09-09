from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets as pysecrets
import tempfile
from collections.abc import Callable, Iterable
from pathlib import Path

try:
    import fcntl
except ImportError:
    fcntl = None

DEFAULT_DIR = Path(os.environ.get("KEYFENCE_HOME", Path.home() / ".keyfence"))
MIN_SECRET_LENGTH = 8
MAX_MIN_LENGTH = 256
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class VaultError(RuntimeError):
    pass


class Vault:
    def __init__(self, path: Path | None = None, salt: bytes | None = None):
        self.path = Path(path) if path else DEFAULT_DIR / "vault.json"
        self._salt: bytes = salt or b""
        self._hashes: set[str] = set()
        self._canaries: dict[str, str] = {}
        self.min_length: int = MIN_SECRET_LENGTH
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            if not self._salt:
                self._salt = pysecrets.token_bytes(32)
            return
        try:
            data = json.loads(self.path.read_text())
            salt = bytes.fromhex(data["salt"])
            hashes = data["hashes"]
            canaries = data.get("canaries", {})
            min_length = data.get("min_length", MIN_SECRET_LENGTH)
            if (len(salt) < 16 or not isinstance(hashes, list)
                    or not all(isinstance(h, str) and _DIGEST.match(h) for h in hashes)
                    or not isinstance(canaries, dict)
                    or not all(isinstance(k, str) and _DIGEST.match(k) and isinstance(v, str)
                               for k, v in canaries.items())
                    or isinstance(min_length, bool) or not isinstance(min_length, int)
                    or min_length > MAX_MIN_LENGTH):
                raise ValueError("unexpected field types")
            min_length = max(MIN_SECRET_LENGTH, min_length)
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            raise VaultError(
                f"{self.path} is not a valid keyfence vault ({exc}). Move it aside and "
                "register your secrets again with `keyfence import` or `keyfence add-secret`.") from None
        self._salt = salt
        self._hashes = set(hashes)
        self._canaries = dict(canaries)
        self.min_length = min_length

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({
            "salt": self._salt.hex(),
            "hashes": sorted(self._hashes),
            "canaries": dict(sorted(self._canaries.items())),
            "min_length": self.min_length,
        }, indent=2)
        fd, tmp = tempfile.mkstemp(prefix=self.path.name + ".", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(payload)
            with contextlib.suppress(OSError):
                os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except OSError as exc:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise VaultError(f"could not write {self.path}: {exc}") from None

    @property
    def lock_path(self) -> Path:
        return self.path.with_name(self.path.name + ".lock")

    def remove_files(self) -> None:
        for path in (self.path, self.lock_path):
            with contextlib.suppress(OSError):
                path.unlink()

    @contextlib.contextmanager
    def _locked(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.lock_path, "a+") as lock:
            if fcntl is not None:
                fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(lock, fcntl.LOCK_UN)

    def _update(self, mutate: Callable[[], int]) -> int:
        with self._locked():
            self._load()
            changed = mutate()
            self._save()
            return changed

    def ensure_saved(self) -> None:
        if not self.path.exists():
            with self._locked():
                self._load()
                if not self.path.exists():
                    self._save()

    @property
    def salt(self) -> bytes:
        return self._salt

    def _digest(self, value: str) -> str:
        return hmac.new(self._salt, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def placeholder_digest(self, value: str) -> str:
        return hmac.new(self._salt, b"placeholder:" + value.encode("utf-8"), hashlib.sha256).hexdigest()

    def add(self, value: str) -> bool:
        return self.add_many([value]) == 1

    def add_many(self, values: Iterable[str]) -> int:
        cleaned = [v.strip() for v in values]

        def mutate() -> int:
            before = len(self._hashes)
            for value in cleaned:
                if len(value) >= self.min_length:
                    self._hashes.add(self._digest(value))
            return len(self._hashes) - before

        return self._update(mutate)

    def add_canary(self, value: str, label: str) -> bool:
        value = value.strip()
        if len(value) < self.min_length:
            return False

        def mutate() -> int:
            self._canaries[self._digest(value)] = label
            return 1

        self._update(mutate)
        return True

    def merge(self, other: "Vault") -> None:
        if self.is_empty():
            self._salt = other.salt
        if other.salt != self._salt:
            raise ValueError("cannot merge vaults with different salts")
        self._hashes |= other._hashes
        self._canaries.update(other._canaries)

    def contains(self, value: str) -> bool:
        if self.is_empty():
            return False
        digest = self._digest(value)
        return digest in self._hashes or digest in self._canaries

    def canary_label(self, value: str) -> str | None:
        if not self._canaries:
            return None
        return self._canaries.get(self._digest(value))

    def is_empty(self) -> bool:
        return not self._hashes and not self._canaries

    def count(self) -> int:
        return len(self._hashes)

    def canary_count(self) -> int:
        return len(self._canaries)
