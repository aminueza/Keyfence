from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets as pysecrets
from collections.abc import Iterable
from pathlib import Path

DEFAULT_DIR = Path(os.environ.get("KEYFENCE_HOME", Path.home() / ".keyfence"))
MIN_SECRET_LENGTH = 8


class Vault:
    def __init__(self, path: Path | None = None, salt: bytes | None = None):
        self.path = Path(path) if path else DEFAULT_DIR / "vault.json"
        self._salt: bytes = salt or b""
        self._hashes: set[str] = set()
        self._canaries: dict[str, str] = {}
        self.min_length: int = MIN_SECRET_LENGTH
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            data = json.loads(self.path.read_text())
            self._salt = bytes.fromhex(data["salt"])
            self._hashes = set(data["hashes"])
            self._canaries = dict(data.get("canaries", {}))
            self.min_length = max(
                MIN_SECRET_LENGTH, int(data.get("min_length", MIN_SECRET_LENGTH)))
        elif not self._salt:
            self._salt = pysecrets.token_bytes(32)

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({
            "salt": self._salt.hex(),
            "hashes": sorted(self._hashes),
            "canaries": dict(sorted(self._canaries.items())),
            "min_length": self.min_length,
        }, indent=2)
        self.path.write_text(payload)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def ensure_saved(self) -> None:
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
        before = len(self._hashes)
        for value in values:
            value = value.strip()
            if len(value) >= self.min_length:
                self._hashes.add(self._digest(value))
        self._save()
        return len(self._hashes) - before

    def add_canary(self, value: str, label: str) -> bool:
        value = value.strip()
        if len(value) < self.min_length:
            return False
        self._canaries[self._digest(value)] = label
        self._save()
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
