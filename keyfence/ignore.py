from __future__ import annotations

import fnmatch
from collections.abc import Iterable

from .vault import value_digest


class IgnoreList:
    def __init__(self, salt: bytes = b"", keys: Iterable[str] = (), values: Iterable[str] = ()):
        self._salt = salt
        self._keys = tuple(dict.fromkeys(k.lower() for k in keys))
        self._digests = frozenset(value_digest(salt, v) for v in values)

    @property
    def key_count(self) -> int:
        return len(self._keys)

    @property
    def value_count(self) -> int:
        return len(self._digests)

    def ignores_key(self, key: str | None) -> bool:
        if not key or not self._keys:
            return False
        key = key.lower()
        for pattern in self._keys:
            if "*" in pattern or "?" in pattern:
                if fnmatch.fnmatchcase(key, pattern):
                    return True
            elif key == pattern:
                return True
        return False

    def ignores_value(self, value: str) -> bool:
        return bool(self._digests) and value_digest(self._salt, value) in self._digests

    def ignores(self, key: str | None, value: str) -> bool:
        return self.ignores_key(key) or self.ignores_value(value)
