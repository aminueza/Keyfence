from __future__ import annotations

import codecs
import json
from typing import Any

JsonPath = tuple[Any, ...]


def restore(text: str, mapping: dict[str, str]) -> str:
    for token, original in mapping.items():
        if token in text:
            text = text.replace(token, original)
    return text


def partial_suffix(text: str, tokens: tuple[str, ...], max_len: int) -> str:
    window = max(0, len(text) - max_len + 1)
    for i in range(window, len(text)):
        if text[i] != "<":
            continue
        suffix = text[i:]
        if any(t.startswith(suffix) and suffix != t for t in tokens):
            return suffix
    return ""


def _map_strings(obj, fn, path: JsonPath = ()):
    if isinstance(obj, str):
        return fn(path, obj)
    if isinstance(obj, list):
        return [_map_strings(v, fn, path + (i,)) for i, v in enumerate(obj)]
    if isinstance(obj, dict):
        return {k: _map_strings(v, fn, path + (k,)) for k, v in obj.items()}
    return obj


class Event:
    def __init__(self, raw: str):
        self.raw = raw
        self.lines = raw.split("\n")
        self.data_index = next(
            (i for i, line in enumerate(self.lines) if line.startswith("data:")), None)
        self.obj = None
        self.dirty = False
        if self.data_index is not None:
            try:
                self.obj = json.loads(self.lines[self.data_index][5:].strip())
            except ValueError:
                self.obj = None

    def get(self, path: JsonPath):
        node = self.obj
        for key in path:
            node = node[key]
        return node

    def set(self, path: JsonPath, value) -> None:
        node = self.obj
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
        self.dirty = True

    def render(self) -> str:
        if not self.dirty:
            return self.raw
        lines = list(self.lines)
        lines[self.data_index] = "data: " + json.dumps(
            self.obj, ensure_ascii=False, separators=(",", ":"))
        return "\n".join(lines)


class SSERestorer:
    def __init__(self, mapping: dict[str, str]):
        self.mapping = mapping
        self.tokens = tuple(mapping)
        self.max_len = max(len(t) for t in self.tokens)
        self.decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self.pending = ""
        self.queue: list[Event] = []
        self.held: dict[JsonPath, tuple[Event, str]] = {}

    def feed(self, chunk: bytes) -> bytes:
        final = chunk == b""
        self.pending += self.decoder.decode(chunk, final)
        out: list[str] = []
        while True:
            boundary = self._next_boundary()
            if boundary is None:
                break
            raw, self.pending = self.pending[:boundary], self.pending[boundary:]
            self._process(Event(raw))
            if not self.held:
                out.extend(self._drain())
        if final:
            if self.pending:
                self._process(Event(self.pending))
                self.pending = ""
            self.held.clear()
            out.extend(self._drain())
        return "".join(out).encode("utf-8")

    def stream(self, chunk: bytes) -> list[bytes]:
        data = self.feed(chunk)
        return [data] if data else []

    def _next_boundary(self) -> int | None:
        candidates = [
            self.pending.find(sep) + len(sep)
            for sep in ("\n\n", "\r\n\r\n")
            if self.pending.find(sep) != -1
        ]
        return min(candidates) if candidates else None

    def _process(self, event: Event) -> None:
        self.queue.append(event)
        if not isinstance(event.obj, (dict, list)):
            return

        def fn(path: JsonPath, s: str) -> str:
            previous = self.held.pop(path, None)
            if previous is not None:
                prev_event, partial = previous
                prev_event.set(path, prev_event.get(path)[:-len(partial)])
                s = partial + s
            s = restore(s, self.mapping)
            suffix = partial_suffix(s, self.tokens, self.max_len)
            if suffix:
                self.held[path] = (event, suffix)
            return s

        new_obj = _map_strings(event.obj, fn)
        if new_obj != event.obj:
            event.obj = new_obj
            event.dirty = True

    def _drain(self) -> list[str]:
        rendered = [e.render() for e in self.queue]
        self.queue.clear()
        return rendered
