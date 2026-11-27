from __future__ import annotations

import codecs
import json
from typing import Any

from .detectors import string_value_spans, string_key_spans

JsonPath = tuple[Any, ...]


NESTED_JSON_FIELDS = ("partial_json", "arguments")
RESPONSES_API_DELTA_EVENT = "response.function_call_arguments.delta"


def json_escaped(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)[1:-1]


def restore(text: str, mapping: dict[str, str], escape: int = 0) -> str:
    for token, original in mapping.items():
        if token in text:
            value = original
            for _ in range(escape):
                value = json_escaped(value)
            text = text.replace(token, value)
    return text


def _is_arguments_delta(text: str) -> bool:
    if RESPONSES_API_DELTA_EVENT not in text:
        return False
    try:
        obj = json.loads(text)
    except ValueError:
        return False
    return isinstance(obj, dict) and obj.get("type") == RESPONSES_API_DELTA_EVENT


def restore_json(text: str, mapping: dict[str, str]) -> str:
    parts: list[str] = []
    pos = 0
    arguments_delta = _is_arguments_delta(text)
    for start, end, key in string_value_spans(text):
        parts.append(text[pos:start])
        value = text[start:end]
        if arguments_delta and key == "delta":
            extra = 2
        elif key in NESTED_JSON_FIELDS and value and (value[0] == "{" or value[0] == "["):
            extra = 2
        else:
            extra = 1
        parts.append(restore(value, mapping, extra))
        pos = end
    parts.append(text[pos:])

    text_with_restored_values = "".join(parts)
    parts = []
    pos = 0
    for start, end in string_key_spans(text_with_restored_values):
        parts.append(text_with_restored_values[pos:start])
        key_value = text_with_restored_values[start:end]
        parts.append(restore(key_value, mapping, 1))
        pos = end
    parts.append(text_with_restored_values[pos:])
    return "".join(parts)


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


def _choice_index(obj, path: JsonPath):
    if not isinstance(obj, dict) or path[:1] != ("choices",) or len(path) < 2:
        return None
    choice = obj["choices"][path[1]]
    index = choice.get("index") if isinstance(choice, dict) else None
    return index if isinstance(index, int) else path[1]


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
        self.held: dict[tuple, tuple[Event, str]] = {}

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

    def _block_index(self, event: Event):
        if isinstance(event.obj, dict):
            if "output_index" in event.obj:
                return (event.obj["output_index"], event.obj.get("content_index"))
            return event.obj.get("index")
        return None

    def _release_held(self, index, whole_item: bool = False) -> None:
        keys_to_remove = [
            k for k in self.held
            if k[1] == index or (whole_item and isinstance(k[1], tuple) and k[1][0] == index[0])
        ]
        for key in keys_to_remove:
            self.held.pop(key)

    def _process(self, event: Event) -> None:
        self.queue.append(event)
        if not isinstance(event.obj, (dict, list)):
            return

        obj = event.obj
        index = self._block_index(event)
        event_type = obj.get("type") if isinstance(obj, dict) else None

        if event_type == "content_block_stop":
            self._release_held(index)
            return
        typed = isinstance(event_type, str)
        if typed and event_type.endswith(".done"):
            self._release_held(index, whole_item=event_type == "response.output_item.done" and isinstance(index, tuple))
        complete = typed and event_type.startswith("response.") and not event_type.endswith(".delta")
        family = event_type.removesuffix(".delta").removesuffix(".done") if typed else None

        def fn(path: JsonPath, s: str) -> str:
            held_key = (path, _choice_index(obj, path) if index is None else index, family)
            previous = self.held.pop(held_key, None)
            if previous is not None:
                prev_event, partial = previous
                prev_event.set(path, prev_event.get(path)[:-len(partial)])
                s = partial + s
            json_key = path[-1] if path else None
            if json_key in NESTED_JSON_FIELDS:
                escape = 1
            elif event_type == RESPONSES_API_DELTA_EVENT and json_key == "delta":
                escape = 1
            else:
                escape = 0
            s = restore(s, self.mapping, escape)
            suffix = None if complete or "logprobs" in path else partial_suffix(s, self.tokens, self.max_len)
            if suffix:
                self.held[held_key] = (event, suffix)
            return s

        new_obj = _map_strings(event.obj, fn)
        if new_obj != event.obj:
            event.obj = new_obj
            event.dirty = True
        choices = obj.get("choices") if event_type is None and isinstance(obj, dict) else None
        for position, choice in enumerate(choices if isinstance(choices, list) else []):
            if isinstance(choice, dict) and choice.get("finish_reason"):
                self._release_held(choice["index"] if isinstance(choice.get("index"), int) else position)

    def _drain(self) -> list[str]:
        rendered = [e.render() for e in self.queue]
        self.queue.clear()
        return rendered
