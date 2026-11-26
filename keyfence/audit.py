from __future__ import annotations

import json
from pathlib import Path

LINE_SEPARATOR = "\n"


def split_lines(text: str) -> list[str]:
    if not text:
        return []
    lines = text.split(LINE_SEPARATOR)
    if lines[-1] == "":
        lines.pop()
    return lines


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def encode_entry(entry: dict) -> str:
    return json.dumps(entry, ensure_ascii=True) + LINE_SEPARATOR
