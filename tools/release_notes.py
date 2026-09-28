from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"
HEADING = re.compile(r"^## (\S+)(.*)$", re.M)
LEAD_END = re.compile(r"(?<=[\w`)\]])[.:;](?=\s)")
TOPICS = 2
TOPIC_CHARS = 72
SINGLE_CHARS = 140
DANGLING = ("of", "and", "the", "with", "for", "to", "in", "on", "by", "a", "an", "that", "its", "it", "or", "no", "not", "into", "from", "as", "at", "so")


def version_of(tag: str) -> str:
    return tag[1:] if tag.startswith("v") else tag


def _heading(text: str, tag: str):
    version = version_of(tag)
    headings = list(HEADING.finditer(text))
    for index, match in enumerate(headings):
        if match.group(1) == version:
            end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
            return match, text[match.end():end].strip()
    known = ", ".join(m.group(1) for m in headings[:5])
    raise SystemExit(f"CHANGELOG.md has no section for {version}; it starts with {known}")


def section(text: str, tag: str) -> str:
    _, body = _heading(text, tag)
    if not body:
        raise SystemExit(f"the {version_of(tag)} section of CHANGELOG.md is empty")
    return body


def entries(body: str) -> list[str]:
    found: list[str] = []
    current = None
    intro: list[str] = []
    for line in body.splitlines():
        if line.startswith("- "):
            break
        if line.strip():
            intro.append(line.strip())
    if intro:
        found.append(" ".join(intro))
    for line in body.splitlines():
        if line.startswith("- "):
            if current:
                found.append(current)
            current = line[2:].strip()
        elif current is not None and line.startswith("  "):
            current = f"{current} {line.strip()}"
        elif current is not None and not line.strip():
            continue
    if current:
        found.append(current)
    return found or [body.splitlines()[0].strip()]


def lead(entry: str, budget: int = TOPIC_CHARS) -> str:
    quoted = False
    for index, char in enumerate(entry):
        if char == "`":
            quoted = not quoted
        elif not quoted and LEAD_END.match(entry, index):
            entry = entry[:index]
            break
    entry = entry.strip().rstrip(".")
    if len(entry) <= budget:
        return entry
    head = entry[:budget]
    cut = head.rfind(",")
    head = head[:cut] if cut > budget // 2 else head.rsplit(" ", 1)[0]
    words = head.split()
    while words and words[-1].strip("`,").lower() in DANGLING:
        words.pop()
    return " ".join(words).rstrip(",") + "…"


def anchor(heading) -> str:
    title = f"{heading.group(1)}{heading.group(2)}".strip().lower()
    return re.sub(r"[^\w -]", "", title).replace(" ", "-")


def summary(text: str, tag: str) -> str:
    heading, body = _heading(text, tag)
    if not body:
        raise SystemExit(f"the {version_of(tag)} section of CHANGELOG.md is empty")
    found = entries(body)
    budget = SINGLE_CHARS if len(found) == 1 else TOPIC_CHARS
    topics = "; ".join(lead(entry, budget) for entry in found[:TOPICS])
    rest = len(found) - TOPICS
    if rest > 0:
        topics = f"{topics}; and {rest} more change{'s' if rest > 1 else ''}"
    repo = os.environ.get("GITHUB_REPOSITORY")
    where = (f"[CHANGELOG.md](https://github.com/{repo}/blob/{tag}/CHANGELOG.md#{anchor(heading)})"
             if repo else "CHANGELOG.md")
    stop = "" if topics.endswith("…") else "."
    return f"{topics}{stop} Full notes in {where}."


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    full = "--full" in args
    rest = [arg for arg in args if arg != "--full"]
    if len(rest) != 1:
        print("usage: release_notes.py [--full] <tag>", file=sys.stderr)
        return 2
    text = CHANGELOG.read_text()
    print(section(text, rest[0]) if full else summary(text, rest[0]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
