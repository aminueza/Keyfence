from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"
HEADING = re.compile(r"^## (\S+)(.*)$", re.M)


def version_of(tag: str) -> str:
    return tag[1:] if tag.startswith("v") else tag


def section(text: str, tag: str) -> str:
    version = version_of(tag)
    headings = list(HEADING.finditer(text))
    for index, match in enumerate(headings):
        if match.group(1) != version:
            continue
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        body = text[match.end():end].strip()
        if not body:
            raise SystemExit(f"the {version} section of CHANGELOG.md is empty")
        return body
    known = ", ".join(m.group(1) for m in headings[:5])
    raise SystemExit(f"CHANGELOG.md has no section for {version}; it starts with {known}")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: release_notes.py <tag>", file=sys.stderr)
        return 2
    print(section(CHANGELOG.read_text(), args[0]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
