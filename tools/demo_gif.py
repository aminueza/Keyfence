from __future__ import annotations

import io
import re
import sys
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from keyfence import demo  # noqa: E402

SCALE = 2
WIDTH, HEIGHT = 880, 760
WRAP = 98
PAD = 28
LINE = 19
FONT_SIZE = 13
BG = (250, 250, 247)
FRAME = (31, 31, 31)
TEXT = (31, 31, 31)
DIM = (138, 138, 133)
GREEN = (46, 125, 91)
RED = (179, 38, 30)
CHROME = (239, 239, 234)
MONO = "/System/Library/Fonts/Menlo.ttc"
SANS = "/System/Library/Fonts/HelveticaNeue.ttc"
SECRETS = (demo.DEMO_TOKEN, demo.DEMO_PASSWORD)
HIGHLIGHTS = re.compile(r"\[REDACTED:[a-z-]+\]|<<SECRET_[0-9a-f]+>>|HTTP 403|" + "|".join(map(re.escape, SECRETS)))


def output_lines() -> list[str]:
    buf = io.StringIO()
    demo.run(buf)
    lines: list[str] = []
    for raw in buf.getvalue().splitlines():
        raw = raw.rstrip()
        if len(raw) <= WRAP:
            lines.append(raw)
            continue
        indent = " " * (len(raw) - len(raw.lstrip()))
        lines.extend(textwrap.wrap(raw, WRAP, initial_indent="", subsequent_indent=indent + "    ",
                                   break_long_words=False, break_on_hyphens=False))
    return lines


def colour(token: str) -> tuple[int, int, int]:
    if token in SECRETS or token == "HTTP 403":
        return RED
    return GREEN


def draw_line(draw: ImageDraw.ImageDraw, x: int, y: int, text: str, font, dim: bool = False) -> None:
    pos = 0
    for m in HIGHLIGHTS.finditer(text):
        before = text[pos:m.start()]
        draw.text((x, y), before, font=font, fill=DIM if dim else TEXT)
        x += draw.textlength(before, font=font)
        draw.text((x, y), m.group(), font=font, fill=colour(m.group()))
        x += draw.textlength(m.group(), font=font)
        pos = m.end()
    draw.text((x, y), text[pos:], font=font, fill=DIM if dim else TEXT)


def frame(prompt: str, lines: list[str], mono, sans, cursor: bool) -> Image.Image:
    im = Image.new("RGB", (WIDTH * SCALE, HEIGHT * SCALE), BG)
    draw = ImageDraw.Draw(im)
    draw.rounded_rectangle((0, 0, WIDTH * SCALE - 1, HEIGHT * SCALE - 1), radius=12 * SCALE, outline=FRAME, width=2, fill=BG)
    draw.rectangle((2, 2, WIDTH * SCALE - 3, 30 * SCALE), fill=CHROME)
    for i, c in enumerate(((255, 95, 87), (255, 189, 46), (39, 201, 63))):
        cx = (14 + i * 20) * SCALE
        draw.ellipse((cx, 9 * SCALE, cx + 12 * SCALE, 21 * SCALE), fill=c)
    draw.text((WIDTH * SCALE // 2, 15 * SCALE), "keyfence demo", font=sans, fill=DIM, anchor="mm")
    y = (30 + PAD) * SCALE
    x = PAD * SCALE
    draw.text((x, y), "$ ", font=mono, fill=DIM)
    px = x + draw.textlength("$ ", font=mono)
    draw.text((px, y), prompt, font=mono, fill=TEXT)
    if cursor:
        cx = px + draw.textlength(prompt, font=mono) + 2 * SCALE
        draw.rectangle((cx, y, cx + 7 * SCALE, y + FONT_SIZE * SCALE + 2 * SCALE), fill=TEXT)
    y += LINE * SCALE * 2
    for line in lines:
        dim = line.startswith("mode:") is False and (line.startswith("    provider") or line.startswith("    model") or line.startswith("Every") or line.startswith("Try"))
        if line.startswith("mode:"):
            draw.text((x, y), line, font=mono, fill=TEXT)
        else:
            draw_line(draw, x, y, line, mono, dim=dim and not HIGHLIGHTS.search(line))
        y += LINE * SCALE
    return im


def build(out: Path) -> None:
    mono = ImageFont.truetype(MONO, FONT_SIZE * SCALE)
    sans = ImageFont.truetype(SANS, 12 * SCALE)
    lines = output_lines()
    frames: list[Image.Image] = []
    durations: list[int] = []
    command = "keyfence demo"
    for i in range(1, len(command) + 1):
        frames.append(frame(command[:i], [], mono, sans, cursor=True))
        durations.append(70)
    frames.append(frame(command, [], mono, sans, cursor=False))
    durations.append(400)
    shown: list[str] = []
    for line in lines:
        shown.append(line)
        frames.append(frame(command, shown, mono, sans, cursor=False))
        durations.append(60 if not line.strip() else (900 if line.startswith("mode:") else 220))
    durations[-1] = 4500
    target = (1200, int(HEIGHT * 1200 / WIDTH))
    small = [f.resize(target, Image.LANCZOS).quantize(colors=64, method=Image.MEDIANCUT) for f in frames]
    small[0].save(out, save_all=True, append_images=small[1:], duration=durations, loop=0, optimize=True, disposal=1)


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("docs/keyfence-demo.gif")
    build(target)
    print(target, target.stat().st_size // 1024, "KB")
