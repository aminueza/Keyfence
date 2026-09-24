from __future__ import annotations

import sys
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from keyfence import demo  # noqa: E402

SCALE = 2
WIDTH, HEIGHT = 880, 880
WRAP = 98
PAD = 28
LINE = 19
FONT_SIZE = 13
BG = (24, 25, 27)
FRAME = (58, 60, 64)
TEXT = (226, 226, 222)
DIM = (128, 130, 134)
GREEN = (98, 200, 140)
RED = (240, 110, 100)
CHROME = (38, 40, 43)
MONO = "/System/Library/Fonts/Menlo.ttc"
SANS = "/System/Library/Fonts/HelveticaNeue.ttc"
SECRETS = (demo.DEMO_TOKEN, demo.DEMO_PASSWORD)
HIGHLIGHTS = demo.HIGHLIGHT


def output_lines() -> list[tuple[str, str]]:
    lines: list[tuple[str, str]] = []
    for kind, raw in demo.lines()[2:]:
        if kind == "mode":
            name, description = raw.split("\t", 1)
            lines.append((kind, f"{name:<12} {description}"))
            continue
        raw = raw.rstrip()
        if len(raw) <= WRAP:
            lines.append((kind, raw))
            continue
        indent = " " * (len(raw) - len(raw.lstrip()))
        lines.extend((kind, part) for part in textwrap.wrap(
            raw, WRAP, initial_indent="", subsequent_indent=indent + "    ",
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


def frame(prompt: str, lines: list[tuple[str, str]], mono, sans, cursor: bool) -> Image.Image:
    im = Image.new("RGB", (WIDTH * SCALE, HEIGHT * SCALE), BG)
    draw = ImageDraw.Draw(im)
    draw.rounded_rectangle((0, 0, WIDTH * SCALE - 1, HEIGHT * SCALE - 1), radius=12 * SCALE, outline=FRAME, width=2, fill=BG)
    draw.rounded_rectangle((2, 2, WIDTH * SCALE - 3, 30 * SCALE + 12 * SCALE), radius=12 * SCALE, fill=CHROME)
    draw.rectangle((2, 30 * SCALE, WIDTH * SCALE - 3, 30 * SCALE + 12 * SCALE), fill=BG)
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
    for kind, line in lines:
        if kind == "mode":
            name, description = line[:12], line[12:]
            draw.text((x, y), name, font=mono, fill=TEXT)
            draw.text((x + draw.textlength(name, font=mono), y), description, font=mono, fill=DIM)
        else:
            draw_line(draw, x, y, line, mono, dim=kind == "dim")
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
    shown: list[tuple[str, str]] = []
    for kind, line in lines:
        shown.append((kind, line))
        frames.append(frame(command, shown, mono, sans, cursor=False))
        durations.append(60 if not line.strip() else (900 if kind == "mode" else 220))
    durations[-1] = 4500
    target = (1200, int(HEIGHT * 1200 / WIDTH))
    small = [f.resize(target, Image.LANCZOS).quantize(colors=64, method=Image.MEDIANCUT) for f in frames]
    small[0].save(out, save_all=True, append_images=small[1:], duration=durations, loop=0, optimize=True, disposal=1)


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("docs/keyfence-demo.gif")
    build(target)
    print(target, target.stat().st_size // 1024, "KB")
