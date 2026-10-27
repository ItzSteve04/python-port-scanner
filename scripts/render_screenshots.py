"""Render captured terminal text as PNGs; optional dependency: Pillow.

Run local_demo.py first, then `python scripts/render_screenshots.py`. The renderer
does not invent observations or substitute sample numbers into the captured text.
"""

import argparse
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]


def render(source: Path, destination: Path, title: str, font_path: str) -> None:
    """Draw all captured lines within a terminal frame, wrapping long commands."""
    font = ImageFont.truetype(font_path, 18)
    heading = ImageFont.truetype(font_path, 16)
    lines = []
    for line in source.read_text(encoding="utf-8").splitlines():
        lines.extend(
            textwrap.wrap(line, width=104, replace_whitespace=False, drop_whitespace=False) or [""]
        )
    width = 1200
    height = 100 + 28 * len(lines)
    image = Image.new("RGB", (width, height), "#0b1220")
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle(
        (14, 14, width - 14, height - 14), radius=15, fill="#111b2b", outline="#2c3c54"
    )
    draw.line((15, 66, width - 15, 66), fill="#2c3c54", width=1)
    for index, color in enumerate(("#f87171", "#fbbf24", "#34d399")):
        x = 35 + index * 23
        draw.ellipse((x, 34, x + 11, 45), fill=color)
    draw.text((132, 29), title, fill="#9aacbf", font=heading)
    for index, line in enumerate(lines):
        color = "#dce7f4"
        if line.startswith("$"):
            color = "#6ee7b7"
        elif "COMPLETE:" in line or "open=" in line:
            color = "#93c5fd"
        elif line.startswith("  banner"):
            color = "#fcd38d"
        draw.text((34, 82 + 28 * index), line, fill=color, font=font)
    destination.parent.mkdir(parents=True, exist_ok=True)
    image.save(destination)


def main() -> None:
    """Render the example scan and help captures using a chosen monospace font."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--font", default="/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf")
    arguments = parser.parse_args()
    for name, filename, title in (
        ("terminal-session.txt", "localhost-scan.png", "Python Port Scanner | localhost demo"),
        ("cli-help.txt", "cli-help.png", "Python Port Scanner | command reference"),
    ):
        render(ROOT / "examples" / name, ROOT / "docs" / "assets" / filename, title, arguments.font)


if __name__ == "__main__":
    main()
