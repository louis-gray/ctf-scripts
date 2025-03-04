#!/usr/bin/env python3
"""gif_frame_diff.py — split an animated GIF into per-frame PNGs and report
which frames differ from their predecessor.

Usage
-----
    python gif_frame_diff.py <input.gif> <out-dir>

Each frame is saved as ``<out-dir>/frame_NNNN.png``. A summary is printed
showing the bounding box of pixels that changed between frame N-1 and N,
which is usually where the steg payload is hiding.
"""
from __future__ import annotations

import os
import sys

from PIL import Image, ImageChops


def diff_bbox(a: Image.Image, b: Image.Image) -> tuple[int, int, int, int] | None:
    diff = ImageChops.difference(a.convert("RGB"), b.convert("RGB"))
    return diff.getbbox()


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit("Usage: python gif_frame_diff.py <input.gif> <out-dir>")
    src, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    img = Image.open(src)
    prev: Image.Image | None = None
    i = 0
    try:
        while True:
            frame = img.copy().convert("RGBA")
            frame.save(os.path.join(out, f"frame_{i:04d}.png"))
            if prev is not None:
                bbox = diff_bbox(prev, frame)
                print(f"frame {i:4d}: bbox={bbox}")
            prev = frame
            i += 1
            img.seek(i)
    except EOFError:
        pass
    print(f"\nwrote {i} frames to {out}/")


if __name__ == "__main__":
    main()
