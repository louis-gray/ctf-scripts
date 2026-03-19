#!/usr/bin/env python3
"""gif_frame_diff.py — split an animated GIF into per-frame PNGs and report
which frames differ from their predecessor.

Usage
-----
    python gif_frame_diff.py <input.gif> <out-dir> [--montage montage.png]

Each frame is saved as ``<out-dir>/frame_NNNN.png``. A summary is printed
showing the bounding box of pixels that changed between frame N-1 and N,
which is usually where the steg payload is hiding.

If ``--montage`` is supplied, a grid image is also written stitching the
diff-region of each frame together side-by-side. Useful when the diff is a
single character per frame and you want to read the message at a glance.
"""
from __future__ import annotations

import argparse
import os

from PIL import Image, ImageChops


def diff_bbox(a: Image.Image, b: Image.Image) -> tuple[int, int, int, int] | None:
    diff = ImageChops.difference(a.convert("RGB"), b.convert("RGB"))
    return diff.getbbox()


def montage(crops: list[Image.Image], cols: int = 16) -> Image.Image:
    if not crops:
        return Image.new("RGBA", (1, 1))
    cw = max(c.width for c in crops)
    ch = max(c.height for c in crops)
    rows = (len(crops) + cols - 1) // cols
    canvas = Image.new("RGBA", (cw * cols, ch * rows), (0, 0, 0, 0))
    for i, crop in enumerate(crops):
        x = (i % cols) * cw
        y = (i // cols) * ch
        canvas.paste(crop, (x, y))
    return canvas


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("gif")
    ap.add_argument("out_dir")
    ap.add_argument("--montage", metavar="PATH", help="write a stitched montage of diff regions")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    img = Image.open(args.gif)
    prev: Image.Image | None = None
    crops: list[Image.Image] = []
    i = 0
    try:
        while True:
            frame = img.copy().convert("RGBA")
            frame.save(os.path.join(args.out_dir, f"frame_{i:04d}.png"))
            if prev is not None:
                bbox = diff_bbox(prev, frame)
                print(f"frame {i:4d}: bbox={bbox}")
                if args.montage and bbox is not None:
                    crops.append(frame.crop(bbox))
            prev = frame
            i += 1
            img.seek(i)
    except EOFError:
        pass

    if args.montage and crops:
        montage(crops).save(args.montage)
        print(f"montage of {len(crops)} diff regions -> {args.montage}")
    print(f"\nwrote {i} frames to {args.out_dir}/")


if __name__ == "__main__":
    main()
