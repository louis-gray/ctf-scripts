#!/usr/bin/env python3
"""lsb_image_extract.py — extract data hidden in the least-significant bits
of an image.

Usage
-----
    python lsb_image_extract.py <image> [--bits N] [--channels rgb|r|g|b|a]

`<image>` is anything Pillow can open (PNG, BMP, lossless WebP).
``--bits N`` reads ``N`` low-order bits per channel (default ``1``).
``--channels`` selects which channels to read in scanline order
(default ``rgb``: red, green, blue per pixel).

Output is written to stdout as raw bytes. Pipe into ``file -`` to identify
the embedded payload, or redirect to a file.
"""
from __future__ import annotations

import argparse
import sys

from PIL import Image


def extract(path: str, bits: int, channels: str) -> bytes:
    img = Image.open(path).convert("RGBA")
    w, h = img.size
    pixels = img.load()
    assert pixels is not None

    chan_idx = {"r": 0, "g": 1, "b": 2, "a": 3}
    order = [chan_idx[c] for c in channels]
    mask = (1 << bits) - 1

    bit_buf = 0
    bit_count = 0
    out = bytearray()
    for y in range(h):
        for x in range(w):
            px = pixels[x, y]
            for c in order:
                bit_buf = (bit_buf << bits) | (px[c] & mask)
                bit_count += bits
                while bit_count >= 8:
                    bit_count -= 8
                    out.append((bit_buf >> bit_count) & 0xFF)
                    bit_buf &= (1 << bit_count) - 1
    return bytes(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--bits", type=int, default=1)
    ap.add_argument("--channels", default="rgb")
    args = ap.parse_args()
    sys.stdout.buffer.write(extract(args.image, args.bits, args.channels))


if __name__ == "__main__":
    main()
