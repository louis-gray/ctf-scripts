#!/usr/bin/env python3
"""lsb_image_extract.py — extract data hidden in the least-significant bits
of an image, or visualise the bit-planes for inspection.

Usage
-----
    python lsb_image_extract.py <image> [--bits N] [--channels rgb|r|g|b|a]
    python lsb_image_extract.py <image> --planes <out-dir>

In ``extract`` mode (default), output is written to stdout as raw bytes.
``--bits N`` reads ``N`` low-order bits per channel (default ``1``).
``--channels`` selects which channels to read (default ``rgb``).

In ``--planes`` mode, eight images named ``plane_0.png`` … ``plane_7.png``
are written to the output directory. Each pixel is set to white if that
bit is ``1`` in the corresponding channel of the source. Bit 0 is the LSB
(usually where steg lives); bit 7 is the MSB (usually the actual image).
"""
from __future__ import annotations

import argparse
import os
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


def visualise_planes(path: str, out_dir: str) -> None:
    img = Image.open(path).convert("L")
    w, h = img.size
    pixels = img.load()
    assert pixels is not None
    os.makedirs(out_dir, exist_ok=True)
    for bit in range(8):
        plane = Image.new("L", (w, h))
        pp = plane.load()
        assert pp is not None
        for y in range(h):
            for x in range(w):
                pp[x, y] = 255 if (pixels[x, y] >> bit) & 1 else 0
        plane.save(os.path.join(out_dir, f"plane_{bit}.png"))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--bits", type=int, default=1)
    ap.add_argument("--channels", default="rgb")
    ap.add_argument("--planes", metavar="OUT_DIR",
                    help="write per-bit-plane images instead of extracting")
    args = ap.parse_args()
    if args.planes:
        visualise_planes(args.image, args.planes)
    else:
        sys.stdout.buffer.write(extract(args.image, args.bits, args.channels))


if __name__ == "__main__":
    main()
