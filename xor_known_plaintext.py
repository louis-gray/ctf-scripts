#!/usr/bin/env python3
"""xor_known_plaintext.py — recover the XOR key (and surrounding plaintext)
from a ciphertext given a plaintext fragment you expect to find somewhere
inside it.

Usage
-----
    python xor_known_plaintext.py <ciphertext-hex> <crib> [--hex]

`<ciphertext-hex>` is the ciphertext, hex-encoded.
`<crib>` is the known plaintext fragment. By default it's interpreted as
an ASCII string (e.g. ``flag{`` or ``HTTP/1.1``). Pass ``--hex`` if your crib
contains arbitrary bytes (PNG header, gzip magic, etc.).

The script slides the crib across every offset of the ciphertext, derives the
key fragment at that position, repeats it cyclically, and ranks candidates
by how printable the recovered plaintext is.
"""
from __future__ import annotations

import argparse
import string

PRINTABLE = set(string.printable.encode())
# Letters + space are the strong signal: random XOR misalignments give plenty
# of printable punctuation, but rarely a high count of natural-language letters.
TEXTY = set((string.ascii_letters + " ").encode())


def score(b: bytes) -> int:
    """Composite score: lots of letters/spaces (strong) plus printable bonus."""
    letters = sum(1 for x in b if x in TEXTY)
    printable = sum(1 for x in b if x in PRINTABLE)
    return letters * 4 + printable


def recover(ct: bytes, crib: bytes, top: int = 5) -> list[tuple[int, bytes, bytes]]:
    """Return the top `top` (offset, key_fragment, plaintext_guess) by score."""
    candidates: list[tuple[int, bytes, bytes]] = []
    for off in range(0, len(ct) - len(crib) + 1):
        key = bytes(c ^ p for c, p in zip(ct[off:off + len(crib)], crib))
        # Repeat the key fragment over the full ciphertext, aligned so the
        # crib lines up at `off`.
        rotated = key[(-off) % len(key):] + key[:(-off) % len(key)]
        full = (rotated * ((len(ct) // len(key)) + 1))[:len(ct)]
        pt = bytes(c ^ k for c, k in zip(ct, full))
        candidates.append((off, key, pt))
    candidates.sort(key=lambda x: score(x[2]), reverse=True)
    return candidates[:top]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("ciphertext")
    ap.add_argument("crib")
    ap.add_argument("--hex", action="store_true",
                    help="interpret the crib as hex bytes rather than ASCII")
    args = ap.parse_args()

    ct = bytes.fromhex(args.ciphertext)
    crib = bytes.fromhex(args.crib) if args.hex else args.crib.encode()
    for i, (off, key, pt) in enumerate(recover(ct, crib), 1):
        print(f"#{i} offset={off} key={key.hex()} score={score(pt)}")
        print(f"   pt={pt!r}")


if __name__ == "__main__":
    main()
