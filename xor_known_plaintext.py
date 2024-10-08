#!/usr/bin/env python3
"""xor_known_plaintext.py — recover the XOR key (and surrounding plaintext)
from a ciphertext given a plaintext fragment you expect to find somewhere
inside it.

Usage
-----
    python xor_known_plaintext.py <ciphertext-hex> <crib>

`<ciphertext-hex>` is the ciphertext, hex-encoded.
`<crib>` is the known plaintext fragment as an ASCII string
(e.g. ``flag{`` or ``HTTP/1.1``).

The script slides the crib across every offset of the ciphertext, derives the
key fragment at that position, repeats it cyclically, and ranks candidates
by how printable the recovered plaintext is.
"""
from __future__ import annotations

import string
import sys

PRINTABLE = set(string.printable.encode())


def score(b: bytes) -> int:
    return sum(1 for x in b if x in PRINTABLE)


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
    if len(sys.argv) != 3:
        sys.exit("Usage: python xor_known_plaintext.py <ciphertext-hex> <crib>")
    ct = bytes.fromhex(sys.argv[1])
    crib = sys.argv[2].encode()
    for i, (off, key, pt) in enumerate(recover(ct, crib), 1):
        print(f"#{i} offset={off} key={key.hex()} score={score(pt)}")
        print(f"   pt={pt!r}")


if __name__ == "__main__":
    main()
