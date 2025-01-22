#!/usr/bin/env python3
"""cbc_bitflip.py — block-level bit-flipping primitive for attacks against
CBC-encrypted data where the plaintext of one block is known.

Usage
-----
Import ``flip`` and call it with the previous ciphertext block, the known
plaintext of the *target* block, and the desired plaintext you want the
target block to decrypt to::

    from cbc_bitflip import flip

    new_prev = flip(prev_block, b"role=user;admin=0", b"role=user;admin=1")

Splice ``new_prev`` back into the ciphertext in place of ``prev_block`` and
re-submit. The target block now decrypts to the desired plaintext while the
preceding block decrypts to garbage.

Block size is inferred from the inputs — they must all be the same length.

This is a deliberately tiny module. It exists because every CBC-malleability
challenge ends up wanting the same three-line XOR and it's nicer to import
it than to retype it.
"""
from __future__ import annotations


def flip(prev_ct: bytes, known_pt: bytes, desired_pt: bytes) -> bytes:
    """Return a replacement for ``prev_ct`` such that the next block decrypts
    to ``desired_pt`` instead of ``known_pt``."""
    if not (len(prev_ct) == len(known_pt) == len(desired_pt)):
        raise ValueError("all three inputs must share a length")
    return bytes(p ^ k ^ d for p, k, d in zip(prev_ct, known_pt, desired_pt))


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4:
        sys.exit("Usage: python cbc_bitflip.py <prev-ct-hex> <known-pt-hex> <desired-pt-hex>")
    a = bytes.fromhex(sys.argv[1])
    b = bytes.fromhex(sys.argv[2])
    c = bytes.fromhex(sys.argv[3])
    print(flip(a, b, c).hex())
