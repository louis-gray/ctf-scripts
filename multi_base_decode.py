#!/usr/bin/env python3
"""multi_base_decode.py — auto-detect and brute-decode common bases with
nested-layer DFS.

Usage
-----
    python multi_base_decode.py <input-file-or->     # `-` for stdin

Tries base16, base32, base58 (Bitcoin alphabet), base62, base64, base85 at
each layer, recursing on outputs that look text-like (>=90% printable ASCII).
Prints top candidates ranked by chi-squared distance from English letter
frequencies.
"""
from __future__ import annotations

import base64
import string
import sys
from collections import Counter

ENGLISH_FREQ = {
    "a": 8.17, "b": 1.49, "c": 2.78, "d": 4.25, "e": 12.70, "f": 2.23,
    "g": 2.02, "h": 6.09, "i": 6.97, "j": 0.15, "k": 0.77, "l": 4.03,
    "m": 2.41, "n": 6.75, "o": 7.51, "p": 1.93, "q": 0.10, "r": 5.99,
    "s": 6.33, "t": 9.06, "u": 2.76, "v": 0.98, "w": 2.36, "x": 0.15,
    "y": 1.97, "z": 0.07,
}

B58_ALPH = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B62_ALPH = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

PRINTABLE_BYTES = set(string.printable.encode())


def score_english(text: str) -> float:
    """Lower is better. Chi-squared distance from English letter frequencies
    on the letters-only lowercase projection of ``text``."""
    lower = "".join(c for c in text.lower() if c.isalpha())
    if not lower:
        return float("inf")
    counts = Counter(lower)
    n = len(lower)
    chi = 0.0
    for letter, expected_pct in ENGLISH_FREQ.items():
        expected = expected_pct / 100 * n
        observed = counts.get(letter, 0)
        if expected > 0:
            chi += (observed - expected) ** 2 / expected
    return chi


def is_mostly_printable(b: bytes, threshold: float = 0.9) -> bool:
    if not b:
        return False
    printable = sum(1 for c in b if c in PRINTABLE_BYTES)
    return printable / len(b) >= threshold


def _strip(blob: bytes) -> bytes:
    return bytes(c for c in blob if c not in b" \t\r\n")


def try_b16(blob: bytes) -> bytes | None:
    blob = _strip(blob)
    if not blob or len(blob) % 2:
        return None
    try:
        return base64.b16decode(blob, casefold=True)
    except Exception:
        return None


def try_b32(blob: bytes) -> bytes | None:
    blob = _strip(blob).upper()
    if not blob:
        return None
    pad = (-len(blob)) % 8
    blob = blob + b"=" * pad
    try:
        return base64.b32decode(blob, casefold=True)
    except Exception:
        return None


def _base_n_decode(blob: bytes, alphabet: bytes) -> bytes | None:
    blob = _strip(blob)
    if not blob:
        return None
    base = len(alphabet)
    n = 0
    for ch in blob:
        idx = alphabet.find(ch)
        if idx < 0:
            return None
        n = n * base + idx
    out = b""
    while n:
        n, r = divmod(n, 256)
        out = bytes([r]) + out
    zero_char = alphabet[0]
    leading = 0
    for ch in blob:
        if ch == zero_char:
            leading += 1
        else:
            break
    return b"\x00" * leading + out


def try_b58(blob: bytes) -> bytes | None:
    return _base_n_decode(blob, B58_ALPH)


def try_b62(blob: bytes) -> bytes | None:
    return _base_n_decode(blob, B62_ALPH)


def try_b64(blob: bytes) -> bytes | None:
    blob = _strip(blob)
    if not blob:
        return None
    pad = (-len(blob)) % 4
    padded = blob + b"=" * pad
    try:
        return base64.b64decode(padded, validate=True)
    except Exception:
        pass
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception:
        return None


def try_b85(blob: bytes) -> bytes | None:
    blob = _strip(blob)
    if not blob:
        return None
    try:
        return base64.b85decode(blob)
    except Exception:
        return None


BASES = [
    ("base64", try_b64),
    ("base32", try_b32),
    ("base16", try_b16),
    ("base85", try_b85),
    ("base58", try_b58),
    ("base62", try_b62),
]


def unwrap(blob: bytes, max_layers: int = 4) -> list[tuple[list[str], bytes]]:
    """DFS through nested encodings. Returns all leaf decodings as
    ``(chain, plaintext)`` pairs, sorted by best chi-squared English score."""
    results: list[tuple[list[str], bytes]] = []
    seen: set[bytes] = set()

    def dfs(current: bytes, chain: list[str]) -> None:
        if current in seen:
            return
        seen.add(current)
        if len(chain) >= max_layers:
            results.append((chain, current))
            return
        any_recursed = False
        for name, decoder in BASES:
            out = decoder(current)
            if out is None or out == current or out == b"":
                continue
            if is_mostly_printable(out):
                any_recursed = True
                dfs(out, chain + [name])
            else:
                results.append((chain + [name], out))
        if not any_recursed:
            results.append((chain, current))

    dfs(blob, [])

    def score(item: tuple[list[str], bytes]) -> float:
        try:
            return score_english(item[1].decode("latin-1", errors="replace"))
        except Exception:
            return float("inf")

    results.sort(key=score)
    return results


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("Usage: python multi_base_decode.py <input-file-or->")
    src = sys.argv[1]
    if src == "-":
        data = sys.stdin.buffer.read()
    else:
        with open(src, "rb") as fh:
            data = fh.read()
    chains = unwrap(data.strip())
    print("--- top decode candidates (best chi-squared English first) ---")
    for chain, leaf in chains[:10]:
        chain_str = " -> ".join(chain) if chain else "<no decoding>"
        preview = leaf[:80]
        print(f"  [{chain_str}]\n    {preview!r}")


if __name__ == "__main__":
    main()
