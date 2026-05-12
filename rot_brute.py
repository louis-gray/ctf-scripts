#!/usr/bin/env python3
"""rot_brute.py — brute ROT-N, Caesar, and Atbash, ranked by chi-squared
distance from English letter frequencies.

Usage
-----
    python rot_brute.py <input-file-or->     # `-` for stdin
"""
from __future__ import annotations

import sys
from collections import Counter

ENGLISH_FREQ = {
    "a": 8.17, "b": 1.49, "c": 2.78, "d": 4.25, "e": 12.70, "f": 2.23,
    "g": 2.02, "h": 6.09, "i": 6.97, "j": 0.15, "k": 0.77, "l": 4.03,
    "m": 2.41, "n": 6.75, "o": 7.51, "p": 1.93, "q": 0.10, "r": 5.99,
    "s": 6.33, "t": 9.06, "u": 2.76, "v": 0.98, "w": 2.36, "x": 0.15,
    "y": 1.97, "z": 0.07,
}


def rot(text: str, n: int) -> str:
    """ROT-N preserving case and non-letters."""
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + n) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + n) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def atbash(text: str) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr(ord("z") - (ord(ch) - ord("a"))))
        elif "A" <= ch <= "Z":
            out.append(chr(ord("Z") - (ord(ch) - ord("A"))))
        else:
            out.append(ch)
    return "".join(out)


def score_english(text: str) -> float:
    """Lower is better. Chi-squared distance from English letter frequencies."""
    letters = [c for c in text.lower() if c.isalpha()]
    if not letters:
        return float("inf")
    counts = Counter(letters)
    n = len(letters)
    chi = 0.0
    for letter, expected_pct in ENGLISH_FREQ.items():
        expected = expected_pct / 100 * n
        observed = counts.get(letter, 0)
        if expected > 0:
            chi += (observed - expected) ** 2 / expected
    return chi


def brute(text: str, top: int = 5) -> list[tuple[str, str, float]]:
    """Return ``[(plaintext, label, score), ...]`` for ROT-1..25 and Atbash,
    sorted ascending by score (best first), truncated to ``top``."""
    candidates: list[tuple[str, str, float]] = []
    for n in range(1, 26):
        pt = rot(text, n)
        candidates.append((pt, f"rot-{n}", score_english(pt)))
    pt = atbash(text)
    candidates.append((pt, "atbash", score_english(pt)))
    candidates.sort(key=lambda x: x[2])
    return candidates[:top]


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("Usage: python rot_brute.py <input-file-or->")
    src = sys.argv[1]
    if src == "-":
        text = sys.stdin.read()
    else:
        with open(src) as fh:
            text = fh.read()
    print("--- top candidates (lower chi-squared = more English) ---")
    for pt, label, sc in brute(text, top=5):
        preview = pt[:80].replace("\n", " ")
        print(f"  {label:8s}  chi={sc:7.2f}  {preview!r}")


if __name__ == "__main__":
    main()
