#!/usr/bin/env python3
"""vigenere_break.py — find the key length and recover the key for a
Vigenère cipher over alphabetic text.

Usage
-----
    python vigenere_break.py <ciphertext-file>

The ciphertext is read as text, lowercased, and stripped of non-letters.
Output:

    candidate key length(s) by index of coincidence
    candidate key(s) by chi-squared frequency match
    decrypted text under the best key

Only handles A-Z. Don't use this on binary or on languages with significantly
different letter frequencies.
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


def index_of_coincidence(text: str) -> float:
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def best_key_lengths(ct: str, max_len: int = 20) -> list[tuple[int, float]]:
    scored: list[tuple[int, float]] = []
    for L in range(1, max_len + 1):
        cols = ["".join(ct[i::L]) for i in range(L)]
        avg_ic = sum(index_of_coincidence(c) for c in cols) / L
        scored.append((L, avg_ic))
    # Sort by closeness to English IC (~0.066).
    scored.sort(key=lambda x: abs(x[1] - 0.066))
    return scored


def best_shift(column: str) -> int:
    best, best_score = 0, float("inf")
    for shift in range(26):
        decoded = "".join(chr((ord(ch) - ord("a") - shift) % 26 + ord("a")) for ch in column)
        counts = Counter(decoded)
        n = len(decoded)
        chi = 0.0
        for letter, expected_pct in ENGLISH_FREQ.items():
            expected = expected_pct / 100 * n
            observed = counts.get(letter, 0)
            if expected > 0:
                chi += (observed - expected) ** 2 / expected
        if chi < best_score:
            best_score, best = chi, shift
    return best


def break_with_length(ct: str, L: int) -> tuple[str, str]:
    cols = ["".join(ct[i::L]) for i in range(L)]
    shifts = [best_shift(c) for c in cols]
    key = "".join(chr(s + ord("a")) for s in shifts)
    pt = []
    for i, ch in enumerate(ct):
        s = shifts[i % L]
        pt.append(chr((ord(ch) - ord("a") - s) % 26 + ord("a")))
    return key, "".join(pt)


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("Usage: python vigenere_break.py <ciphertext-file>")
    raw = open(sys.argv[1]).read().lower()
    ct = "".join(c for c in raw if c.isalpha())
    print("--- key length candidates (best IC first) ---")
    for L, ic in best_key_lengths(ct)[:5]:
        print(f"  L={L:2d}  IC={ic:.4f}")
    L = best_key_lengths(ct)[0][0]
    key, pt = break_with_length(ct, L)
    print(f"\n--- using L={L}, key={key!r} ---")
    print(pt[:500])


if __name__ == "__main__":
    main()
