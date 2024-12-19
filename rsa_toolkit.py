#!/usr/bin/env python3
"""rsa_toolkit.py — drop-in attacks against weak RSA setups.

Usage
-----
    python rsa_toolkit.py common-modulus -n N -e1 E1 -c1 C1 -e2 E2 -c2 C2
    python rsa_toolkit.py small-e -n N -e E -c C

``common-modulus`` recovers ``m`` when the same ``m`` is encrypted under the
same ``n`` with two coprime exponents.

``small-e`` takes the integer ``e``-th root of ``c`` directly. Only useful
when ``m**e < n`` (no padding, short message).

All numbers may be passed as decimal or as ``0x``-prefixed hex.
"""
from __future__ import annotations

import argparse
import sys


def parse_int(s: str) -> int:
    return int(s, 0)


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("not invertible")
    return x % m


def iroot(c: int, e: int) -> tuple[int, bool]:
    """Integer e-th root of c. Returns (root, exact)."""
    if c < 2:
        return c, True
    lo, hi = 1, 1 << ((c.bit_length() + e - 1) // e + 1)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** e < c:
            lo = mid + 1
        else:
            hi = mid
    return lo, lo ** e == c


def common_modulus(n: int, e1: int, c1: int, e2: int, c2: int) -> int:
    g, s, t = egcd(e1, e2)
    if g != 1:
        raise ValueError("e1, e2 must be coprime")
    if s < 0:
        c1 = modinv(c1, n)
        s = -s
    if t < 0:
        c2 = modinv(c2, n)
        t = -t
    return (pow(c1, s, n) * pow(c2, t, n)) % n


def small_e(n: int, e: int, c: int) -> int:
    root, exact = iroot(c, e)
    if not exact:
        # Try adding multiples of n in case m**e wrapped a few times.
        for k in range(1, 1 << 14):
            root, exact = iroot(c + k * n, e)
            if exact:
                return root
        raise ValueError("no exact root within search bound")
    return root


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    cm = sub.add_parser("common-modulus")
    cm.add_argument("-n", type=parse_int, required=True)
    cm.add_argument("-e1", type=parse_int, required=True)
    cm.add_argument("-c1", type=parse_int, required=True)
    cm.add_argument("-e2", type=parse_int, required=True)
    cm.add_argument("-c2", type=parse_int, required=True)

    se = sub.add_parser("small-e")
    se.add_argument("-n", type=parse_int, required=True)
    se.add_argument("-e", type=parse_int, required=True)
    se.add_argument("-c", type=parse_int, required=True)

    args = ap.parse_args()

    if args.cmd == "common-modulus":
        m = common_modulus(args.n, args.e1, args.c1, args.e2, args.c2)
    elif args.cmd == "small-e":
        m = small_e(args.n, args.e, args.c)
    else:
        sys.exit(2)

    print(f"m = {m}")
    try:
        print(f"bytes = {m.to_bytes((m.bit_length() + 7) // 8, 'big')!r}")
    except OverflowError:
        pass


if __name__ == "__main__":
    main()
