#!/usr/bin/env python3
"""rsa_toolkit.py — drop-in attacks against weak RSA setups.

Usage
-----
    python rsa_toolkit.py common-modulus -n N -e1 E1 -c1 C1 -e2 E2 -c2 C2
    python rsa_toolkit.py small-e -n N -e E -c C
    python rsa_toolkit.py wiener -n N -e E
    python rsa_toolkit.py hastad -e E -p N1 C1 -p N2 C2 -p N3 C3 [-p ...]

``common-modulus`` recovers ``m`` when the same ``m`` is encrypted under the
same ``n`` with two coprime exponents.

``small-e`` takes the integer ``e``-th root of ``c`` directly. Only useful
when ``m**e < n`` (no padding, short message).

``wiener`` recovers ``d`` (and the prime factorisation of ``n``) when ``d``
is small relative to ``n`` — specifically ``d < n**0.25 / 3`` or so. Useful
against challenges that pick a small ``d`` for "performance".

``hastad`` recovers ``m`` when the same ``m`` is encrypted under the same
small exponent ``e`` to ``e`` (or more) distinct coprime moduli. Requires
``m**e < prod(n_i)``.

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
    """Integer e-th root of c (floor). Returns (root, exact) where ``root``
    is the largest integer with ``root**e <= c`` and ``exact`` is True iff
    ``root**e == c``."""
    if c < 2:
        return c, True
    lo, hi = 1, 1 << ((c.bit_length() + e - 1) // e + 1)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** e <= c:
            lo = mid + 1
        else:
            hi = mid
    # After the loop, lo == hi is the smallest integer with lo**e > c.
    # The floor is therefore lo - 1.
    floor = lo - 1
    return floor, floor ** e == c


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


def continued_fraction(num: int, den: int) -> list[int]:
    out = []
    while den:
        q, r = divmod(num, den)
        out.append(q)
        num, den = den, r
    return out


def convergents(cf: list[int]) -> list[tuple[int, int]]:
    h0, h1 = 0, 1
    k0, k1 = 1, 0
    out: list[tuple[int, int]] = []
    for a in cf:
        h2 = a * h1 + h0
        k2 = a * k1 + k0
        out.append((h2, k2))
        h0, h1 = h1, h2
        k0, k1 = k1, k2
    return out


def wiener(n: int, e: int) -> int:
    """Return d when d is small enough for Wiener's attack to bite."""
    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        phi_candidate, rem = divmod(e * d - 1, k)
        if rem != 0:
            continue
        # phi = (p-1)(q-1) = n - p - q + 1 → p + q = n - phi + 1.
        s = n - phi_candidate + 1
        # Solve x^2 - s x + n = 0 for integer roots.
        disc = s * s - 4 * n
        if disc < 0:
            continue
        sq, exact = iroot(disc, 2)
        if not exact:
            continue
        if (s + sq) % 2 == 0:
            return d
    raise ValueError("Wiener's attack failed; d may be too large")


def hastad_broadcast(pairs: list[tuple[int, int]], e: int) -> int:
    """Håstad broadcast. ``pairs`` is ``[(n_i, c_i), ...]`` of the same ``m``
    encrypted under exponent ``e`` to distinct coprime moduli. Needs
    ``m**e < prod(n_i)`` for the integer root to be exact."""
    if len(pairs) < e:
        raise ValueError(f"Håstad requires at least e={e} pairs, got {len(pairs)}")
    N, C = pairs[0]
    for n_i, c_i in pairs[1:]:
        g, _, _ = egcd(N, n_i)
        if g != 1:
            raise ValueError("moduli must be pairwise coprime")
        # CRT step: find X such that X ≡ C (mod N) and X ≡ c_i (mod n_i).
        # X = C + N * ((c_i - C) * modinv(N, n_i) mod n_i)
        diff = (c_i - C) % n_i
        inv = modinv(N % n_i, n_i)
        X = C + N * ((diff * inv) % n_i)
        N = N * n_i
        C = X % N
    root, exact = iroot(C, e)
    if not exact:
        raise ValueError("Håstad failed: CRT-combined value is not a perfect e-th power")
    return root


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

    wn = sub.add_parser("wiener")
    wn.add_argument("-n", type=parse_int, required=True)
    wn.add_argument("-e", type=parse_int, required=True)

    hd = sub.add_parser("hastad")
    hd.add_argument("-e", type=parse_int, required=True)
    hd.add_argument("-p", "--pair", nargs=2, action="append", required=True,
                    metavar=("N", "C"), help="modulus + ciphertext pair (repeat for each)")

    args = ap.parse_args()

    if args.cmd == "common-modulus":
        m = common_modulus(args.n, args.e1, args.c1, args.e2, args.c2)
    elif args.cmd == "small-e":
        m = small_e(args.n, args.e, args.c)
    elif args.cmd == "wiener":
        d = wiener(args.n, args.e)
        print(f"d = {d}")
        return
    elif args.cmd == "hastad":
        pairs = [(parse_int(n), parse_int(c)) for n, c in args.pair]
        m = hastad_broadcast(pairs, args.e)
    else:
        sys.exit(2)

    print(f"m = {m}")
    try:
        print(f"bytes = {m.to_bytes((m.bit_length() + 7) // 8, 'big')!r}")
    except OverflowError:
        pass


if __name__ == "__main__":
    main()
