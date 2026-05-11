#!/usr/bin/env python3
"""hash_identify.py — fingerprint a hash by length and charset, return likely
algorithms with their john ``--format`` and hashcat ``-m`` mode IDs.

Usage
-----
    python hash_identify.py <hash>
    python hash_identify.py -                 # read hash from stdin

The same length can match multiple algorithms (e.g. 32 hex → MD5, NTLM, LM).
All candidates are returned; pick by context.
"""
from __future__ import annotations

import re
import sys


# (name, pattern, john_mode, hashcat_mode, notes)
RULES: list[tuple[str, str, str, int, str]] = [
    ("MD5",         r"^[a-fA-F0-9]{32}$",                          "raw-md5",        0,     ""),
    ("NTLM",        r"^[a-fA-F0-9]{32}$",                          "nt",             1000,  "Windows password hash"),
    ("LM",          r"^[a-fA-F0-9]{32}$",                          "lm",             3000,  "legacy Windows, max 14 chars"),
    ("MD4",         r"^[a-fA-F0-9]{32}$",                          "raw-md4",        900,   ""),
    ("SHA-1",       r"^[a-fA-F0-9]{40}$",                          "raw-sha1",       100,   ""),
    ("MySQL5",      r"^\*[a-fA-F0-9]{40}$",                        "mysql-sha1",     300,   "leading '*'"),
    ("RIPEMD-160",  r"^[a-fA-F0-9]{40}$",                          "ripemd-160",     6000,  ""),
    ("SHA-224",     r"^[a-fA-F0-9]{56}$",                          "raw-sha224",     1300,  ""),
    ("SHA-256",     r"^[a-fA-F0-9]{64}$",                          "raw-sha256",     1400,  ""),
    ("SHA3-256",    r"^[a-fA-F0-9]{64}$",                          "raw-sha3-256",   17400, ""),
    ("Keccak-256",  r"^[a-fA-F0-9]{64}$",                          "raw-keccak-256", 17800, ""),
    ("SHA-384",     r"^[a-fA-F0-9]{96}$",                          "raw-sha384",     10800, ""),
    ("SHA-512",     r"^[a-fA-F0-9]{128}$",                         "raw-sha512",     1700,  ""),
    ("Whirlpool",   r"^[a-fA-F0-9]{128}$",                         "whirlpool",      6100,  ""),
    ("SHA3-512",    r"^[a-fA-F0-9]{128}$",                         "raw-sha3-512",   17600, ""),
    ("bcrypt",      r"^\$2[abxy]\$\d+\$[./A-Za-z0-9]{53}$",        "bcrypt",         3200,  ""),
    ("PHPass",      r"^\$[PH]\$[./A-Za-z0-9]{31}$",                "phpass",         400,   "WordPress, phpBB3"),
    ("md5crypt",    r"^\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$","md5crypt",      500,   ""),
    ("sha256crypt", r"^\$5\$[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{43}$","sha256crypt",  7400,  ""),
    ("sha512crypt", r"^\$6\$[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{86}$","sha512crypt",  1800,  ""),
    ("Argon2",      r"^\$argon2(id|i|d)\$",                        "argon2",         34000, "prefix match only"),
    ("MD5(Unix)",   r"^\$apr1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$","md5crypt",   1600,  "Apache MD5"),
]


def identify(h: str) -> list[dict]:
    """Return candidate algorithms for ``h``. Empty list if no match."""
    h = h.strip()
    if not h:
        return []
    charset = "hex" if re.fullmatch(r"[a-fA-F0-9]+", h) else "mixed"
    out: list[dict] = []
    for name, pattern, john, hashcat, notes in RULES:
        if re.fullmatch(pattern, h):
            out.append({
                "name": name,
                "length": len(h),
                "charset": charset,
                "john_mode": john,
                "hashcat_mode": hashcat,
                "notes": notes,
            })
    return out


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("Usage: python hash_identify.py <hash-or-->")
    if sys.argv[1] == "-":
        h = sys.stdin.read().strip()
    else:
        h = sys.argv[1]
    candidates = identify(h)
    if not candidates:
        print(f"No match for hash of length {len(h)}.")
        return
    print(f"--- {len(candidates)} candidate(s) for length-{len(h)} hash ---")
    for c in candidates:
        notes = f"  ({c['notes']})" if c["notes"] else ""
        print(f"  {c['name']:14s}  john --format={c['john_mode']:16s}  hashcat -m {c['hashcat_mode']:<6d}{notes}")


if __name__ == "__main__":
    main()
