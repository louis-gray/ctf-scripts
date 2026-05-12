#!/usr/bin/env python3
"""ecb_toolkit.py — ECB detection by block repetition, and byte-at-a-time
chosen-plaintext recovery against an ECB oracle.

Usage
-----
    python ecb_toolkit.py detect <hex-ciphertext>
    python ecb_toolkit.py byte-at-a-time --cmd '<oracle-binary>' [--block-size 16] [--max-len 256]

The ``--cmd`` oracle reads a prefix on stdin and writes the ECB ciphertext
of ``prefix || secret`` on stdout. For network oracles, import
``byte_at_a_time`` and pass a Python callable.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from typing import Callable


def detect_ecb(ct: bytes, block_size: int = 16) -> int:
    """Number of duplicate blocks (sum of ``count - 1`` over each block).
    Non-zero means at least one block appears more than once."""
    if len(ct) % block_size != 0:
        ct = ct[: len(ct) // block_size * block_size]
    blocks = [ct[i : i + block_size] for i in range(0, len(ct), block_size)]
    extras = 0
    seen: dict[bytes, int] = {}
    for b in blocks:
        seen[b] = seen.get(b, 0) + 1
    for count in seen.values():
        if count > 1:
            extras += count - 1
    return extras


def byte_at_a_time(
    oracle: Callable[[bytes], bytes],
    block_size: int = 16,
    max_len: int = 256,
) -> bytes:
    """Classic byte-at-a-time secret recovery against an ECB oracle of the
    form ``E(prefix || secret)`` with a fixed key. Stops at ``max_len`` or
    when a byte can't be recovered."""
    recovered = b""
    for i in range(max_len):
        block_idx = i // block_size
        pad_len = block_size - 1 - (i % block_size)
        prefix = b"A" * pad_len
        target_ct = oracle(prefix)
        target_block = target_ct[block_idx * block_size : (block_idx + 1) * block_size]
        if len(target_block) < block_size:
            break
        found = False
        for b in range(256):
            probe = prefix + recovered + bytes([b])
            probe_ct = oracle(probe)
            probe_block = probe_ct[block_idx * block_size : (block_idx + 1) * block_size]
            if probe_block == target_block:
                recovered += bytes([b])
                found = True
                break
        if not found:
            break
    return recovered


def _cli_byte_at_a_time(cmd: str, block_size: int, max_len: int) -> bytes:
    def oracle(prefix: bytes) -> bytes:
        result = subprocess.run(
            cmd, shell=True, input=prefix, capture_output=True, check=False
        )
        return result.stdout
    return byte_at_a_time(oracle, block_size=block_size, max_len=max_len)


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("detect")
    d.add_argument("hex", help="hex-encoded ciphertext")
    d.add_argument("--block-size", type=int, default=16)

    b = sub.add_parser("byte-at-a-time")
    b.add_argument("--cmd", required=True, help="shell command for the oracle")
    b.add_argument("--block-size", type=int, default=16)
    b.add_argument("--max-len", type=int, default=256)

    args = ap.parse_args()

    if args.cmd == "detect":
        ct = bytes.fromhex(args.hex)
        extras = detect_ecb(ct, args.block_size)
        n_blocks = len(ct) // args.block_size
        print(f"blocks: {n_blocks}, extra-repeated: {extras}")
        if extras > 0:
            print("ECB detected (at least one block appears more than once)")
        else:
            print("no repeated blocks (not necessarily ECB-clean)")
    elif args.cmd == "byte-at-a-time":
        recovered = _cli_byte_at_a_time(args.cmd, args.block_size, args.max_len)
        sys.stdout.buffer.write(recovered + b"\n")


if __name__ == "__main__":
    main()
