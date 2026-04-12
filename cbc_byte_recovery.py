#!/usr/bin/env python3
"""cbc_byte_recovery.py — recover an unknown secret one byte at a time
against a CBC encryption oracle that lets you submit attacker-chosen
plaintext and observe the ciphertext.

When does this apply?
---------------------
The server holds a secret ``S`` and an AES-CBC key. On each request:

* The attacker sends a plaintext ``P``.
* The server returns ``ENC(P || S)`` under CBC, with each connection's IV
  set to the previous response's last ciphertext block.

That last property — the chained IV — means we can craft a probe whose
first block aligns to ``S[0]``, then brute-force ``S[0]`` by checking
which value produces the same ciphertext block as the corresponding
target block in a separate "alignment" request.

Usage
-----
Adapt the ``Oracle`` class below to your challenge's wire protocol, then
call ``recover()``. The script in its bundled form expects a length-prefixed
binary protocol over a TCP socket; rewrite ``query()`` for HTTP, JSON, etc.

Charset (``CHARSET``) is the alphabet the secret might use. Smaller charset
= faster recovery. Default covers space + uppercase letters which suits
most "challenge key" style secrets.
"""
from __future__ import annotations

import socket
import struct
from typing import Iterable

CHARSET: bytes = b" ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{}_"
BLOCK = 16


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class Oracle:
    """Reference TCP implementation. Override ``query`` for other protocols."""

    def __init__(self, host: str, port: int):
        self.s = socket.create_connection((host, port), timeout=10)
        self.iv = self._recv(BLOCK)

    def _recv(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.s.recv(n - len(buf))
            if not chunk:
                raise EOFError
            buf += chunk
        return buf

    def query(self, plaintext: bytes) -> tuple[bytes, bytes]:
        """Submit ``plaintext`` and return ``(iv_used, ciphertext)``."""
        self.s.sendall(struct.pack("<I", len(plaintext)) + plaintext)
        length = struct.unpack("<I", self._recv(4))[0]
        ct = self._recv(length)
        prev_iv = self.iv
        self.iv = ct[-BLOCK:]
        return prev_iv, ct


def recover(host: str, port: int, charset: Iterable[int] = CHARSET, max_len: int = 64) -> bytes:
    """Recover the secret one byte at a time."""
    sess = Oracle(host, port)
    secret = b""
    while len(secret) < max_len:
        k = len(secret)
        # Pad so that the next byte of the secret falls at the end of a block.
        pad_len = (BLOCK - 1 - k) % BLOCK
        block_index = (pad_len + k) // BLOCK

        # First request gives us the target ciphertext block we need to match.
        try:
            iv_a, ct_a = sess.query(b"A" * pad_len)
        except EOFError:
            sess = Oracle(host, port)
            continue
        target_block = ct_a[block_index * BLOCK:(block_index + 1) * BLOCK]
        target_iv = iv_a if block_index == 0 else ct_a[(block_index - 1) * BLOCK:block_index * BLOCK]

        full_known = b"A" * pad_len + secret
        prefix15 = full_known[block_index * BLOCK:block_index * BLOCK + (BLOCK - 1)]

        found = None
        for guess in charset:
            probe_iv = sess.iv
            block = bytes(prefix15) + bytes([guess])
            probe = xor(xor(block, target_iv), probe_iv)
            try:
                _, ct = sess.query(probe)
            except EOFError:
                sess = Oracle(host, port)
                break
            if ct[:BLOCK] == target_block:
                found = bytes([guess])
                break

        if found is None:
            print(f"[!] no match at byte {k}; stopping")
            break
        secret += found
        print(f"[+] {k:2d} = {found!r}  -> {secret!r}")

    sess.s.close()
    return secret


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        sys.exit("Usage: python cbc_byte_recovery.py <host> <port>")
    print(recover(sys.argv[1], int(sys.argv[2])))
