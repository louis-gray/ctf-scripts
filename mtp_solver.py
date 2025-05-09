#!/usr/bin/env python3
"""mtp_solver.py — recover plaintext from a many-time-pad (a.k.a. several
ciphertexts XORed against the same one-time-pad).

Usage
-----
    python mtp_solver.py <messages-file> [--target N]

`<messages-file>` is one ciphertext per line, hex-encoded. Optional ``label: hex``
prefix is tolerated (the prefix before ``: `` is ignored).

By default the last message in the file is treated as the target; pass
``--target N`` to pick a different (zero-indexed) message.

Cribs are short plaintexts you suspect appear at the start of one or more of
the *other* messages. Edit the ``CRIBS`` list below to reflect the challenge.

Each crib XORed against its message yields a fragment of the shared key, which
in turn decrypts the corresponding bytes of every other message. The target is
printed at the end with `?` filling positions where no key byte is known yet.
"""
from __future__ import annotations

import argparse


# Suspected plaintext fragments keyed by start offset. Most cribs sit at 0
# (assumption: messages start with English text), but mid-message cribs
# such as "the " or " and " are very useful once the early bytes are pinned.
CRIBS: dict[int, list[bytes]] = {
    0: [
        b"the ",
        b"The ",
        b"And ",
    ],
}


def parse(path: str) -> list[bytes]:
    msgs: list[bytes] = []
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        if ": " in line:
            line = line.split(": ", 1)[1]
        msgs.append(bytes.fromhex(line))
    return msgs


def derive_key(msgs: list[bytes], cribs: dict[int, list[bytes]]) -> list[int | None]:
    maxlen = max(len(m) for m in msgs)
    key: list[int | None] = [None] * maxlen
    for offset, fragments in cribs.items():
        for crib in fragments:
            for m in msgs:
                if len(m) < offset + len(crib):
                    continue
                for j, c in enumerate(crib):
                    kb = m[offset + j] ^ c
                    if key[offset + j] is None:
                        key[offset + j] = kb
    return key


def decrypt(msg: bytes, key: list[int | None]) -> str:
    out = bytearray(len(msg))
    for j in range(len(msg)):
        out[j] = (msg[j] ^ key[j]) if key[j] is not None else ord("?")
    return out.decode("latin1")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("messages")
    ap.add_argument("--target", type=int, default=-1)
    args = ap.parse_args()

    msgs = parse(args.messages)
    target = msgs[args.target]
    key = derive_key(msgs, CRIBS)
    known = sum(1 for k in key if k is not None)
    print(f"key bytes recovered: {known}/{len(target)}")
    print(decrypt(target, key))


if __name__ == "__main__":
    main()
