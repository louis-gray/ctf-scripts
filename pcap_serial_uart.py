#!/usr/bin/env python3
"""pcap_serial_uart.py — decode UART 8N1 frames from a logic-analyser-style
capture file.

Usage
-----
    python pcap_serial_uart.py <capture-file> [--samples-per-bit N] [--bit B]

`<capture-file>` is a flat byte stream of samples. Each sample byte encodes
the line state across one or more channels. By default we read bit 0 of
each sample as the UART line; use ``--bit`` to pick a different bit if
multiple lines are interleaved (e.g. RX and TX on bits 1 and 0).

``--samples-per-bit`` is the number of samples covering one UART bit.
Compute it as ``capture_rate / baud_rate`` (e.g. 6 MHz capture at 115200
baud → ~52 samples per bit).

Idle line is high (1). A frame is detected when the line drops (start bit),
followed by 8 data bits LSB-first, then a stop bit. Each decoded byte is
written to stdout as raw bytes.
"""
from __future__ import annotations

import argparse
import sys


def decode(stream: bytes, spb: int, bit: int) -> bytes:
    line = bytes((b >> bit) & 1 for b in stream)
    out = bytearray()
    i, n = 0, len(line)
    frame_len = 10 * spb  # start + 8 data + stop
    while i < n - frame_len:
        # Detect a falling edge marking the start bit.
        if line[i] == 0 and (i == 0 or line[i - 1] == 1):
            byte = 0
            for b in range(8):
                # Sample at the middle of each data bit.
                sample_at = i + int((b + 1.5) * spb)
                if line[sample_at]:
                    byte |= 1 << b
            out.append(byte)
            i += frame_len
        else:
            i += 1
    return bytes(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("capture")
    ap.add_argument("--samples-per-bit", type=int, default=52)
    ap.add_argument("--bit", type=int, default=0)
    args = ap.parse_args()
    data = open(args.capture, "rb").read()
    sys.stdout.buffer.write(decode(data, args.samples_per_bit, args.bit))


if __name__ == "__main__":
    main()
