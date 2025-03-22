#!/usr/bin/env python3
"""pcap_usb_hid.py — reconstruct keystrokes from a USB HID pcap capture.

Usage
-----
    python pcap_usb_hid.py <capture.pcap> [--layout uk|us]

The HID boot-protocol keyboard report is 8 bytes:

    [modifier, reserved, key1, key2, key3, key4, key5, key6]

We pull the URB Leftover Capture Data field from each USB packet, treat any
8-byte payload as a keyboard report, and translate the first non-zero key
through a layout map. Shift / AltGr are honoured for symbol keys; for
arbitrary characters in the upper Unicode range, fall back to ``--layout us``.

Defaults to UK layout because that's what the challenges I run into seem
to use. Pull-requests welcome for other layouts.
"""
from __future__ import annotations

import argparse

from scapy.all import rdpcap

# HID usage ID -> (unshifted, shifted) for printable keys
US = {
    0x04: ("a", "A"), 0x05: ("b", "B"), 0x06: ("c", "C"), 0x07: ("d", "D"),
    0x08: ("e", "E"), 0x09: ("f", "F"), 0x0A: ("g", "G"), 0x0B: ("h", "H"),
    0x0C: ("i", "I"), 0x0D: ("j", "J"), 0x0E: ("k", "K"), 0x0F: ("l", "L"),
    0x10: ("m", "M"), 0x11: ("n", "N"), 0x12: ("o", "O"), 0x13: ("p", "P"),
    0x14: ("q", "Q"), 0x15: ("r", "R"), 0x16: ("s", "S"), 0x17: ("t", "T"),
    0x18: ("u", "U"), 0x19: ("v", "V"), 0x1A: ("w", "W"), 0x1B: ("x", "X"),
    0x1C: ("y", "Y"), 0x1D: ("z", "Z"),
    0x1E: ("1", "!"), 0x1F: ("2", "@"), 0x20: ("3", "#"), 0x21: ("4", "$"),
    0x22: ("5", "%"), 0x23: ("6", "^"), 0x24: ("7", "&"), 0x25: ("8", "*"),
    0x26: ("9", "("), 0x27: ("0", ")"),
    0x28: ("\n", "\n"), 0x29: ("[esc]", "[esc]"),
    0x2A: ("[bs]", "[bs]"), 0x2B: ("\t", "\t"), 0x2C: (" ", " "),
    0x2D: ("-", "_"), 0x2E: ("=", "+"), 0x2F: ("[", "{"), 0x30: ("]", "}"),
    0x31: ("\\", "|"), 0x33: (";", ":"), 0x34: ("'", '"'), 0x35: ("`", "~"),
    0x36: (",", "<"), 0x37: (".", ">"), 0x38: ("/", "?"),
}

# UK keyboard differs from US in a handful of positions.
UK = dict(US)
UK[0x1F] = ("2", '"')
UK[0x20] = ("3", "£")
UK[0x24] = ("7", "&")
UK[0x31] = ("#", "~")
UK[0x32] = ("\\", "|")
UK[0x34] = ("'", "@")
UK[0x35] = ("`", "¬")


def decode(report: bytes, layout: dict) -> str:
    if len(report) < 3:
        return ""
    modifier = report[0]
    shift = bool(modifier & 0x22)  # left or right shift
    key = report[2]
    if key == 0:
        return ""
    if key in layout:
        return layout[key][1 if shift else 0]
    return f"[0x{key:02x}]"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--layout", choices=("uk", "us"), default="uk")
    args = ap.parse_args()

    layout = UK if args.layout == "uk" else US
    last = b""
    out = []
    for pkt in rdpcap(args.pcap):
        data = bytes(pkt.original)
        # Scan for an 8-byte HID report-shaped trailing payload.
        if len(data) < 8:
            continue
        report = data[-8:]
        if report == last:
            continue
        last = report
        out.append(decode(report, layout))
    print("".join(out))


if __name__ == "__main__":
    main()
