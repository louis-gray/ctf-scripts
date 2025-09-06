#!/usr/bin/env python3
"""pcap_usb_mass_storage.py — reassemble files transferred over USB
Mass-Storage from a pcap capture.

Usage
-----
    python pcap_usb_mass_storage.py <capture.pcap> <out.bin>

The script walks USB Bulk-Only Transport (BOT) traffic and concatenates the
DATA-IN payloads from successful READ(10) commands, in CBW-tag order. The
result is the raw block stream the host received — typically a disk image
or a flat file blob you can carve with ``foremost`` / ``binwalk``.

Caveats:

* Only handles USB MSC BOT (the dominant variant). Doesn't touch UAS.
* Doesn't sort by LBA; it relies on the host having issued reads in
  sensible order. For most CTF captures that's true.
* If multiple devices are plugged in, you'll need to pre-filter the pcap
  with ``tshark -Y 'usb.device_address==X'``.
"""
from __future__ import annotations

import struct
import sys

from scapy.all import rdpcap

CBW_SIGNATURE = 0x43425355  # "USBC", little-endian on the wire


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit("Usage: python pcap_usb_mass_storage.py <capture.pcap> <out.bin>")
    src, dst = sys.argv[1], sys.argv[2]
    blob = bytearray()
    pending: dict[int, int] = {}  # CBW tag -> remaining transfer length

    for pkt in rdpcap(src):
        data = bytes(pkt.original)
        # Look for a CBW header anywhere in the payload.
        sig_off = data.find(b"USBC")
        if sig_off >= 0 and len(data) >= sig_off + 31:
            cbw = data[sig_off:sig_off + 31]
            tag = struct.unpack("<I", cbw[4:8])[0]
            xfer_len = struct.unpack("<I", cbw[8:12])[0]
            opcode = cbw[15]
            if opcode == 0x28:  # READ(10)
                pending[tag] = xfer_len
            continue

        # Otherwise treat the trailing bulk payload as data-in for the
        # most recent pending tag if the size matches.
        if not pending:
            continue
        # Heuristic: take the last `chunk` bytes that match a multiple of 512.
        for size in (8192, 4096, 2048, 1024, 512):
            if len(data) >= size and (len(data) - size) < 64:
                blob += data[-size:]
                # Decrement the oldest pending tag.
                tag = next(iter(pending))
                pending[tag] -= size
                if pending[tag] <= 0:
                    pending.pop(tag)
                break

    with open(dst, "wb") as f:
        f.write(blob)
    print(f"wrote {len(blob)} bytes to {dst}")


if __name__ == "__main__":
    main()
