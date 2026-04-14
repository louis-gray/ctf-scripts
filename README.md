# ctf-scripts

A grab-bag of self-contained scripts I've written to handle recurring problems
in CTFs. Each script tries to do one thing, document its inputs at the top,
and stay readable enough to fork into a one-off solver when a challenge
needs something close-but-not-quite.

## Scripts

- `xor_known_plaintext.py` — slide a known plaintext fragment across an XOR
  ciphertext to recover the key and rank candidate plaintexts by printability.
- `mtp_solver.py` — recover plaintext from a many-time-pad given a few
  candidate cribs. Edit the `CRIBS` list to taste.
- `lsb_image_extract.py` — pull bytes out of the least-significant bits of
  an image's RGBA channels.
- `rsa_toolkit.py` — common-modulus and small-`e` cube-root attacks against
  weak RSA setups.
- `cbc_padding_oracle.py` — generic PKCS#7 padding-oracle attack. Pass an
  oracle callable, get the plaintext.
- `cbc_bitflip.py` — three-line bit-flip primitive for CBC malleability
  attacks, packaged as an importable function.
- `vigenere_break.py` — index-of-coincidence key-length detection plus
  chi-squared key recovery.
- `gif_frame_diff.py` — split a GIF into per-frame PNGs and report the
  bounding box of pixels that changed. Handy for steg.
- `pcap_usb_hid.py` — reconstruct keystrokes from a USB HID capture, with
  UK and US layout maps.
- `pcap_usb_mass_storage.py` — reassemble files from USB BOT pcap captures.
- `pcap_serial_uart.py` — decode UART 8N1 frames out of a logic-analyser
  capture file given the samples-per-bit ratio.
- `cbc_byte_recovery.py` — chosen-IV byte-at-a-time secret recovery against
  CBC encryption oracles that chain IV from the previous response.

## Setup

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```
