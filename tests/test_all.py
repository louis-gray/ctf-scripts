"""Verification tests for every importable function in the toolbox.

Strategy: known-answer testing. Encrypt / encode something with a known key
or layout, run the recovery script, assert it returned the secret.
"""
from __future__ import annotations

import io
import os
import socket
import struct
import subprocess
import sys
import threading
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
PYTHON = sys.executable


# ----------------------------------------------------------------------------
# xor_known_plaintext
# ----------------------------------------------------------------------------

def test_xor_known_plaintext_recovers_key():
    """Crib length is a multiple of the key length — the standard case the
    script can solve. With a crib shorter than the period or out of phase,
    the recovered "key fragment" wouldn't tile back to the real key."""
    from xor_known_plaintext import recover

    key = b"KEY"  # period 3
    pt = (
        b"hello world this is a long english sentence that should score "
        b"well on printable-ascii heuristics here yes indeed it does."
    )
    ct = bytes(p ^ key[i % len(key)] for i, p in enumerate(pt))
    # The recovery rotates and tiles the recovered fragment as if its length
    # were the period, so the crib length must be a multiple of the real key
    # period for the rotated fragment to equal the true key.
    crib = b"is a long en"  # length 12 = 4 * 3
    expected_offset = pt.index(crib)
    assert len(crib) % len(key) == 0
    results = recover(ct, crib, top=5)
    assert any(off == expected_offset for off, _, _ in results)
    # And one of the top candidates' plaintexts should equal the original
    assert any(rpt == pt for _, _, rpt in results)


# ----------------------------------------------------------------------------
# mtp_solver
# ----------------------------------------------------------------------------

def test_mtp_solver_recovers_partial_key():
    from mtp_solver import derive_key, decrypt

    key = bytes(range(40))
    plaintexts = [
        b"the quick brown fox jumps over the lazy",
        b"The morning is bright and full of energy",
        b"And then the cat jumped off the counter",
        b"the answer is hidden in plain sight here",
    ]
    msgs = [bytes(p ^ key[i] for i, p in enumerate(pt)) for pt in plaintexts]
    cribs = {0: [b"the ", b"The ", b"And "]}
    derived = derive_key(msgs, cribs)
    # The first 4 key bytes should have been recovered
    for i in range(4):
        assert derived[i] == key[i], f"key byte {i} wrong: {derived[i]!r} vs {key[i]!r}"
    # And decrypt should produce a string starting with "the " (or similar) for msg 0
    out = decrypt(msgs[0], derived)
    assert out.startswith("the ")


# ----------------------------------------------------------------------------
# lsb_image_extract
# ----------------------------------------------------------------------------

def test_lsb_extract_round_trip(tmp_path):
    from PIL import Image
    from lsb_image_extract import extract, visualise_planes

    payload = b"hide me in pixels!!!"
    bits_needed = len(payload) * 8
    # 3 channels * 1 bit per pixel; need at least bits_needed pixels
    n_pixels = bits_needed + 16  # some slack
    img = Image.new("RGB", (n_pixels, 1))
    pixels = img.load()
    bit_iter = iter("".join(f"{b:08b}" for b in payload))
    for x in range(n_pixels):
        r = g = b = 128  # arbitrary base
        try:
            r = (r & 0xFE) | int(next(bit_iter))
            g = (g & 0xFE) | int(next(bit_iter))
            b = (b & 0xFE) | int(next(bit_iter))
        except StopIteration:
            pass
        pixels[x, 0] = (r, g, b)
    img_path = tmp_path / "lsb.png"
    img.save(img_path)
    out = extract(str(img_path), bits=1, channels="rgb")
    assert out.startswith(payload), f"got {out[:32]!r}"

    # planes mode: just check 8 planes are written
    planes_dir = tmp_path / "planes"
    visualise_planes(str(img_path), str(planes_dir))
    for i in range(8):
        assert (planes_dir / f"plane_{i}.png").exists()


# ----------------------------------------------------------------------------
# rsa_toolkit
# ----------------------------------------------------------------------------

def _toy_primes():
    """Two genuine primes (Crypto.Util.number-generated, hard-coded for
    determinism). p, q both 64-bit, so n is ~128-bit — large enough that
    small messages don't wrap, small enough that tests run instantly."""
    p = 0xDB6F3DB5AF99D4A5
    q = 0xFDDD8280E711E589
    from Crypto.Util.number import isPrime
    assert isPrime(p) and isPrime(q)
    return p, q


def test_rsa_iroot_exact():
    from rsa_toolkit import iroot
    assert iroot(27, 3) == (3, True)
    # 28 is not a perfect cube; floor(28**(1/3)) = 3.
    assert iroot(28, 3) == (3, False)
    assert iroot(1024, 10) == (2, True)
    # Larger exact case
    assert iroot(2 ** 100, 10) == (2 ** 10, True)


def test_rsa_small_e():
    from rsa_toolkit import small_e
    p, q = _toy_primes()
    n = p * q
    e = 3
    m = 0x1234
    c = pow(m, e, n)  # m**3 < n so wraps not needed
    assert small_e(n, e, c) == m


def test_rsa_common_modulus():
    from rsa_toolkit import common_modulus
    p, q = _toy_primes()
    n = p * q
    m = 0xDEADBEEFCAFEBABE
    # gcd(m, n) must be 1 (real RSA) or the algorithm can't invert ciphertexts
    from math import gcd
    assert gcd(m, n) == 1
    e1, e2 = 3, 5
    c1 = pow(m, e1, n)
    c2 = pow(m, e2, n)
    assert common_modulus(n, e1, c1, e2, c2) == m


def test_rsa_wiener():
    from rsa_toolkit import wiener
    p, q = _toy_primes()
    n = p * q
    phi = (p - 1) * (q - 1)
    # n ~128 bits, n^0.25 ~ 32 bits, so d ~30 bits is safely Wiener-able.
    d = 0x1A2B3C4D
    from math import gcd
    while gcd(d, phi) != 1:
        d += 2

    def egcd(a, b):
        if b == 0:
            return a, 1, 0
        g, x, y = egcd(b, a % b)
        return g, y, x - (a // b) * y

    _, x, _ = egcd(d, phi)
    e = x % phi
    recovered = wiener(n, e)
    assert recovered == d


# ----------------------------------------------------------------------------
# cbc_padding_oracle
# ----------------------------------------------------------------------------

def test_cbc_padding_oracle_attack():
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from cbc_padding_oracle import attack

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
    # recovered is padded plaintext; strip pkcs7
    assert unpad(recovered, 16) == msg


def test_cbc_padding_oracle_attack_threaded():
    """Same attack but with workers > 1 to exercise the threaded path."""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from cbc_padding_oracle import attack

    key = os.urandom(16)
    iv = os.urandom(16)
    msg = b"workers gonna work"
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg, 16))

    def oracle(blob: bytes) -> bool:
        try:
            unpad(AES.new(key, AES.MODE_CBC, blob[:16]).decrypt(blob[16:]), 16)
            return True
        except ValueError:
            return False

    recovered = attack(oracle, iv + ct, 16, workers=8)
    assert unpad(recovered, 16) == msg


# ----------------------------------------------------------------------------
# cbc_bitflip
# ----------------------------------------------------------------------------

def test_cbc_bitflip_changes_target_block():
    from Crypto.Cipher import AES
    from cbc_bitflip import flip

    key = os.urandom(16)
    iv = os.urandom(16)
    pt = b"role=user;admin=0" + b"\x00" * (32 - 17)  # 32 bytes, 2 blocks
    pt = pt[:32]
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pt)
    # Want to flip block 1's plaintext from b"min=0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    # but easier: make a simple two-block known plaintext.
    pt = b"AAAAAAAAAAAAAAAA" + b"role=user;admin"  # block 0 + block 1 (15 bytes)
    pt = pt + b"\x00"  # pad to 32
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pt)
    known_pt_block1 = pt[16:32]
    desired_pt_block1 = b"role=user;admin\x01"
    new_block0 = flip(ct[:16], known_pt_block1, desired_pt_block1)
    new_ct = new_block0 + ct[16:]
    decrypted = AES.new(key, AES.MODE_CBC, iv).decrypt(new_ct)
    assert decrypted[16:32] == desired_pt_block1


# ----------------------------------------------------------------------------
# vigenere_break
# ----------------------------------------------------------------------------

# Long-ish English plaintext (Lorem-ish from real public-domain text)
ENGLISH_TEXT = (
    "it was the best of times it was the worst of times it was the age of "
    "wisdom it was the age of foolishness it was the epoch of belief it was "
    "the epoch of incredulity it was the season of light it was the season "
    "of darkness it was the spring of hope it was the winter of despair we "
    "had everything before us we had nothing before us we were all going "
    "direct to heaven we were all going direct the other way in short the "
    "period was so far like the present period that some of its noisiest "
    "authorities insisted on its being received for good or for evil in the "
    "superlative degree of comparison only there were a king with a large "
    "jaw and a queen with a plain face on the throne of england there were "
    "a king with a large jaw and a queen with a fair face on the throne of "
    "france in both countries it was clearer than crystal to the lords of "
    "the state preserves of loaves and fishes that things in general were "
    "settled for ever"
)


def _vig_encrypt(pt: str, key: str) -> str:
    out = []
    for i, ch in enumerate(pt):
        s = ord(key[i % len(key)]) - ord("a")
        out.append(chr((ord(ch) - ord("a") + s) % 26 + ord("a")))
    return "".join(out)


def test_vigenere_break_recovers_key():
    from vigenere_break import best_key_lengths, break_with_length

    key = "lemon"
    pt_letters = "".join(c for c in ENGLISH_TEXT.lower() if c.isalpha())
    ct = _vig_encrypt(pt_letters, key)
    candidates = best_key_lengths(ct, max_len=12)
    top_lengths = [L for L, _ in candidates[:3]]
    # Either L=5 directly, or a multiple. Most realistic: top-3 includes 5.
    assert 5 in top_lengths, f"expected 5 in top key lengths, got {top_lengths}"
    rkey, rpt = break_with_length(ct, 5)
    assert rkey == key
    assert rpt == pt_letters


# ----------------------------------------------------------------------------
# gif_frame_diff
# ----------------------------------------------------------------------------

def test_gif_diff_bbox_and_montage(tmp_path):
    from PIL import Image
    from gif_frame_diff import diff_bbox, montage

    a = Image.new("RGB", (32, 32), (0, 0, 0))
    b = Image.new("RGB", (32, 32), (0, 0, 0))
    # Paint a 4x4 white square in b at (10, 12)
    for x in range(10, 14):
        for y in range(12, 16):
            b.putpixel((x, y), (255, 255, 255))
    bbox = diff_bbox(a, b)
    assert bbox == (10, 12, 14, 16)

    crops = [b.crop(bbox), b.crop(bbox)]
    m = montage(crops, cols=2)
    assert m.width == 8 and m.height == 4


# ----------------------------------------------------------------------------
# pcap_usb_hid
# ----------------------------------------------------------------------------

def test_usb_hid_decode_hello():
    from pcap_usb_hid import decode, US

    # HID usage IDs for h, e, l, l, o
    reports = [
        bytes([0, 0, 0x0B, 0, 0, 0, 0, 0]),  # h
        bytes([0, 0, 0x08, 0, 0, 0, 0, 0]),  # e
        bytes([0, 0, 0x0F, 0, 0, 0, 0, 0]),  # l
        bytes([0, 0, 0x0F, 0, 0, 0, 0, 0]),  # l (dup, but decode itself doesn't dedup)
        bytes([0, 0, 0x12, 0, 0, 0, 0, 0]),  # o
    ]
    out = "".join(decode(r, US) for r in reports)
    assert out == "hello"


def test_usb_hid_decode_shifted():
    from pcap_usb_hid import decode, US

    # shift+a = A
    r = bytes([0x02, 0, 0x04, 0, 0, 0, 0, 0])  # left-shift modifier
    assert decode(r, US) == "A"


def test_usb_hid_pcap_end_to_end(tmp_path):
    """Build a pcap of HID reports, run the script, check the output."""
    from scapy.all import Ether, Raw, wrpcap

    reports = [
        bytes([0, 0, 0x0B, 0, 0, 0, 0, 0]),  # h
        bytes([0, 0, 0x00, 0, 0, 0, 0, 0]),  # release
        bytes([0, 0, 0x08, 0, 0, 0, 0, 0]),  # e
        bytes([0, 0, 0x00, 0, 0, 0, 0, 0]),
        bytes([0, 0, 0x0F, 0, 0, 0, 0, 0]),  # l
        bytes([0, 0, 0x00, 0, 0, 0, 0, 0]),
        bytes([0, 0, 0x0F, 0, 0, 0, 0, 0]),  # l (second)
        bytes([0, 0, 0x00, 0, 0, 0, 0, 0]),
        bytes([0, 0, 0x12, 0, 0, 0, 0, 0]),  # o
    ]
    pkts = [Ether() / Raw(load=r) for r in reports]
    pcap_path = tmp_path / "hid.pcap"
    wrpcap(str(pcap_path), pkts)
    result = subprocess.run(
        [PYTHON, str(REPO / "pcap_usb_hid.py"), str(pcap_path), "--layout", "us"],
        capture_output=True, text=True, cwd=str(REPO),
    )
    assert result.returncode == 0, result.stderr
    assert "hello" in result.stdout


# ----------------------------------------------------------------------------
# pcap_usb_mass_storage  (script-only — invoke as subprocess)
# ----------------------------------------------------------------------------

def test_pcap_usb_mass_storage_reassembles(tmp_path):
    from scapy.all import Ether, wrpcap, Raw

    # Build a synthetic CBW + 512-byte data-in.
    payload = b"PAYLOAD!" * 64  # 512 bytes
    # CBW: signature(4) + tag(4) + xfer_len(4) + flags(1) + lun(1) + cb_len(1) + CB(16)
    cbw = b"USBC" + struct.pack("<I", 0xDEADBEEF) + struct.pack("<I", 512) + b"\x80\x00\x10"
    cbw += b"\x28" + b"\x00" * 15  # opcode 0x28 = READ(10)
    assert len(cbw) == 31

    # Wrap as fake "ethernet" packets — the script just calls bytes(pkt.original)
    # and looks for the "USBC" magic, so any framing works.
    pkt_cbw = Ether() / Raw(load=cbw)
    pkt_data = Ether() / Raw(load=payload)
    pcap_path = tmp_path / "msc.pcap"
    wrpcap(str(pcap_path), [pkt_cbw, pkt_data])

    out_path = tmp_path / "out.bin"
    result = subprocess.run(
        [PYTHON, str(REPO / "pcap_usb_mass_storage.py"), str(pcap_path), str(out_path)],
        capture_output=True, text=True, cwd=str(REPO),
    )
    assert result.returncode == 0, result.stderr
    blob = out_path.read_bytes()
    assert blob.endswith(payload), f"got {len(blob)} bytes, last 32: {blob[-32:]!r}"


# ----------------------------------------------------------------------------
# pcap_serial_uart
# ----------------------------------------------------------------------------

def _uart_encode(data: bytes, spb: int) -> bytes:
    """Build a sample stream of one channel (bit 0) representing 8N1 frames."""
    samples = bytearray()
    samples.extend([1] * (spb * 4))  # idle prefix
    for byte in data:
        # start bit (0)
        samples.extend([0] * spb)
        # 8 data bits LSB-first
        for b in range(8):
            bit = (byte >> b) & 1
            samples.extend([bit] * spb)
        # stop bit (1)
        samples.extend([1] * spb)
        # idle gap
        samples.extend([1] * spb)
    samples.extend([1] * (spb * 4))  # idle suffix
    return bytes(samples)


def test_uart_decode_round_trip():
    from pcap_serial_uart import decode

    spb = 8
    payload = b"Hello, UART!"
    stream = _uart_encode(payload, spb)
    out = decode(stream, spb, bit=0)
    # Decoder may include idle-noise byte at edges; check payload appears
    assert payload in out, f"got {out!r}"


# ----------------------------------------------------------------------------
# cbc_byte_recovery — local TCP oracle
# ----------------------------------------------------------------------------

class _CBCOracleServer(threading.Thread):
    """Threaded TCP server that mimics the chained-IV CBC oracle.

    On connect: send 16-byte IV.
    Per request: read u32-LE length, then plaintext. Encrypt (plaintext || secret)
    under AES-CBC with the per-connection IV (chained from previous response).
    Reply: u32-LE ciphertext length, then ciphertext.
    """

    def __init__(self, secret: bytes, key: bytes):
        super().__init__(daemon=True)
        self.secret = secret
        self.key = key
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except Exception:
            pass

    def run(self):
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad

        while not self._stop.is_set():
            try:
                self.sock.settimeout(0.5)
                try:
                    conn, _ = self.sock.accept()
                except socket.timeout:
                    continue
            except OSError:
                return

            t = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            t.start()

    def _handle(self, conn: socket.socket):
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad

        try:
            iv = os.urandom(16)
            conn.sendall(iv)
            while not self._stop.is_set():
                hdr = self._recv_exact(conn, 4)
                if hdr is None:
                    return
                length = struct.unpack("<I", hdr)[0]
                pt = self._recv_exact(conn, length)
                if pt is None:
                    return
                msg = pad(pt + self.secret, 16)
                ct = AES.new(self.key, AES.MODE_CBC, iv).encrypt(msg)
                conn.sendall(struct.pack("<I", len(ct)) + ct)
                iv = ct[-16:]
        except (ConnectionError, OSError):
            return
        finally:
            try:
                conn.close()
            except Exception:
                pass

    @staticmethod
    def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
        buf = b""
        while len(buf) < n:
            try:
                chunk = conn.recv(n - len(buf))
            except (ConnectionError, OSError):
                return None
            if not chunk:
                return None
            buf += chunk
        return buf


def test_cbc_byte_recovery():
    from cbc_byte_recovery import recover

    secret = b"FLAG_TOP_SECRET"
    key = os.urandom(16)
    server = _CBCOracleServer(secret, key)
    server.start()
    try:
        recovered = recover("127.0.0.1", server.port, max_len=len(secret))
        assert recovered == secret, f"got {recovered!r}"
    finally:
        server.stop()


# ----------------------------------------------------------------------------
# cbc_padding_oracle — also exercise _demo via subprocess
# ----------------------------------------------------------------------------

def test_cbc_padding_oracle_demo_subprocess():
    result = subprocess.run(
        [PYTHON, str(REPO / "cbc_padding_oracle.py"), "--demo"],
        capture_output=True, text=True, cwd=str(REPO), timeout=60,
    )
    assert result.returncode == 0, result.stderr
    # _demo prints the recovered (padded) plaintext, which contains the message
    assert b"squeamish ossifrage at dawn" in result.stdout.encode()


# ----------------------------------------------------------------------------
# multi_base_decode
# ----------------------------------------------------------------------------

def test_multi_base_decode_b64_single_layer():
    import base64 as _b
    from multi_base_decode import unwrap

    plain = b"the flag is squeamish ossifrage at dawn"
    blob = _b.b64encode(plain)
    chains = unwrap(blob)
    assert any(leaf == plain for _, leaf in chains), f"plain not in chains: {chains[:5]}"
    assert any("base64" in chain for chain, _ in chains)


def test_multi_base_decode_nested_b64_then_b32():
    import base64 as _b
    from multi_base_decode import unwrap

    plain = b"hello world this is a longer message for chi squared scoring"
    inner = _b.b32encode(plain)
    outer = _b.b64encode(inner)
    chains = unwrap(outer, max_layers=4)
    assert any(leaf == plain for _, leaf in chains), f"plain not in chains: {chains[:5]}"


def test_multi_base_decode_b58():
    from multi_base_decode import unwrap

    ALPH = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    payload = b"flag{base58}"
    n = int.from_bytes(payload, "big")
    enc = b""
    while n:
        n, r = divmod(n, 58)
        enc = ALPH[r:r + 1] + enc
    for byte in payload:
        if byte == 0:
            enc = b"1" + enc
        else:
            break
    chains = unwrap(enc)
    assert any(leaf == payload for _, leaf in chains), f"payload not in chains: {chains[:5]}"
