# CHEATSHEET

---

## Decision tree by symptom

- **Long printable string given** → see [Encoding tells](#encoding-tells). If unknown layered → `python multi_base_decode.py -`.
- **Hex / b64-looking blob, ASCII output suspected** → `multi_base_decode`, then `rot_brute`, then `vigenere_break` (if pure letters).
- **Unknown binary blob** → `file <f>`; `xxd <f> | head`; `binwalk -E <f>`; check [Magic bytes](#magic-bytes); if structured archive → `binwalk -e <f>` or `foremost -i <f>`.
- **Image with hidden data** → `exiftool <f>`; `binwalk <f>`; `zsteg -a <f>` (PNG/BMP); `steghide info <f>` / `stegseek <f> rockyou.txt` (JPEG); `python lsb_image_extract.py <f> --planes`.
- **GIF with subtle changes between frames** → `python gif_frame_diff.py <gif>`.
- **PCAP given** → `tshark -r <f> -q -z conv,tcp` (protocol overview); then by traffic type:
  - USB HID (keyboard) → `python pcap_usb_hid.py <f> --layout {us,uk}`
  - USB Mass Storage → `python pcap_usb_mass_storage.py <f> out.bin`
  - Logic-analyser UART → `python pcap_serial_uart.py <f> --spb N`
  - HTTP → `tshark -r <f> --export-objects http,./out`
  - DNS exfil → `tshark -r <f> -Y dns -T fields -e dns.qry.name`
  - TLS with keylog → `tshark -r <f> -o tls.keylog_file:keys.log`
- **RSA challenge with N + e** → see [Crypto decision tree](#crypto-decision-tree).
- **AES ciphertext** → see [Crypto decision tree](#crypto-decision-tree).
- **XOR ciphertext, partial known plaintext** → `python xor_known_plaintext.py`.
- **Several XOR ciphertexts under same key (many-time pad)** → `python mtp_solver.py`.
- **Hash that needs cracking** → `python hash_identify.py <hash>` → feed mode ID to `hashcat -m <mode> -a 0 <hash> rockyou.txt` or `john --format=<name> --wordlist=rockyou.txt`.
- **Web JWT** → `python jwt_attack.py decode <token>`; then `none`, `brute`, `tamper`, or `kid`.
- **Web LFI primitive** → `python lfi_payloads.py {traversal,filter,proc,log}`.
- **Web SQLi** → `sqlmap -u 'URL' --batch --dbs` (start with `--level=3 --risk=2` if defaults fail).
- **Web directory bust** → `gobuster dir -u URL -w /usr/share/seclists/Discovery/Web-Content/common.txt`.
- **Binary with `printf(user_input)`** → `python format_string.py {offset,leak,write}`.
- **Binary ELF, no clear approach** → `checksec <bin>`; `strings -n8 <bin> | less`; `r2 -A <bin>` then `pdf @ main`; `gdb-pwndbg <bin>` then `vmmap`.
- **Memory dump (.dmp / .vmem / .raw)** → `vol -f <f> windows.info` → `windows.pslist`, `windows.cmdline`, `windows.filescan`, `windows.dumpfiles --pid N`.

---

## Flag formats

- UKCT: `flag{...}` (online round). Other common: `FLAG{...}`, `CTF{...}`, `picoCTF{...}`, `HTB{...}`.
- Grep: `grep -aEo 'flag\{[^}]+\}'`

---

## Magic bytes

| Hex prefix | Type |
|-|-|
| `89 50 4E 47 0D 0A 1A 0A` | PNG |
| `FF D8 FF [E0/E1/DB/EE]` | JPEG |
| `47 49 46 38 [37/39] 61` | GIF87a / GIF89a |
| `25 50 44 46 2D` | PDF (`%PDF-`) |
| `50 4B 03 04` | ZIP / docx / xlsx / apk / jar |
| `52 61 72 21 1A 07 [00/01]` | RAR |
| `37 7A BC AF 27 1C` | 7z |
| `1F 8B` | gzip |
| `42 5A 68` | bzip2 (`BZh`) |
| `FD 37 7A 58 5A 00` | xz |
| `7F 45 4C 46` | ELF |
| `4D 5A` | PE (`MZ`) |
| `CF FA ED FE` | Mach-O 64 LE |
| `CA FE BA BE` | Java class / Mach-O fat |
| `FF FB` / `FF F3` / `49 44 33` | MP3 (ADTS / ID3) |
| `66 4C 61 43` | FLAC (`fLaC`) |
| `4F 67 67 53` | OGG |
| `52 49 46 46 .... 57 41 56 45` | WAV |
| `38 42 50 53` | Photoshop PSD |
| `49 49 2A 00` / `4D 4D 00 2A` | TIFF (LE / BE) |

Triage commands: `file <f>`; `xxd <f> | head -2`; `binwalk <f>`; `binwalk -e <f>` (extract); `foremost -i <f> -o out`; `exiftool <f>`.

---

## Encoding tells

| Observable | Likely |
|-|-|
| Only `[0-9a-fA-F]`, even length | hex |
| `[A-Z2-7]+=*` (uppercase + 2-7, `=` pad) | base32 |
| `[A-Za-z0-9+/]+=*` | base64 |
| `[A-Za-z0-9_-]+` (no `=`, has `-_`) | base64url |
| `[A-Za-z0-9]+` no padding, mixed case | base62 or base64url |
| `[1-9A-HJ-NP-Za-km-z]+` (no `0OIl`) | base58 (Bitcoin) |
| `[!-~]+` 91-char subset, no spaces | base91 |
| Dots, dashes, spaces only | Morse |
| `:!\-,.\?` puncuation noise | brainfuck / esolang |
| Numbers > 32 grouped, no ascii | possibly ASCII codepoints |
| Binary `[01]+` length % 8 == 0 | raw bits → bytes |

---

## Command cribs

### `openssl`
```
openssl enc -d -aes-256-cbc -in c.bin -K HEX -iv HEX -nopad   # decrypt without unpadding
openssl rsa -in key.pem -text -noout                          # dump n, e, d, p, q
openssl rsautl -decrypt -in c.bin -inkey key.pem -raw         # raw RSA decrypt (no padding strip)
openssl dgst -sha256 -hmac 'secret' file                      # HMAC-SHA256
openssl s_client -connect host:443 -servername host           # TLS probe
```

### `pwntools` (Python)
```
from pwn import *
context.binary = './chal'                # auto-sets arch/bits/endian
p = process('./chal'); r = remote('h', 1337)
cyclic(200); cyclic_find(0x6161616c)     # offset finding
ROP(elf).call('system', ['/bin/sh'])     # ROP chain
from pwnlib.fmtstr import fmtstr_payload
fmtstr_payload(offset, {addr: value})    # arbitrary write
shellcraft.amd64.linux.sh()              # /bin/sh shellcode src
```

### `radare2`
```
r2 -A bin            # analyse on open
aaa                  # extra analysis
afl                  # list functions
pdf @ main           # disasm main
axt @ sym.func       # cross-refs to func
/R pop ; ret         # ROP gadget search
V! / VV              # visual graph / panel
```

### `gdb` (with pwndbg / peda)
```
checksec             # show mitigations
vmmap                # mapped regions
pattern create 200   # cyclic input
pattern offset 0x...
got / plt            # show GOT/PLT
heap / bins          # glibc heap state
find /x 0xdeadbeef, +0x1000   # search memory
```

### `john`
```
john --wordlist=rockyou.txt --format=raw-sha256 hashes.txt
john --incremental hashes.txt            # brute mode
john --show --format=bcrypt hashes.txt   # display cracked
john --list=formats | grep -i sha        # list available formats
```

### `hashcat`
```
hashcat -m 0    -a 0 hashes.txt rockyou.txt        # MD5 dictionary
hashcat -m 1400 -a 3 hashes.txt '?l?l?l?l?l?l'     # SHA-256 mask
hashcat -m 1800 -a 0 hashes.txt rockyou.txt -r OneRuleToRuleThemAll.rule
hashcat --show -m 0 hashes.txt           # display cracked
hashcat -b -m 0                          # benchmark
```

Common modes: MD5=0, SHA1=100, SHA256=1400, SHA512=1700, NTLM=1000, bcrypt=3200, sha512crypt=1800, PHPass=400, MySQL5=300.

### `volatility3`
```
vol -f mem.raw windows.info
vol -f mem.raw windows.pslist
vol -f mem.raw windows.cmdline
vol -f mem.raw windows.filescan | grep -i flag
vol -f mem.raw windows.dumpfiles --pid 1234
vol -f mem.raw windows.malfind
```

### `binwalk`
```
binwalk file              # list embedded signatures
binwalk -e file           # extract
binwalk -E file           # entropy analysis (find compressed/encrypted segments)
binwalk -M file           # recursive extract
binwalk --dd='.*' file    # extract everything
```

---

## Crypto decision tree

### RSA — by N size and parameters

| Symptom | Attack | Script / tool |
|-|-|-|
| `N < 2^256` | factor directly | `factordb.com`, `yafu`, `sage` |
| `N` between known factors | factordb lookup | `curl 'http://factordb.com/api?query=<N>'` |
| `p` close to `q` | Fermat factorisation | `sage`, or hand-rolled |
| Small `e` (3, 5, 17), no padding, `m^e < N` | direct e-th root | `rsa_toolkit.py small-e` |
| Same `m`, same `N`, two coprime `e` | common modulus | `rsa_toolkit.py common-modulus` |
| Same `m`, same `e`, ≥ e distinct moduli | Håstad broadcast | `rsa_toolkit.py hastad` |
| `d` small (< N^0.25 / 3) | Wiener | `rsa_toolkit.py wiener` |
| Partial bits of `p` or `m` known | Coppersmith | sage `small_roots()` |
| `e` and `phi` not coprime (rare) | factor `gcd(e, phi)` | manual |
| Shared `p` across two `N` | `gcd(N1, N2)` | `python -c "from math import gcd; print(gcd(N1,N2))"` |

### AES — by mode

| Symptom | Attack | Script |
|-|-|-|
| Repeated 16-byte blocks in CT | ECB | `ecb_toolkit.py detect` |
| ECB oracle appends secret | byte-at-a-time | `ecb_toolkit.py byte-at-a-time` |
| ECB oracle with admin/user prefix | cut-and-paste blocks | manual (block alignment) |
| CBC with padding-error side channel | padding oracle | `cbc_padding_oracle.py` |
| CBC with chained-IV next-block oracle | byte-at-a-time | `cbc_byte_recovery.py` |
| CBC, known PT, want chosen PT | bit-flip prev block | `cbc_bitflip.py` |
| CTR with reused keystream | XOR pairs / crib drag | `xor_known_plaintext.py`, `mtp_solver.py` |
| GCM with reused nonce | forbidden attack | manual sage (not yet scripted) |
| Stream cipher with reused key | many-time pad | `mtp_solver.py` |

### Other crypto

- Vigenère / Caesar / ROT-N → `vigenere_break.py`, `rot_brute.py`
- XOR with known crib → `xor_known_plaintext.py`
- Hash crack → `hash_identify.py` → `hashcat` / `john`
- JWT → `jwt_attack.py`
