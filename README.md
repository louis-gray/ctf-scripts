# ctf-scripts

A grab-bag of self-contained scripts I've written to handle recurring problems
in CTFs. Each script tries to do one thing, document its inputs at the top,
and stay readable enough to fork into a one-off solver when a challenge
needs something close-but-not-quite.

## Scripts

- `xor_known_plaintext.py` — slide a known plaintext fragment across an XOR
  ciphertext to recover the key and rank candidate plaintexts by printability.

## Setup

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```
