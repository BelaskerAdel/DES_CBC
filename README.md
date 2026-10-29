# DES-CBC

A from-scratch, pure-Python implementation of the **Data Encryption Standard (DES)**
block cipher running in **Cipher Block Chaining (CBC)** mode. Every part of the
algorithm — the permutation tables, the key schedule, the 16 Feistel rounds, the
eight S-boxes and the block chaining — is implemented by hand, so the code can be
read as a walk-through of how DES actually works.

> ⚠️ **Educational use only.** DES is cryptographically broken: its 56-bit key can
> be brute-forced in hours, and this implementation is not constant-time or
> side-channel resistant. Never use it to protect real data. For production use a
> vetted library such as [`cryptography`](https://cryptography.io) with AES-GCM.

## Features

- Complete DES block cipher implemented from the specification (no crypto libraries)
- CBC mode with an initialization vector (IV)
- PKCS#7 padding, so messages of any length round-trip exactly
- Clean `bytes`-based API plus the low-level block/key-schedule functions
- Built-in self-test that checks a published DES known-answer test vector

## Requirements

- Python 3.9+ (no third-party dependencies)

## Usage

Run the demo and self-test directly:

```bash
python des_cbc.py
```

Use it as a module:

```python
import des_cbc

key = "1f4f8a113b4a5d66"          # 8 bytes, as 16 hex chars (or a bytes object)
iv  = bytes([0] * 5 + [1] * 2 + [0])  # 8-byte initialization vector

ciphertext = des_cbc.encrypt(b"Adel Belasker", key, iv)
plaintext  = des_cbc.decrypt(ciphertext, key, iv)

assert plaintext == b"Adel Belasker"
```

### API

| Function | Description |
|---|---|
| `encrypt(plaintext: bytes, key, iv: bytes) -> bytes` | DES-CBC encrypt with PKCS#7 padding |
| `decrypt(ciphertext: bytes, key, iv: bytes) -> bytes` | DES-CBC decrypt and remove padding |
| `generate_subkeys(key_bits)` | Derive the 16 round subkeys |
| `encrypt_block(block, subkeys)` / `decrypt_block(...)` | Single 8-byte block operations |

`key` may be an 8-byte `bytes` object or a 16-character hex string.

## How DES works (quick tour of the code)

1. **Key schedule** (`generate_subkeys`) — PC-1 selects 56 bits from the 64-bit key,
   which is then split and rotated each round, and PC-2 picks the 48-bit subkey.
2. **Initial permutation** (`IP`) reorders the 64 input bits.
3. **16 Feistel rounds** — each round runs the right half through the round function
   `f` (expansion → XOR with subkey → S-boxes → permutation `P`) and XORs the result
   into the left half.
4. **Final permutation** (`FP`) produces the output block.
5. **CBC mode** XORs each plaintext block with the previous ciphertext block (or the
   IV for the first block) before encryption, so identical blocks encrypt differently.

## References

- [DES explained (PDF)](http://highered.mheducation.com/sites/dl/free/007070208x/877405/Chapter_06_Data_Encription_Standard.pdf)
- [Cipher Block Chaining mode (Wikipedia)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC))

## Author

**Adel Belasker** — [LinkedIn](https://www.linkedin.com/in/belasker/)
