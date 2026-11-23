"""
DES_CBC.py - A from-scratch implementation of DES in CBC mode (Python 3).

This is an *educational* implementation written to illustrate how the Data
Encryption Standard (DES) block cipher and the Cipher Block Chaining (CBC)
mode of operation work internally - the permutation tables, the Feistel
rounds, the S-boxes and the block chaining are all implemented by hand.

-----------------------------------------------------------------------------
SECURITY WARNING
-----------------------------------------------------------------------------
DES is **broken** and must never be used to protect real data. Its 56-bit key
is brute-forceable in hours on modern hardware. This code is also not written
to be constant-time or side-channel resistant. Use it to learn, not to secure.
For real applications use a vetted library (e.g. AES-GCM via `cryptography`).
-----------------------------------------------------------------------------

Author : Adel Belasker  -  https://www.linkedin.com/in/belasker/
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# DES permutation / substitution tables (all indices are 0-based)
# ---------------------------------------------------------------------------

# Initial Permutation applied to the 64-bit input block.
IP = [57, 49, 41, 33, 25, 17, 9,  1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7,
      56, 48, 40, 32, 24, 16, 8,  0,
      58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6]

# Expansion table: expands the 32-bit half block to 48 bits inside f().
EXPANSION = [31,  0,  1,  2,  3,  4,
              3,  4,  5,  6,  7,  8,
              7,  8,  9, 10, 11, 12,
             11, 12, 13, 14, 15, 16,
             15, 16, 17, 18, 19, 20,
             19, 20, 21, 22, 23, 24,
             23, 24, 25, 26, 27, 28,
             27, 28, 29, 30, 31,  0]

# Permuted Choice 1: selects 56 bits from the 64-bit key (drops parity bits).
PC1 = [56, 48, 40, 32, 24, 16,  8,
        0, 57, 49, 41, 33, 25, 17,
        9,  1, 58, 50, 42, 34, 26,
       18, 10,  2, 59, 51, 43, 35,
       62, 54, 46, 38, 30, 22, 14,
        6, 61, 53, 45, 37, 29, 21,
       13,  5, 60, 52, 44, 36, 28,
       20, 12,  4, 27, 19, 11,  3]

# Number of left rotations of the key halves per round.
LEFT_ROTATIONS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# Permuted Choice 2: selects 48 bits from the rotated 56-bit key.
PC2 = [13, 16, 10, 23,  0,  4,
        2, 27, 14,  5, 20,  9,
       22, 18, 11,  3, 25,  7,
       15,  6, 26, 19, 12,  1,
       40, 51, 30, 36, 46, 54,
       29, 39, 50, 44, 32, 47,
       43, 48, 38, 55, 33, 52,
       45, 41, 49, 35, 28, 31]

# Final Permutation (inverse of IP) applied at the end of a block.
FP = [39,  7, 47, 15, 55, 23, 63, 31,
      38,  6, 46, 14, 54, 22, 62, 30,
      37,  5, 45, 13, 53, 21, 61, 29,
      36,  4, 44, 12, 52, 20, 60, 28,
      35,  3, 43, 11, 51, 19, 59, 27,
      34,  2, 42, 10, 50, 18, 58, 26,
      33,  1, 41,  9, 49, 17, 57, 25,
      32,  0, 40,  8, 48, 16, 56, 24]

# The eight S-boxes, each a flat list of 64 values (4 rows x 16 columns).
SBOX = [
    # S1
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    # S2
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    # S3
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    # S4
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    # S5
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    # S6
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    # S7
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    # S8
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]

# Straight permutation P applied to the S-box output inside f().
P = [15,  6, 19, 20, 28, 11,
     27, 16,  0, 14, 22, 25,
      4, 17, 30,  9,  1,  7,
     23, 13, 31, 26,  2,  8,
     18, 12, 29,  5, 21, 10,
      3, 24]

BLOCK_SIZE = 8  # DES operates on 64-bit (8-byte) blocks.


# ---------------------------------------------------------------------------
# Small bit helpers
# ---------------------------------------------------------------------------

def _bytes_to_bits(data: bytes) -> list[int]:
    """Convert a bytes object into a flat list of bits (MSB first)."""
    bits = []
    for byte in data:
        bits.extend((byte >> (7 - i)) & 1 for i in range(8))
    return bits


def _bits_to_bytes(bits: list[int]) -> bytes:
    """Convert a flat list of bits (length multiple of 8) back into bytes."""
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)


def _permute(block: list[int], table: list[int]) -> list[int]:
    """Return a new block whose i-th bit is block[table[i]]."""
    return [block[i] for i in table]


def _xor(a: list[int], b: list[int]) -> list[int]:
    """Bitwise XOR of two equal-length bit lists."""
    return [x ^ y for x, y in zip(a, b)]


# ---------------------------------------------------------------------------
# DES core
# ---------------------------------------------------------------------------

def generate_subkeys(key_bits: list[int]) -> list[list[int]]:
    """Derive the 16 round subkeys (48 bits each) from a 64-bit key."""
    key_56 = _permute(key_bits, PC1)        # 64 -> 56 bits (drop parity)
    c, d = key_56[:28], key_56[28:]         # two 28-bit halves
    subkeys = []
    for rotations in LEFT_ROTATIONS:
        # Rotate both halves left by the per-round amount.
        c = c[rotations:] + c[:rotations]
        d = d[rotations:] + d[:rotations]
        subkeys.append(_permute(c + d, PC2))  # 56 -> 48 bits
    return subkeys


def _f(r_half: list[int], subkey: list[int]) -> list[int]:
    """The DES round function f: takes 32-bit R and a 48-bit subkey -> 32 bits."""
    # 1) Expand R from 32 to 48 bits and mix with the subkey.
    mixed = _xor(_permute(r_half, EXPANSION), subkey)

    # 2) Run the 48 bits through the eight S-boxes (6 bits in -> 4 bits out).
    sbox_out: list[int] = []
    for box in range(8):
        six = mixed[box * 6:box * 6 + 6]
        row = (six[0] << 1) | six[5]                       # outer bits -> row
        col = (six[1] << 3) | (six[2] << 2) | (six[3] << 1) | six[4]  # column
        value = SBOX[box][row * 16 + col]
        sbox_out.extend((value >> (3 - i)) & 1 for i in range(4))

    # 3) Final straight permutation P.
    return _permute(sbox_out, P)


def _process_block(block_bits: list[int], subkeys: list[list[int]]) -> list[int]:
    """Run the 16 Feistel rounds on one 64-bit block with the given subkeys."""
    block = _permute(block_bits, IP)          # initial permutation
    left, right = block[:32], block[32:]
    for subkey in subkeys:
        left, right = right, _xor(left, _f(right, subkey))
    # Note the final swap: the output pre-image is R16 + L16.
    return _permute(right + left, FP)         # final permutation


def encrypt_block(block: bytes, subkeys: list[list[int]]) -> bytes:
    """Encrypt a single 8-byte block."""
    return _bits_to_bytes(_process_block(_bytes_to_bits(block), subkeys))


def decrypt_block(block: bytes, subkeys: list[list[int]]) -> bytes:
    """Decrypt a single 8-byte block (decryption = encryption with reversed subkeys)."""
    return _bits_to_bytes(_process_block(_bytes_to_bits(block), subkeys[::-1]))


# ---------------------------------------------------------------------------
# PKCS#7 padding so arbitrary-length messages round-trip exactly
# ---------------------------------------------------------------------------

def _pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def _unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Invalid padded data length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-pad_len]


def _normalise_key(key) -> bytes:
    """Accept an 8-byte key, or a 16-character hex string, and return 8 bytes."""
    if isinstance(key, str):
        key = bytes.fromhex(key)
    if len(key) != BLOCK_SIZE:
        raise ValueError("DES key must be 8 bytes (64 bits / 16 hex chars)")
    return key


# ---------------------------------------------------------------------------
# Public CBC API
# ---------------------------------------------------------------------------

def encrypt(plaintext: bytes, key, iv: bytes) -> bytes:
    """Encrypt `plaintext` (bytes) with DES-CBC. Returns the ciphertext bytes."""
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 8 bytes")
    subkeys = generate_subkeys(_bytes_to_bits(_normalise_key(key)))
    previous = iv
    ciphertext = bytearray()
    padded = _pad(plaintext)
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        xored = bytes(a ^ b for a, b in zip(block, previous))  # chain with previous
        encrypted = encrypt_block(xored, subkeys)
        ciphertext.extend(encrypted)
        previous = encrypted
    return bytes(ciphertext)


def decrypt(ciphertext: bytes, key, iv: bytes) -> bytes:
    """Decrypt a DES-CBC ciphertext produced by `encrypt`. Returns plaintext bytes."""
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 8 bytes")
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be a multiple of 8 bytes")
    subkeys = generate_subkeys(_bytes_to_bits(_normalise_key(key)))
    previous = iv
    plaintext = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        decrypted = decrypt_block(block, subkeys)
        plaintext.extend(a ^ b for a, b in zip(decrypted, previous))  # undo chaining
        previous = block
    return _unpad(bytes(plaintext))


# ---------------------------------------------------------------------------
# Demo / self-test
# ---------------------------------------------------------------------------

def _self_test() -> None:
    """Round-trip a few messages and check against a known DES test vector."""
    # Known-answer test from the DES specification (single block, ECB-equivalent):
    # key=0x133457799BBCDFF1, plaintext=0x0123456789ABCDEF -> 0x85E813540F0AB405
    key = bytes.fromhex("133457799BBCDFF1")
    subkeys = generate_subkeys(_bytes_to_bits(key))
    block = bytes.fromhex("0123456789ABCDEF")
    expected = bytes.fromhex("85E813540F0AB405")
    assert encrypt_block(block, subkeys) == expected, "DES known-answer test failed"
    assert decrypt_block(expected, subkeys) == block, "DES block decrypt failed"

    # CBC round-trip on arbitrary-length text.
    key = "1f4f8a113b4a5d66"
    iv = bytes([0] * 5 + [1] * 2 + [0])
    for message in (b"", b"Adel Belasker", b"DES in CBC mode - educational only!"):
        ct = encrypt(message, key, iv)
        pt = decrypt(ct, key, iv)
        assert pt == message, f"CBC round-trip failed for {message!r}"

    print("All self-tests passed.")


if __name__ == "__main__":
    _self_test()

    # Small interactive-style demo.
    key = "1f4f8a113b4a5d66"
    iv = bytes([0] * 5 + [1] * 2 + [0])
    message = b"Adel Belasker"
    ciphertext = encrypt(message, key, iv)
    recovered = decrypt(ciphertext, key, iv)

    print(f"Key (hex)   : {key}")
    print(f"IV  (hex)   : {iv.hex()}")
    print(f"Plaintext   : {message!r}")
    print(f"Ciphertext  : {ciphertext.hex()}")
    print(f"Decrypted   : {recovered!r}")
