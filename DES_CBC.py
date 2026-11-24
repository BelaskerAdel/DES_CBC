#!/usr/bin/env python3
"""DES-CBC: an educational, from-scratch implementation of DES in CBC mode.

Every part of the Data Encryption Standard (DES) block cipher is implemented by
hand - the permutation tables, the key schedule, the sixteen Feistel rounds and
the eight S-boxes - together with the Cipher Block Chaining (CBC) mode of
operation and PKCS#7 padding. The goal is readability: the code is meant to be
followed alongside a description of the algorithm.

Security
--------
DES is cryptographically **broken**. Its 56-bit key is brute-forceable in hours,
and this implementation is not constant-time or side-channel resistant. Use it to
learn, never to protect real data. For production, use a vetted library such as
``cryptography`` with AES-GCM.

Command line
------------
    python DES_CBC.py selftest
    python DES_CBC.py encrypt --key 1f4f8a113b4a5d66 --iv 0000000000010100 --text "Adel"
    python DES_CBC.py decrypt --key 1f4f8a113b4a5d66 --iv 0000000000010100 --hex f4ed...

Author: Adel Belasker - https://www.linkedin.com/in/belasker/
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Sequence, Union

__all__ = ["DES", "encrypt", "decrypt", "BLOCK_SIZE"]

#: DES operates on 64-bit (8-byte) blocks.
BLOCK_SIZE = 8

Key = Union[bytes, str]
Bits = List[int]


# ---------------------------------------------------------------------------
# DES permutation / substitution tables (all indices are 0-based)
# ---------------------------------------------------------------------------

#: Initial permutation of the 64-bit input block.
_IP: Sequence[int] = (
    57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7,
    56, 48, 40, 32, 24, 16,  8,  0, 58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4, 62, 54, 46, 38, 30, 22, 14,  6,
)

#: Expands a 32-bit half block to 48 bits inside the round function.
_EXPANSION: Sequence[int] = (
    31,  0,  1,  2,  3,  4,  3,  4,  5,  6,  7,  8,
     7,  8,  9, 10, 11, 12, 11, 12, 13, 14, 15, 16,
    15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24,
    23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31,  0,
)

#: Permuted Choice 1: selects 56 key bits (drops the 8 parity bits).
_PC1: Sequence[int] = (
    56, 48, 40, 32, 24, 16,  8,  0, 57, 49, 41, 33, 25, 17,
     9,  1, 58, 50, 42, 34, 26, 18, 10,  2, 59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14,  6, 61, 53, 45, 37, 29, 21,
    13,  5, 60, 52, 44, 36, 28, 20, 12,  4, 27, 19, 11,  3,
)

#: Left rotations applied to each key half, per round.
_LEFT_ROTATIONS: Sequence[int] = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

#: Permuted Choice 2: selects the 48-bit subkey from the rotated halves.
_PC2: Sequence[int] = (
    13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
    22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
    40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
    43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31,
)

#: Final permutation (the inverse of the initial permutation).
_FP: Sequence[int] = (
    39,  7, 47, 15, 55, 23, 63, 31, 38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29, 36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27, 34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25, 32,  0, 40,  8, 48, 16, 56, 24,
)

#: Straight permutation applied to the S-box output inside the round function.
_P: Sequence[int] = (
    15,  6, 19, 20, 28, 11, 27, 16,  0, 14, 22, 25,  4, 17, 30,  9,
     1,  7, 23, 13, 31, 26,  2,  8, 18, 12, 29,  5, 21, 10,  3, 24,
)

#: The eight S-boxes, each a flat 64-entry table (4 rows x 16 columns).
_SBOX: Sequence[Sequence[int]] = (
    (14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
      0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
      4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
     15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13),
    (15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
      3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
      0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
     13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9),
    (10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
     13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
     13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
      1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12),
    ( 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
     13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
     10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
      3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14),
    ( 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
     14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
      4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
     11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3),
    (12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
     10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
      9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
      4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13),
    ( 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
     13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
      1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
      6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12),
    (13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
      1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
      7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
      2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11),
)


# ---------------------------------------------------------------------------
# Bit / byte helpers
# ---------------------------------------------------------------------------

def _bytes_to_bits(data: bytes) -> Bits:
    """Expand *data* into a flat list of bits, most-significant bit first."""
    return [(byte >> (7 - i)) & 1 for byte in data for i in range(8)]


def _bits_to_bytes(bits: Bits) -> bytes:
    """Pack a flat bit list (length a multiple of 8) back into bytes."""
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)


def _permute(block: Bits, table: Sequence[int]) -> Bits:
    """Reorder *block* so that output bit ``i`` is ``block[table[i]]``."""
    return [block[i] for i in table]


def _xor(a: Bits, b: Bits) -> Bits:
    """Bitwise XOR of two equal-length bit lists."""
    return [x ^ y for x, y in zip(a, b)]


def _coerce_key(key: Key) -> bytes:
    """Return an 8-byte key from a ``bytes`` value or a 16-char hex string."""
    if isinstance(key, str):
        key = bytes.fromhex(key)
    if len(key) != BLOCK_SIZE:
        raise ValueError("DES key must be 8 bytes (64 bits / 16 hex characters)")
    return key


# ---------------------------------------------------------------------------
# PKCS#7 padding
# ---------------------------------------------------------------------------

def _pad(data: bytes) -> bytes:
    """Append PKCS#7 padding to a multiple of the block size."""
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def _unpad(data: bytes) -> bytes:
    """Strip and validate PKCS#7 padding; raise ``ValueError`` if it is invalid."""
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("Invalid padded data length")
    pad_len = data[-1]
    if not 1 <= pad_len <= BLOCK_SIZE or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-pad_len]


# ---------------------------------------------------------------------------
# The DES block cipher
# ---------------------------------------------------------------------------

class DES:
    """The DES block cipher under a fixed 64-bit key.

    The key schedule is computed once on construction; the resulting round
    subkeys are reused for every block, which is why a single instance should
    be created per key and shared across calls.
    """

    block_size = BLOCK_SIZE

    def __init__(self, key: Key) -> None:
        self._subkeys = self._key_schedule(_bytes_to_bits(_coerce_key(key)))

    # -- public block API --------------------------------------------------

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt a single 8-byte block."""
        self._check_block(block)
        return _bits_to_bytes(self._feistel(_bytes_to_bits(block), self._subkeys))

    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt a single 8-byte block (the subkeys are applied in reverse)."""
        self._check_block(block)
        return _bits_to_bytes(self._feistel(_bytes_to_bits(block), self._subkeys[::-1]))

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _check_block(block: bytes) -> None:
        if len(block) != BLOCK_SIZE:
            raise ValueError(f"DES block must be exactly {BLOCK_SIZE} bytes")

    @staticmethod
    def _key_schedule(key_bits: Bits) -> List[Bits]:
        """Derive the sixteen 48-bit round subkeys from the 64-bit key."""
        left, right = (lambda k: (k[:28], k[28:]))(_permute(key_bits, _PC1))
        subkeys: List[Bits] = []
        for shift in _LEFT_ROTATIONS:
            left = left[shift:] + left[:shift]
            right = right[shift:] + right[:shift]
            subkeys.append(_permute(left + right, _PC2))
        return subkeys

    @staticmethod
    def _round_function(half: Bits, subkey: Bits) -> Bits:
        """The Feistel function f(R, K): 32 bits in, 32 bits out."""
        mixed = _xor(_permute(half, _EXPANSION), subkey)   # expand to 48, mix key
        out: Bits = []
        for i in range(8):                                 # eight S-boxes
            chunk = mixed[i * 6:i * 6 + 6]
            row = (chunk[0] << 1) | chunk[5]
            col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
            value = _SBOX[i][row * 16 + col]
            out.extend((value >> (3 - b)) & 1 for b in range(4))
        return _permute(out, _P)                           # straight permutation

    @classmethod
    def _feistel(cls, block_bits: Bits, subkeys: Sequence[Bits]) -> Bits:
        """Run the full 16-round Feistel network on one block."""
        block = _permute(block_bits, _IP)
        left, right = block[:32], block[32:]
        for subkey in subkeys:
            left, right = right, _xor(left, cls._round_function(right, subkey))
        return _permute(right + left, _FP)                 # note the final swap


# ---------------------------------------------------------------------------
# CBC mode - the public module API
# ---------------------------------------------------------------------------

def encrypt(plaintext: bytes, key: Key, iv: bytes) -> bytes:
    """Encrypt *plaintext* with DES in CBC mode and PKCS#7 padding."""
    _check_iv(iv)
    cipher = DES(key)
    previous = iv
    out = bytearray()
    for block in _blocks(_pad(plaintext)):
        previous = cipher.encrypt_block(bytes(a ^ b for a, b in zip(block, previous)))
        out.extend(previous)
    return bytes(out)


def decrypt(ciphertext: bytes, key: Key, iv: bytes) -> bytes:
    """Decrypt a DES-CBC *ciphertext* produced by :func:`encrypt`."""
    _check_iv(iv)
    if len(ciphertext) % BLOCK_SIZE:
        raise ValueError("Ciphertext length must be a multiple of the block size")
    cipher = DES(key)
    previous = iv
    out = bytearray()
    for block in _blocks(ciphertext):
        out.extend(a ^ b for a, b in zip(cipher.decrypt_block(block), previous))
        previous = block
    return _unpad(bytes(out))


def _check_iv(iv: bytes) -> None:
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"IV must be exactly {BLOCK_SIZE} bytes")


def _blocks(data: bytes):
    """Yield *data* one block at a time."""
    for i in range(0, len(data), BLOCK_SIZE):
        yield data[i:i + BLOCK_SIZE]


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def self_test() -> None:
    """Validate against a known-answer vector and round-trip several messages."""
    # DES known-answer test: key, plaintext -> ciphertext (from the FIPS example).
    cipher = DES(bytes.fromhex("133457799BBCDFF1"))
    block = bytes.fromhex("0123456789ABCDEF")
    expected = bytes.fromhex("85E813540F0AB405")
    assert cipher.encrypt_block(block) == expected, "DES known-answer test failed"
    assert cipher.decrypt_block(expected) == block, "DES block decryption failed"

    key, iv = "1f4f8a113b4a5d66", bytes.fromhex("0000000000010100")
    for message in (b"", b"Adel Belasker", b"DES in CBC mode - educational only!"):
        assert decrypt(encrypt(message, key, iv), key, iv) == message, (
            f"CBC round-trip failed for {message!r}"
        )
    print("All self-tests passed.")


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Educational DES-CBC encryption/decryption (not for real secrets).",
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("selftest", help="run the built-in known-answer and round-trip tests")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--key", required=True, help="64-bit key as 16 hex characters")
    common.add_argument("--iv", required=True, help="64-bit IV as 16 hex characters")

    enc = subparsers.add_parser("encrypt", parents=[common], help="encrypt UTF-8 text")
    enc.add_argument("--text", required=True, help="plaintext to encrypt")

    dec = subparsers.add_parser("decrypt", parents=[common], help="decrypt a hex ciphertext")
    dec.add_argument("--hex", required=True, help="ciphertext as a hex string")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "encrypt":
            ciphertext = encrypt(args.text.encode(), args.key, bytes.fromhex(args.iv))
            print(ciphertext.hex())
        elif args.command == "decrypt":
            plaintext = decrypt(bytes.fromhex(args.hex), args.key, bytes.fromhex(args.iv))
            print(plaintext.decode(errors="replace"))
        else:  # no command, or "selftest": run the tests then a short demo
            self_test()
            _demo()
    except (ValueError, UnicodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def _demo() -> None:
    key, iv = "1f4f8a113b4a5d66", bytes.fromhex("0000000000010100")
    message = b"Adel Belasker"
    ciphertext = encrypt(message, key, iv)
    print(f"Key (hex)  : {key}")
    print(f"IV  (hex)  : {iv.hex()}")
    print(f"Plaintext  : {message!r}")
    print(f"Ciphertext : {ciphertext.hex()}")
    print(f"Decrypted  : {decrypt(ciphertext, key, iv)!r}")


if __name__ == "__main__":
    raise SystemExit(main())
