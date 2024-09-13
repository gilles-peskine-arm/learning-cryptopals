#!/usr/bin/env python3

"""Cryptopals set 2 challenge 12.

https://cryptopals.com/sets/2/challenges/12
"""

import base64
import os
from typing import Callable
import unittest

from cryptography.hazmat.primitives import ciphers



BLOCK_SIZE = 16

_KEY = os.urandom(16)

_SECRET_BASE64 = """\
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""
_SECRET = base64.b64decode(_SECRET_BASE64)
SECRET_LENGTH = len(_SECRET)

def ecb_encrypt(plaintext: bytes) -> bytes:
    cipher = ciphers.Cipher(ciphers.algorithms.AES(_KEY), ciphers.modes.ECB())
    enc = cipher.encryptor()
    ciphertext = b''
    ciphertext += enc.update(plaintext)
    ciphertext += enc.update(_SECRET)
    padding_length = BLOCK_SIZE - (len(plaintext) + len(_SECRET)) % BLOCK_SIZE
    ciphertext += enc.update(os.urandom(padding_length))
    ciphertext += enc.finalize()
    return ciphertext

Oracle = Callable[[bytes], bytes]


def check_byte(oracle: Oracle, correct_prefix: bytes, value: int) -> bool:
    k = BLOCK_SIZE - len(correct_prefix) % BLOCK_SIZE - 1
    plaintext1 = b'A' * k
    plaintext2 = plaintext1 + correct_prefix + bytes([value])
    m = len(plaintext2)
    assert m % BLOCK_SIZE == 0
    ciphertext1 = oracle(plaintext1)
    ciphertext2 = oracle(plaintext2)
    return ciphertext1[m - BLOCK_SIZE:m] == ciphertext2[m - BLOCK_SIZE:m]

def decrypt(oracle: Oracle) -> bytes:
    prefix = b''
    for n in range(SECRET_LENGTH):
        for b in range(256):
            if check_byte(oracle, prefix, b):
                prefix += bytes([b])
                break
        else:
            raise Exception('No valid byte after ' + str(prefix))
    return prefix

class Tests(unittest.TestCase):
    def test_challenge_2_12(self) -> None:
        self.assertEqual(decrypt(ecb_encrypt), _SECRET)

if __name__ == '__main__':
    unittest.main()
