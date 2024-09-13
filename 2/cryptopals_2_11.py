#!/usr/bin/env python3

"""Cryptopals set 2 challenge 11.

https://cryptopals.com/sets/2/challenges/11
"""

import enum
import os
import unittest
from typing import Callable, Union

from cryptography.hazmat.primitives import ciphers



BLOCK_SIZE = 16

class Mode(enum.Enum):
    ECB = 0
    CBC = 1

CipherMode = Union[ciphers.modes.ECB, ciphers.modes.CBC]


def encrypt_ecb_or_cbc(mode: Mode,
                       prefix_length: int,
                       suffix_length: int,
                       plaintext: bytes) -> bytes:
    key = os.urandom(BLOCK_SIZE)
    if mode == Mode.CBC:
        mode_object = ciphers.modes.CBC(os.urandom(BLOCK_SIZE)) #type: CipherMode
    else:
        mode_object = ciphers.modes.ECB()
    cipher = ciphers.Cipher(ciphers.algorithms.AES(key), mode_object)
    enc = cipher.encryptor()
    ciphertext = b''
    ciphertext += enc.update(os.urandom(prefix_length))
    ciphertext += enc.update(plaintext)
    ciphertext += enc.update(os.urandom(suffix_length))
    padding_length = BLOCK_SIZE - (prefix_length + len(plaintext) + suffix_length) % BLOCK_SIZE
    ciphertext += enc.update(os.urandom(padding_length))
    ciphertext += enc.finalize()
    return ciphertext

Encryptor = Callable[[bytes], bytes]



def guess_ecb_or_cbc(encryptor: Encryptor) -> Mode:
    plaintext = b'A' * (BLOCK_SIZE * 3 - 1)
    ciphertext = encryptor(plaintext)
    blocks = set()
    found_repeat = False
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i: i + BLOCK_SIZE]
        if block in blocks:
            found_repeat = True
            break
        blocks.add(block)
    return Mode.ECB if found_repeat else Mode.CBC


class Tests(unittest.TestCase):
    def one_case(self, mode: Mode,
                 prefix_length: int, suffix_length: int) -> None:
        encryptor = lambda plaintext: \
            encrypt_ecb_or_cbc(mode, prefix_length, suffix_length, plaintext)
        guessed = guess_ecb_or_cbc(encryptor)
        self.assertEqual(mode, guessed)

    def test_ecb_detection(self) -> None:
        for prefix_length in range(16):
            for suffix_length in (0, 5):
                for mode in Mode:
                    with self.subTest(mode=mode,
                                      prefix_length=prefix_length,
                                      suffix_length=suffix_length):
                        self.one_case(mode, prefix_length, suffix_length)


if __name__ == '__main__':
    unittest.main()
