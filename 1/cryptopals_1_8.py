#!/usr/bin/env python3

"""Cryptopals set 1 challenges 7 and 8.

https://cryptopals.com/sets/1/challenges/7
https://cryptopals.com/sets/1/challenges/8
"""

import base64
import unittest

import cryptography.hazmat.primitives.ciphers as ciphers
import cryptography.hazmat.primitives.padding as padding


def ecb_pkcs7_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    cipher = ciphers.Cipher(ciphers.algorithms.AES(key), ciphers.modes.ECB())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext)
    padded += dec.finalize()
    unpadder = padding.PKCS7(16 * 8).unpadder()
    plaintext = unpadder.update(padded)
    plaintext += unpadder.finalize()
    return plaintext


def has_repeated_blocks(block_size: int, data: bytes) -> bool:
    """Whether there are at least two identical blocks in data."""
    if len(data) < 2 * block_size:
        return False
    blocks = set()
    for i in range(0, len(data) - 2 * block_size + 1, block_size):
        block = data[i:i + block_size]
        if block in blocks:
            return True
        blocks.add(block)
    return False


class Tests(unittest.TestCase):
    def test_challenge7(self) -> None:
        with open('7.txt') as input_file:
            ciphertext = base64.b64decode(input_file.read())
        key = b'YELLOW SUBMARINE'
        plaintext = ecb_pkcs7_decrypt(key, ciphertext)
        self.assertTrue(plaintext.endswith(b'\nPlay that funky music \n'))

    def test_challenge8(self) -> None:
        with open('8.txt') as input_file:
            ciphertexts = [base64.b64decode(line) for line in input_file]
        likely_ecb = [i for i in range(len(ciphertexts))
                      if has_repeated_blocks(16, ciphertexts[i])]
        self.assertEqual(likely_ecb, [132])


if __name__ == '__main__':
    unittest.main()
