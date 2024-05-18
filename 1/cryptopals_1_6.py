#!/usr/bin/env python3

"""Cryptopals set 1 challenges 3-6.

https://cryptopals.com/sets/1/challenges/3
https://cryptopals.com/sets/1/challenges/4
https://cryptopals.com/sets/1/challenges/5
https://cryptopals.com/sets/1/challenges/6
"""

import base64
import itertools
import math
import unittest


def xor(s1: bytes, s2: bytes) -> bytes:
    """Bitwise xor of two bit strings.

    If the strings are of different lengths, only the common prefix is processed.
    """
    return bytes(x1 ^ x2 for x1, x2 in zip(s1, s2))


def edit_distance(s1: bytes, s2: bytes):
    """Edit distance between two bit strings."""
    if len(s1) != len(s2):
        raise ValueError('The strings have different lengths: {} != {}'
                         .format(len(s1), len(s2)))
    distance = 0
    for b1, b2 in zip(s1, s2):
        x = b1 ^ b2
        while x:
            if x & 1:
                distance += 1
            x >>= 1
    return distance


def block_dissimilarity(ciphertext: bytes, block_size: int) -> float:
    # We ignore the last incomplete block.
    block_count = len(ciphertext) // block_size
    block0 = ciphertext[:block_size]
    def get_block(n):
        return ciphertext[n * block_size:(n + 1) * block_size]
    total = sum(edit_distance(block0, get_block(n))
                for n in range(1, block_count))
    return total / ((block_count - 1) * block_size)

def guess_xor_key_size(ciphertext: bytes) -> int:
    BAD = 8.0 # penalty score (all bits distinct)
    dissimilarities = [BAD if block_size == 0 else
                       block_dissimilarity(ciphertext, block_size)
                       for block_size in range(len(ciphertext) // 2)]
    for n in range(2, int(math.sqrt(len(dissimilarities))) + 1):
        for m in range(2 * n, len(dissimilarities), n):
            if dissimilarities[m] >= dissimilarities[n] * 0.8:
                # Prefer n to a multiple of n if the multiple is only slightly
                # better.
                dissimilarities[m] = BAD
    # print(sorted([(n, dissimilarities[n]) for n in range(len(dissimilarities))
    #               if dissimilarities[n] < BAD],
    #              key=lambda x: x[1]))
    return min(range(len(dissimilarities)), key=lambda n: dissimilarities[n])


def character_score(c: int) -> int:
    return (int(32 <= c <= 126 or c == 10 or c == 13) * 1000 + # printable
            int(c == 32) * 20 + # space
            #int(65 <= c <= 90) * 1 + # uppercase letter
            #int(97 <= c <= 122) * 3 + # lowercase letter
            0)

def score_xor_key_1(ciphertext: bytes, key: int) -> int:
    return sum(character_score(c ^ key) for c in ciphertext)

def guess_xor_key_1(ciphertext: bytes) -> int:
    """Guess the key used for single-byte-xor encryption."""
    scores = [(k, score_xor_key_1(ciphertext, k)) for k in range(256)]
    #print(sorted(scores, key=lambda x:-x[1]))
    return max(scores, key=lambda x: x[1])[0]

def guess_xor_key(ciphertext: bytes, block_size: int) -> bytes:
    return bytes(guess_xor_key_1(ciphertext[i::block_size])
                 for i in range(block_size))


class Tests(unittest.TestCase):
    def test_wokka_wokka(self) -> None:
        self.assertEqual(edit_distance(b"this is a test", b"wokka wokka!!!"), 37)

    def test_challenge3(self) -> None:
        ciphertext = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
        key = guess_xor_key(ciphertext, 1)
        plaintext = xor(ciphertext, key * len(ciphertext))
        self.assertEqual(plaintext, b"Cooking MC's like a pound of bacon")

    def test_challenge4(self) -> None:
        with open('4.txt') as input_file:
            ciphertext_candidates = [bytes.fromhex(line) for line in input_file]
        scores = [(ciphertext, k, score_xor_key_1(ciphertext, k))
                  for k in range(256)
                  for ciphertext in ciphertext_candidates]
        # print([(xor(ciphertext, bytes(k) * len(ciphertext)), score)
        #        for ciphertext, k, score in sorted(scores, key=lambda x: x[2])[-10:]])
        ciphertext, k, _score = max(scores, key=lambda x: x[2])
        plaintext = xor(ciphertext, bytes([k]) * len(ciphertext))
        self.assertEqual(plaintext, b"Now that the party is jumping\n")

    def test_challenge6(self) -> None:
        with open('6.txt') as input_file:
            ciphertext = base64.b64decode(input_file.read())
        block_size = guess_xor_key_size(ciphertext)
        self.assertEqual(block_size, 29)
        key = guess_xor_key(ciphertext, block_size)
        #print('Key:', key)
        self.assertEqual(key, b"Terminator X: Bring the noise")
        keystream = key * (len(ciphertext) // block_size + 1)
        plaintext = xor(ciphertext, keystream)
        #print(plaintext.decode('ascii'))
        self.assertTrue(plaintext.startswith(b"I'm back and I'm ringin' the bell"))

if __name__ == '__main__':
    unittest.main()
