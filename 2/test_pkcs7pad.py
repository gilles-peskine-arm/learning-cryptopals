#!/usr/bin/env python3
import subprocess
import unittest


def padding(block_size: int, plaintext_length: int) -> bytes:
    if block_size > 256:
        raise ValueError(block_size)
    padding_size = block_size - plaintext_length % block_size
    return bytes([padding_size]) * padding_size

def pad(block_size: int, plaintext: bytes) -> bytes:
    return plaintext + padding(block_size, len(plaintext))


class TestPKCS7Pad(unittest.TestCase):
    def run_test(self, block_size: int, plaintext: bytes) -> None:
        expected = pad(block_size, plaintext)
        actual = subprocess.check_output(['beef', 'pkcs7pad.bf'],
                                         input=bytes([block_size]) + plaintext)
        self.assertEqual(expected, actual)

    def test_1(self) -> None:
        self.run_test(1, b'hello')

    def test_8(self) -> None:
        for i in range(20):
            with self.subTest(i=i):
                self.run_test(8, b'x' * i)

    def test_16_yellowsubmarine(self) -> None:
        self.run_test(16, b'YELLOW SUBMARINE')

    def test_20_yellowsubmarine(self) -> None:
        self.run_test(20, b'YELLOW SUBMARINE')


if __name__ == '__main__':
    unittest.main()
