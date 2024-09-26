#!/usr/bin/env python3

"""Cryptopals set 2 challenge 13.

https://cryptopals.com/sets/2/challenges/13
"""

import dataclasses
import enum
import os
import re
from typing import Callable, Dict, Tuple
import unittest

from cryptography.hazmat.primitives import ciphers


################################################################
#### Support functions ####
################################################################

class Role(enum.Enum):
    USER = 1
    ADMIN = 2

@dataclasses.dataclass
class Profile:
    email: str
    uid: int
    role: Role

def encode_profile(profile: Profile) -> str:
    """Encode the given profile as a key=value string.

    To make the challenge simpler, user IDs are padded to 20 digits.
    """
    role_name = 'admin' if profile.role == Role.ADMIN else 'user'
    return f'email={profile.email}&uid={profile.uid:020}&role={role_name}'

def make_user_profile(email: str) -> Profile:
    """Return a user profile for the given email with a deterministic UID."""
    return Profile(email, hash(email) & 0xffffffffffffffff, Role.USER)

def profile_for(email: str) -> str:
    """Return the profile for the given email address as a key-value string.

    User IDs are unpredictable, but statistically distinct for different
    email addresses, and consistent within one run of the program.
    """
    if '&' in email or '=' in email:
        raise ValueError('Invalid character in email: ' + email)
    profile = make_user_profile(email)
    return encode_profile(profile)


################################################################
#### The oracle and a verifier ####
################################################################

_TRACE = False
#_TRACE = True
BLOCK_SIZE = 16
_KEY = os.urandom(16)

def ecb_encrypt(plaintext: str) -> bytes:
    """ECB encryption of plaintext, padded with '&'."""
    if _TRACE:
        print(f'DEBUG: encrypting "{plaintext}"')
    plaintext_bytes = plaintext.encode('utf-8')
    cipher = ciphers.Cipher(ciphers.algorithms.AES(_KEY), ciphers.modes.ECB())
    enc = cipher.encryptor()
    ciphertext = enc.update(plaintext_bytes)
    padding_length = BLOCK_SIZE - len(plaintext_bytes) % BLOCK_SIZE
    ciphertext += enc.update(b'&' * padding_length)
    ciphertext += enc.finalize()
    return ciphertext

def encrypted_profile(email: str) -> bytes:
    """Return the encrypted profile for the given email with the user role.

    This is function A.
    """
    return ecb_encrypt(profile_for(email))

Oracle = Callable[[str], bytes]

def ecb_decrypt(ciphertext: bytes) -> str:
    """ECB decryption of ciphertext, removing trailing '&'."""
    cipher = ciphers.Cipher(ciphers.algorithms.AES(_KEY), ciphers.modes.ECB())
    enc = cipher.decryptor()
    plaintext_bytes = enc.update(ciphertext)
    plaintext_bytes += enc.finalize()
    padded_plaintext = plaintext_bytes.decode('utf-8')
    if _TRACE:
        print(f'DEBUG: decrypted  "{padded_plaintext}"')
    return padded_plaintext.rstrip('&')

def decode_encrypted_profile(token: bytes) -> Profile:
    """Return information about the profile encoded in the given token.

    The solution to the challenge may not use this function.
    It is provided to validate a solution.
    """
    plaintext = ecb_decrypt(token)
    values = {}
    for assignment in plaintext.split('&'):
        m = re.match(r'\A([^=]+)=([^=]*)\Z', assignment)
        if not m:
            raise Exception('Invalid token syntax: ' + plaintext)
        if m.group(1) in values:
            raise Exception('Duplicated key in token: ' + plaintext)
        values[m.group(1)] = m.group(2)
    return Profile(values['email'],
                   int(values['uid']),
                   Role.ADMIN if values['role'] == 'admin' else Role.USER)

def is_admin_profile(email: str, token: bytes) -> bool:
    """Whether the given token is an admin profile for the given email."""
    profile = decode_encrypted_profile(token)
    return profile.email == email and profile.role == Role.ADMIN


################################################################
#### The challenge solution ####
################################################################

def forge_admin_profile(oracle: Oracle) -> Tuple[str, bytes]:
    """Using the provided oracle that makes user-role tokens, forge an admin token.

    Return the corresponding email and the forged token.
    """
    # email=AAAAAAAAAA&uid=NNNNNNNNNNNNNNNNNNNN&role=user&&&&&&&&&&&&&
    # 0000000000000000111111111111111122222222222222223333333333333333
    ct_email_equal_letters = oracle('AAAAAAAAAA')[0:16]
    # email=AAAAAAAAAAA&uid=NNNNNNNNNNNNNNNNNNNN&role=user&&&&&&&&&&&&
    # 0000000000000000111111111111111122222222222222223333333333333333
    ct_digits_and_role_equal = oracle('AAAAAAAAAAA')[32:48]
    uid_of_digits_and_role_equal = hash('AAAAAAAAAAA') & 0xffffffffffffffff
    # email=AAAAAAAAAAadmin&uid=NNNNNNNNNNNNNNNNNNNN&role=user&&&&&&&&
    # 0000000000000000111111111111111122222222222222223333333333333333
    ct_admin_and_uid_equal_digits = oracle('AAAAAAAAAAadmin')[16:32]
    # email=AAAA&uid=NNNNNNNNNNNNNNNNNNNN&role=user&&&
    # 000000000000000011111111111111112222222222222222
    ct_digits_and = oracle('AAAA')[16:32]

    # email=AAAAAAAAAANNNNNNNNNN&role=admin&uid=NNNNNNNNNNNNNNNNNNNNN&
    # 0000000000000000111111111111111122222222222222223333333333333333
    token = ct_email_equal_letters + ct_digits_and_role_equal + ct_admin_and_uid_equal_digits + ct_digits_and
    email = 'AAAAAAAAAA' + str(uid_of_digits_and_role_equal)[-10:]
    if _TRACE:
        print(email)
    return (email, token)

################################################################
#### Tests ####
################################################################

class Tests(unittest.TestCase):
    def test_encode_decode_user(self) -> None:
        profile = make_user_profile('bob')
        token = encrypted_profile('bob')
        self.assertEqual(profile, decode_encrypted_profile(token))

    def test_encode_decode_admin(self) -> None:
        profile = Profile('alice', 0, Role.ADMIN)
        token = ecb_encrypt(encode_profile(profile))
        self.assertTrue(is_admin_profile('alice', token))

    def test_challenge_2_13(self) -> None:
        email, token = forge_admin_profile(encrypted_profile)
        self.assertTrue(is_admin_profile(email, token))

if __name__ == '__main__':
    unittest.main()
