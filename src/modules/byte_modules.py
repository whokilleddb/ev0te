#!/usr/bin/env python3
"""
This File contains the Bytes function and associated
functions required to manipulate bytes
"""
from __future__ import annotations


import time
import random
import hashlib
from Crypto.Cipher import AES

class Bytes:
    """Class containing Byte related functions"""

    def __init__(self, payload):
        """Initialize the variables"""
        self.str_payload = None
        self.enc_block = {}
        self.payload = None

        """Create a new instance of the class"""

        if isinstance(payload, str):
            self.str_payload = payload
            self.payload = payload.encode("utf-8")

        elif isinstance(payload, bytes):
            self.payload = payload

        else:
            raise Exception("Incompatible type: must be str or bytes")


    @staticmethod
    def pad(payload:bytes, align: int = 16)->bytes:
        """Pad bytes to given alignment"""

        pad_len = align - (len(payload) % align)
        padded_payload = [align, payload + pad_len*b' ']
        return padded_payload


    def unpad(self)->bytes:
        """Remove padding from bytes"""
        return self.payload.rstrip()

    @staticmethod
    def get_random_bytes(size: int = 32)->bytes:
        """Returns a random bytes of specified length(default: 32)"""

        output = None

        # Seed with current time
        random.seed(time.time())

        # Generate random bytes of specified size
        output = bytes(random.getrandbits(8) for _ in range(size))

        if output[-1] == b' ':
            output = Bytes.get_random_bytes(size)

        return output

    def enc_aes256(self, password: Bytes):
        """Encrypt using AES-256"""

        salt = Bytes.get_random_bytes(AES.block_size)
        private_key = hashlib.scrypt(password.payload, salt=salt, n=2**14, r=8, p=1, dklen=32)

        # create cipher config
        cipher_config = AES.new(private_key, AES.MODE_GCM)

        cipher_text, tag = cipher_config.encrypt_and_digest(self.payload)

        self.enc_block = {
            'cipher': cipher_text,
            'salt': salt,
            'nonce': cipher_config.nonce,
            'tag': tag
        }

        return self.enc_block

    @staticmethod
    def dec_aes256(enc_dict, password: Bytes):
        """Decrypt AES-256"""

        # decode the dictionary entries from base64
        salt = enc_dict['salt']
        cipher_text = enc_dict['cipher']
        nonce = enc_dict['nonce']
        tag = enc_dict['tag']

        # generate the private key from the password and salt
        private_key = hashlib.scrypt(
            password.payload, salt=salt, n=2**14, r=8, p=1, dklen=32)

        # create the cipher config
        cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

        # decrypt the cipher text
        decrypted = cipher.decrypt_and_verify(cipher_text, tag)

        return decrypted
