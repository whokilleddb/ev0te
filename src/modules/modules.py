#!/usr/bin/env python3
from byte_modules import *
from Crypto.Cipher import AES


class AESEncryptor(Bytes):
    def __init__(self, password: bytes):
        self.key = Bytes().new() 

    def genkey(self):
        # generate a random salt
        salt = get_random_bytes()
        print()
