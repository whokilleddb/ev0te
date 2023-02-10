#!/usr/bin/env python3
import time
import pyaes
import string
import random
import hashlib
from base64 import b64encode
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend


def close_socket(s):
    """Close socket"""
    print("[i] Closing Socket")
    s.close()



def random_bytes(size: int = 32, readable: bool = False):
    """Return random bytes"""
    output = None

    # Seed with current time
    random.seed(time.time())

    if readable:
        output = ''.join(random.choices(string.printable, k=size))
        output = output.encode()
    else:
        output = bytes(random.getrandbits(8) for _ in range(size))
        if output[-1] == b' ':
            output = random_bytes(size)

    return output


def encrypt(plaintext: bytes, password: bytes):
    # Salt for encryption
    salt = bytes()

    # Create 32 bytes key
    key = hashlib.pbkdf2_hmac('sha256', password, salt, 1000)

    # Encryption with AES-256-CBC
    encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key))
    ciphertext = encrypter.feed(plaintext)
    ciphertext += encrypter.feed()
    return ciphertext


def decrypt(ciphertext: bytes, password: bytes):
    salt = bytes()
    key = hashlib.pbkdf2_hmac('sha256', password, salt, 1000)
    decrypter = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(key))
    decryptedData = decrypter.feed(ciphertext)
    decryptedData += decrypter.feed()
    return decryptedData

def gen_keys():
    key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=65537,
        key_size=2048
    )

    private_key = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption()
    )

    public_key = key.public_key().public_bytes(
        crypto_serialization.Encoding.OpenSSH,
        crypto_serialization.PublicFormat.OpenSSH
    )

    return[private_key, public_key]