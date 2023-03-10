#!/usr/bin/env python3
import os
import sys
import time
import pyaes
import string
import random
import hashlib
from base64 import b64encode
from Crypto.Hash import SHA256
from cryptography.fernet import Fernet
from stat import S_IREAD, S_IRGRP, S_IROTH
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def close_socket(s):
    """Close socket"""
    print("[i] Closing Socket")
    s.close()

def eprint(msg):
    """Print to stderr"""
    print(msg, file=sys.stderr)

def randnum():
    """Return Random Number"""
    random.seed(time.time())
    return random.randint(0, 999999999999)

def pad(payload:bytes, align: int = 16):
        """Pad bytes to given alignment"""

        pad_len = align - (len(payload) % align)
        padded_payload = payload + pad_len*b' '
        return padded_payload

def unpad(payload):
    """Remove padding from bytes"""
    return payload.rstrip()

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
    #print("[i] Orig Hex:\t", hashlib.sha256(plaintext).hexdigest())
    key = hashlib.sha256(password).digest()
    cipher = Cipher(algorithms.AES(key), modes.CBC(bytes(16)), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(pad(plaintext)) + encryptor.finalize()
    #print("[i] Enc Hex:\t", hashlib.sha256(ciphertext).hexdigest())
    return ciphertext

def decrypt(ciphertext: bytes, password: bytes):
    #print("[i] Enc Hex:\t", hashlib.sha256(ciphertext).hexdigest())
    key = hashlib.sha256(password).digest()
    cipher = Cipher(algorithms.AES(key), modes.CBC(bytes(16)), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    #print("[i] Decrypt Hex:\t", hashlib.sha256(plaintext).hexdigest())
    return unpad(plaintext)

def gen_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    return[public_key, private_key]

def sign(message, privkey):
    """Sign a message with a private key"""
    encrypted = privkey.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return encrypted

def verify_sign(pubkey, message, signature):
    """verify a signature with public key"""
    # Verify the signature with the public key
    try:
        pubkey.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False

def write_keys(key_dict):
    pub = key_dict['pub']
    priv = key_dict['priv']

    # Delete any pre-existing keys
    if os.path.exists(pub['name']):
        os.remove(pub['name'])

    if os.path.exists(priv['name']):
        os.remove(priv['name'])

    # Save public key
    with open(pub['name'], "wb") as f:
        raw_pub_key = pub['val'].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        f.write(raw_pub_key)

    # Save private key
    with open(priv['name'], "wb") as f:
        raw_priv_key = priv['val'].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        f.write(raw_priv_key)

    os.chmod(priv['name'], S_IREAD|S_IRGRP|S_IROTH)
    
def encrypt_a(msg: bytes, pubkey):
    encrypted = pubkey.encrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted

def decrypt_a(enc: bytes, privkey):
    original_message = privkey.decrypt(
        enc,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return original_message