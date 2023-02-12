#!/usr/bin/python3
import os
import sys
import pickle
import socket
from time import sleep
from utils.utils import *
from stat import S_IREAD, S_IRGRP, S_IROTH
from cryptography.hazmat.primitives import serialization

# interface to start server on
LHOST = "127.0.0.1"
LPORT = 6969

# Sockets to handle connection
hClient = None
Server = None

# Keys
kPub = None
kPriv = None

# Valid UUIDs
VALID_UUID = [{
    'a': b'A'*8,
    'b': b'B'*8,
    'c': b'C'*8
    }]

def __closeall():
    global Server, hClient
    hClient.close()
    Server.close()

def init_keys():
    """Generate server keypair & save them"""
    global kPub, kPriv

    print("\n[i] Generating Key Pair")

    kPub, kPriv = gen_keys()

    # Delete any pre-existing keys
    if os.path.exists("pubkey.pem"):
        os.remove("pubkey.pem")

    if os.path.exists("privkey.pem"):
        os.remove("privkey.pem")

    # Save public key
    with open("pubkey.pem", "wb") as f:
        raw_pub_key = kPub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        f.write(raw_pub_key)

    # Save private key
    with open("privkey.pem", "wb") as f:
        raw_priv_key = kPriv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        f.write(raw_priv_key)

    os.chmod("privkey.pem", S_IREAD|S_IRGRP|S_IROTH)
    print("[i] Saved Key Files\n")

def init_socket():
    """Start Server Socket"""
    global Server

    print("[i] Intializing Server")
    Server = socket.socket()
    Server.bind((LHOST, LPORT))
    Server.listen()
    print("[i] Listening\n")

def accept_conn():
    """Receive Connection from client"""
    global Server
    global hClient

    # Accept connection
    hClient, addr = Server.accept()

    print(f"[i] Connection Received from: tcp://{addr[0]}:{addr[1]}")

def __handle_client_hello():
    """Handle and verify Client Hello"""
    global hClient

    raw_payload = hClient.recv(2048)
    payload = pickle.loads(raw_payload)

    for uuid in VALID_UUID:
        if uuid['a'] == payload['a']:
            enc = payload['cipher']
            dec = decrypt(enc, uuid['c'])
            block = pickle.loads(dec)
            if block['b'] == uuid['b']:
                resp = block['chall'] + 1
                return [uuid, resp]
    return None, None

def __handle_server_hello(uuid, resp):
    """Send Server Hello"""
    nonce = random_bytes()
    raw_resp = str(resp).encode()
    signature = sign(raw_resp, kPriv)
    block = {
            "c": uuid['c'],
            "signature": signature
            }
    raw_block = pickle.dumps(block)
    cipher = encrypt(raw_block, uuid['b'])
    payload = {
            'nonce': nonce,
            'cipher': cipher
            }
    raw_payload = pickle.dumps(payload)
    hClient.send(raw_payload)

def say_hello():
    """Complete Client-Server Hello"""
    uuid, resp = __handle_client_hello()
    if not resp:
        eprint("[!] Invalid Client")
        __closeall()
        sys.exit(-1)
    print("[i] Received Client Hello")

    __handle_server_hello(uuid, resp)
    print("[i] Sent Server Hello")

def main():
    """Main function to manage voting server"""

    print("[i] Initializing Voting Server")

    init_keys()
    init_socket()
    accept_conn()
    say_hello()

    __closeall()

if __name__ == '__main__':
    main()
