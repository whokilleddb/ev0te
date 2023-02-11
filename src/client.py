#!/usr/bin/python3
import os
import socket
import pickle
from time import sleep
from utils.utils import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


# Server address
RHOST = "127.0.0.1"
RPORT = 6969

# Unique UUID
UUID = {
            'a': b'A'*8,
            'b': b'B'*8,
            'c': b'C'*8
        }

# Server Public Key
sPUB = None

# Client Socket
Client = socket.socket()

def __send_client_hello():
    """Send Client Hello"""
    global Client

    nonce  = random_bytes()
    chall  = randnum()

    block = {
            'chall': chall,
            'b': UUID['b']
        }

    plaintext = pickle.dumps(block)
    cipher = encrypt(plaintext, UUID['c'])

    payload = {
            'nonce': nonce,
            'a': UUID['a'],
            'cipher': cipher
            }
    raw_payload = pickle.dumps(payload)
    Client.send(raw_payload)
    return chall


def say_hello():
    """Complete Client-Server Hello"""
    chall = __send_client_hello()

def read_server_key():
    """Read Server Public Key"""
    global sPUB
    print("[i] Reading Server Public Key")
    with open("pubkey.pem", "rb") as key_file:
        sPUB = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

def connect_server():
    """Connect to Server"""
    print("[i] Trying to connect to Server")

    try:
        print(f"[i] Connected to: tcp://{RHOST}:{RPORT}")
        Client.connect((RHOST, RPORT))
    except ConnectionRefusedError:
        eprint("[!] Server Unreachable")
        sleep(5)
        os.system("clear")
        connect_server()


def main():
    """Main function to manage voting clients"""

    connect_server()
    read_server_key()
    say_hello()

    close_socket(Client)

if __name__ == '__main__':
    main()
