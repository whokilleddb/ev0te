#!/usr/bin/python3
import os
import sys
import pickle
import socket
from time import sleep
from utils.utils import *
from utils.consts import *
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

# Client Keys
PUBKEY = None
PRIVKEY = None

# Session Token
SID = None
TSES = None
DELTA = None

# Client Socket
Client = socket.socket()


def init_keys():
    """Generate client keypair & save them"""
    global PUBKEY, PRIVKEY

    print("[i] Generating Key Pair")

    PUBKEY, PRIVKEY = gen_keys()
    key_dict = {
        'pub' : {
            'name': PUBKEY_C,
            'val': PUBKEY
        },
        'priv' : {
            'name' : PRIVKEY_C,
            'val': PRIVKEY
        }

    }
    write_keys(key_dict);
    print("[i] Saved Key Files")


def __handle_client_hello():
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

def __handle_server_hello(chall):
    """Handle Server Hello"""
    raw_payload = Client.recv(2048)
    payload = pickle.loads(raw_payload)
    dec = decrypt(payload['cipher'], UUID['b'])
    block = pickle.loads(dec)
    if block['c'] == UUID['c']:
        sign = block['signature']
        result = verify_sign(sPUB, str(chall+1).encode(), sign)
        if result:
            return True
    return False

def say_hello():
    """Complete Client-Server Hello"""
    chall = __handle_client_hello()
    print("[i] Sent Client Hello")
    if __handle_server_hello(chall):
        print("[i] Server Verified")
    else:
        eprint("[!] Could not verify server!")
        Client.close()
        sys.exit(-1)

def read_server_key():
    """Read Server Public Key"""
    global sPUB
    print("[i] Reading Server Public Key")
    with open(PUBKEY_S, "rb") as key_file:
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
        #os.system("clear")
        connect_server()

def generate_tsession():
    """Generate Tsession"""
    global TSES, SID
    TSES = randnum()
    SID = hashlib.sha256(str(TSES).encode()).digest()
    print(f"[i] Session Token: {TSES}")   

def send_tsession():
    """Send Tesseion"""

    nonce = random_bytes()
    payload = {
        'nonce': nonce,
        'TSESSION': TSES
    }

    pickle_payload = pickle.dumps(payload)
    
    enc = sPUB.encrypt(
        pickle_payload,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    Client.send(enc)

def sendd(msg):
    """Update Delta"""
    global TSES, SID, DELTA, Client

    DELTA = randnum()
    payload = {
        'delta': DELTA,
        'payload': msg
    }
    raw_payload = pickle.dumps(payload)
    message = encrypt(raw_payload, SID)
    TSES = TSES + DELTA
    SID = hashlib.sha256(str(TSES).encode()).digest()
    Client.send(message)

def recvv(size = 2048):
    """Recv data"""

    global Client, SID, DELTA, TSES
    raw = Client.recv(size)
    raw_payload = decrypt(raw, SID)
    payload = pickle.loads(raw_payload)
    DELTA = payload['delta']
    TSES = TSES + DELTA
    SID = hashlib.sha256(str(TSES).encode()).digest()
    return payload['payload']

def main():
    """Main function to manage voting clients"""

    init_keys()
    connect_server()
    read_server_key()
    say_hello()
    generate_tsession()
    send_tsession()
    close_socket(Client)

if __name__ == '__main__':
    main()
