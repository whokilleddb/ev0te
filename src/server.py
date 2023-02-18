#!/usr/bin/python3
import os
import sys
import pickle
import socket
from time import sleep
from utils.utils import *
from utils.consts import *

# interface to start server on
LHOST = "127.0.0.1"
LPORT = 6969

# Sockets to handle connection
HCLIENT = None
Server = None

# Keys
PUBKEY = None
PRIVKEY = None

# Session ID
TSES = None
SID = None
DELTA = None

# Valid UUIDs
VALID_UUID = [{
    'a': b'A'*8,
    'b': b'B'*8,
    'c': b'C'*8
    }]

def __closeall():
    global Server, HCLIENT
    print("[i] Closing All Sockets")    
    HCLIENT.close()
    Server.close()
    
def init_keys():
    """Generate server keypair & save them"""
    global PUBKEY, PRIVKEY

    print("[i] Generating Key Pair")

    PUBKEY, PRIVKEY = gen_keys()
    key_dict = {
        'pub' : {
            'name': PUBKEY_S,
            'val': PUBKEY
        },
        'priv' : {
            'name' : PRIVKEY_S,
            'val': PRIVKEY
        }

    }
    write_keys(key_dict);

    print("[i] Saved Key Files")

def init_socket():
    """Start Server Socket"""
    global Server

    print("[i] Intializing Server")
    Server = socket.socket()
    Server.bind((LHOST, LPORT))
    Server.listen()
    print("[i] Listening")

def accept_conn():
    """Receive Connection from client"""
    global Server
    global HCLIENT

    # Accept connection
    HCLIENT, addr = Server.accept()

    print(f"[i] Connection Received from: tcp://{addr[0]}:{addr[1]}")

def __handle_client_hello():
    """Handle and verify Client Hello"""
    global HCLIENT

    raw_payload = HCLIENT.recv(2048)
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
    signature = sign(raw_resp, PRIVKEY)
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
    HCLIENT.send(raw_payload)

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

def get_tsession():
    """Fetch Session ID"""

    global PUBKEY, TSES, SID
    raw_payload = HCLIENT.recv(2048)
    pickle_payload = PRIVKEY.decrypt(
        raw_payload,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    payload = pickle.loads(pickle_payload)
    TSES = payload['TSESSION']
    SID = hashlib.sha256(str(TSES).encode()).digest()
    print(f"[i] Session Token: {TSES}")

def sendd(msg):
    """Update Delta"""
    global TSES, SID, DELTA, HCLIENT

    DELTA = randnum()
    payload = {
        'delta': DELTA,
        'payload': msg
    }
    raw_payload = pickle.dumps(payload)
    message = encrypt(raw_payload, SID)
    TSES = TSES + DELTA
    SID = hashlib.sha256(str(TSES).encode()).digest()
    print(TSES)
    print(SID)
    print(DELTA)
    
    HCLIENT.send(message)

def recvv(size= 2048):
    """Recv data"""

    global HCLIENT, SID, DELTA, TSES
    raw = HCLIENT.recv(size)
    raw_payload = decrypt(raw, SID)
    payload = pickle.loads(raw_payload)
    DELTA = payload['delta']
    TSES = TSES + DELTA
    SID = hashlib.sha256(str(TSES).encode()).digest()
    return payload['payload']

def main():
    """Main function to manage voting server"""
    
    print("[i] Initializing Voting Server")

    init_keys()
    init_socket()
    accept_conn()
    say_hello()
    get_tsession()
    __closeall()

if __name__ == '__main__':
    main()
