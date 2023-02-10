#!/usr/bin/python3
import os
import socket
from time import sleep
from utils.utils import *

LHOST = "127.0.0.1"
LPORT = 6969

UUID_TABLE = [{'a': 'A'*8, 'b': 'B'*8 , 'c': 'C'*8}, {'a': 'D'*8, 'b': 'E'*8 , 'c': 'F'*8}]

Server = socket.socket()
CHandler = None             # Client Socket Handle
PRIV, PUB = gen_keys()

def say_hello():
    os.system("clear")
    c = bytes()
    valid = False
    decrypted = bytes()

    print("\n[i] Listening For Client Hello")
    payload = CHandler.recv(2048)
    
    # Client Hello Payload: Nonce + Ai + [Bi]e(Ai+Bi)  
    _ = payload[0:32]
    a = payload[32:40]
    enc = payload[40:]

    for x in UUID_TABLE:
        # Check if Ai matches any
        if x['a'].encode() == a :

            # Get e(Ai + Bi)
            key = x['a'].encode() + x['b'].encode()
            
            # Get Bi from [Bi]e(Ai+Bi)
            decrypted = decrypt(enc, key)

            if decrypted == x['b'].encode():
                valid = True
                c = x['c'].encode()


    if valid:
        print("[i] Client Verified!")
        print("[i] Sending Server Hello!")
        
        # Server Hello Payload: Nonce + [C + Spub]e(Bi)
        nonce = random_bytes()
        payload = nonce + encrypt(c + PUB, decrypted)
        CHandler.send(payload)
        print("[i] Sent Server Hello\n")
    else:
        CHandler.send("[!] Invalid Machine\n")
        print("NOT OK")

    return valid


def main():
    global CHandler
    print("[i] Starting Server")

    print(f"[i] Binding To Interface")
    Server.bind((LHOST, LPORT))

    print(f"[i] Listening For Connections!")
    Server.listen()

    print("[i] Server is ready to accept connections")
    CHandler, addr = Server.accept()

    RHOST = addr[0]
    RPORT = addr[1]

    print(f"[S] {LHOST}:{LPORT} -> [C] {RHOST}:{RPORT}")

    sleep(2)
    if not (say_hello()):
        close_socket(CHandler)
        close_socket(Server)

    close_socket(CHandler)
    close_socket(Server)

if __name__ == '__main__':
    main()