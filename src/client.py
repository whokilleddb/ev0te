#!/usr/bin/python3
import os
import socket
from time import sleep
from utils.utils import *

RHOST = "127.0.0.1"
RPORT = 6969
Client = socket.socket()
UUID = 'A'*8 + '-'+ 'B'*8 + '-' + 'C'*8
SERVER_PUB = bytes()

def say_hello():
    global SERVER_PUB
    os.system("clear")
    # Extract A-B-C components from UUID    
    a = UUID.split("-")[0].encode()
    b = UUID.split("-")[1].encode()
    c = UUID.split("-")[2].encode()
    
    enc = encrypt(b, a + b)
    nonce = random_bytes()

    # Client Hello Payload: Nonce + Ai + [Bi]e(Ai+Bi)  
    payload = nonce + a + enc
    
    print("\n[i] Sending Client Hello")
    Client.send(payload)


    server_hello = Client.recv(2048)
    print("[i] Received Server Reply")
    
    if server_hello == b'NOT OK':
        print("[!] Failed to validate machine\n")

    else:
        # Server Hello Payload: Nonce + [C + Spub]e(Bi)
        _ = server_hello[0:32]
        enc = server_hello[32:]
        dec = decrypt(enc, b)
        if dec[0:8] == c:
            SERVER_PUB = dec[8:]
            print("[i] Validated Server Hello\n")
            return True

    return False    


def main():
    print("[i] Starting Client")

    print(f"[i] Connecting to Server")
    Client.connect((RHOST, RPORT))

    LHOST = Client.getsockname()[0]
    LPORT = Client.getsockname()[1]

    print(f"[C] {LHOST}:{LPORT} -> [S] {RHOST}:{RPORT}")
    
    sleep(2)
    if not (say_hello()):
        close_socket(Client)
    
    close_socket(Client)

if __name__=='__main__':
    main()