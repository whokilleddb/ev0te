#!/usr/bin/env python3
import pickle
import socket
from utils.utils import *
from utils.consts import *

# Interface to bind to
IHOST = "127.0.0.1"
IPORT = 6900

class Intermediate:
    """Class to manange intermediate server"""
    def __init__(self, host: str, port: int):
        print("[i] Initializing Intermediate Server")
        self.host = host
        self.port = port
        self.conn = None
        self.socket = socket.socket()
        self.pubkey, self.privkey = gen_keys()
        key_dict = {
                'pub': {
                    'name': PUBKEY_I,
                    'val': self.pubkey,
                    },
                'priv': {
                    'name': PRIVKEY_I,
                    'val': self.privkey,
                    }
                }
        write_keys(key_dict)
        print("[i] Wrote Keys To Disk!")


    def start(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen()
        print(f"[i] Intermediate Server Listening On - {self.host}:{self.port}")
        self.conn, client = self.socket.accept()
        print(f"[i] Connection received from: {client[0]}:{client[1]}")

    def send_ballot(self):
        """Get VID"""
        raw_payload = self.conn.recv(2048)
        dec = decrypt_a(raw_payload, self.privkey)
        payload = pickle.loads(dec)
        vid = payload['vid']
        print('[i] Voter ID Number: ', vid)
        biometric = VOTER_DB[str(vid)]['biometric']
        nonce = randnum()
        int_num = randnum()
        VOTER_DB[str(vid)]['int_num'] = int_num
        
        auth_dict = {
            'nonce': nonce,
            'int_num': int_num,
            'ballot': BALLOT
        }
        payload = pickle.dumps(auth_dict)
        raw_payload = encrypt(payload, biometric.encode())
        self.conn.send(raw_payload)
        


    def close_all(self):
        if self.conn:
            self.conn.close()

        if self.socket:
            self.socket.close()

    def __del__(self):
        self.close_all()

def main():
    i_server = Intermediate(IHOST, IPORT)
    i_server.start()
    i_server.send_ballot()
    i_server.close_all()
#    del i_server 

if __name__ == '__main__':
    main()