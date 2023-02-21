#!/usr/bin/env python3
import json
import pickle
import socket
from time import sleep
from utils.utils import *
from utils.consts import *
from utils.hClient import *

INTEGRITY_LIST = list()

class Identity:
    """Class to manange intermediate server"""
    def __init__(self):
        """initilaize identity server"""

        try:
            print("[i] Reading Configuration Options")
            with open('config.json', 'r') as file:
                json_object = json.load(file)
            iserver_config = json_object['i_server']
            self.i_socket = socket.socket()
            self.host = iserver_config['host']
            self.port = iserver_config['port']

            print("[i] Generating Server Keys")
            self.pubkey, self.privkey = gen_keys()
            key_dict = {
                'pub' : {
                    'name': iserver_config['keyfiles']['public'],
                    'val': self.pubkey
                },
                'priv' : {
                    'name' : iserver_config['keyfiles']['private'],
                    'val': self.privkey
                }
            }
            print("[i] Writing keys to Disc")
            write_keys(key_dict)

        except FileNotFoundError:
            eprint("[!] Could not file config.json")
            sys.exit(-1)

        except KeyError:
            eprint("[i] Invalid Config File")
            sys.exit(-2)

    def start(self):
        """Start the socket server"""

        print(f"[i] Starting Voting Server")
        try:
            self.i_socket.bind((self.host, self.port))
            self.i_socket.listen()
            print(f"[i] Listening on - tcp://{self.host}:{self.port}")
        except OSError as e:
            if e.errno == 98:
                eprint("[i] Port already in use!")
                eprint("[i] Retrying in 2s!")
                sleep(2)
                self.start()
            else:
                eprint(f"[!] Error occured as: {e}")
                sys.exit(-3)

    def accept(self):
        """Accept client connections"""
        
        conn, addr = self.i_socket.accept()
        print(f"\n[i] Got connection from {addr[0]}:{addr[1]}")
        return conn

    def get_vid(self, hclient):
        """Get Voter ID from Client"""
        raw_payload = hclient.recv()
        payload = decrypt_a(raw_payload, self.privkey)
        vid_dict = pickle.loads(payload)
        vid = vid_dict['vid']
        print("[i] Voter ID: ", vid)
        if not vid in VOTER_DB.keys():
            eprint(f"[!] Voter ID not in DB!")
            hclient.close()
        
        biometric = VOTER_DB[vid]
        nonce = randnum()
        int_num = randnum()
        INTEGRITY_LIST.append(int_num)
        with open('integrity.pkl', 'wb') as f:
            f.write(pickle.dumps(INTEGRITY_LIST))
        
        auth_dict = {
            'nonce': nonce,
            'int_num': int_num,
            'ballot': BALLOT
        }

        payload = pickle.dumps(auth_dict)
        raw_payload = encrypt(payload, biometric.encode())
        hclient.send(raw_payload)
        del VOTER_DB[vid]
        print("[i] Ballot Sent!")
        

    def __del__(self):
        self.i_socket.close()
        
def main():
    """Main function to launch identity server"""
    i_server = Identity()
    i_server.start()

    # Accept one connection at a time
    while True:
        _conn = i_server.accept()
        conn = HClinet(_conn, i_server)
        i_server.get_vid(conn)
        del conn

    del i_server

if __name__ == '__main__':
    main()