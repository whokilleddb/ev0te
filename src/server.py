#!/usr/bin/python3
"""
This file constains the class which defines the voting server and it's various functions
"""

import sys
import json
import pickle
import socket
from tabulate import tabulate
from time import sleep
from utils.utils import *
from utils.consts import *
from utils.hClient import *

def show_votes(my_dict):
    table = tabulate(my_dict.items(), headers=["Party", "Vote"], tablefmt="simple_grid")
    print(table)
    
class Server:
    """Class to Initiate Voting Server"""

    def __init__(self):
        self.hclient = None
        """Initialize Server"""
        try:
            print("[i] Reading Configuration Options")
            with open('config.json', 'r') as file:
                json_object = json.load(file)
            server_config = json_object['v_server']
            self.s_socket = socket.socket()
            self.host = server_config['host']
            self.port = server_config['port']

            print("[i] Generating Server Keys")
            self.pubkey, self.privkey = gen_keys()
            key_dict = {
                'pub' : {
                    'name': server_config['keyfiles']['public'],
                    'val': self.pubkey
                },
                'priv' : {
                    'name' : server_config['keyfiles']['private'],
                    'val': self.privkey
                }
            }
            print("[i] Writing keys to Disc")
            write_keys(key_dict)

            # Write ballot object to file
            raw_block = pickle.dumps(BALLOT)
            with open("vote.pkl", 'wb') as f:
                f.write(raw_block)

        except FileNotFoundError:
            eprint("[!] Could not file config.json")
            sys.exit(-1)

        except KeyError:
            eprint("[i] Invalid Config File")
            sys.exit(-2)

    def start(self):
        """Start the socket server"""
        try:
            self.s_socket.bind((self.host, self.port))
            self.s_socket.listen()
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
        conn, addr = self.s_socket.accept()
        print(f"[i] Got connection from {addr[0]}:{addr[1]}")
        return conn

    def register_handler(self, hclient):
        """Register Handler"""
        self.hclient = hclient

    def say_hello(self):
        """Manage Client/Server hello"""
        raw_payload = self.hclient.recv(2048)
        print("[i] Received Client Hello")

        payload = pickle.loads(raw_payload)
        a = payload['a']
        cipher = payload['cipher']

        c_uuid = None
        for uuid in UUID_DB:
            if uuid['a'] == a:
                c_uuid = uuid

        if c_uuid is None :
            eprint("[i] Failed to find valid UUID")
            self.hclient.close()
            return False

        decypher = decrypt(cipher, c_uuid['c'])
        block = pickle.loads(decypher)

        resp = block['chall'] + 1
        print("[i] Response Token: ", resp)
        if block['b'] != c_uuid['b'] :
            eprint("[i] Failed to verify UUID")
            self.hclient.close()
            return False

        nonce = random_bytes()
        raw_resp = str(resp).encode()
        signature = sign(raw_resp, self.privkey)
        block = {
            "nonce": nonce,
            "c": c_uuid['c'],
            "signature": signature
        }

        raw_block = pickle.dumps(block)
        
        cipher = encrypt(raw_block, c_uuid['b'])
        
        payload = {
            'cipher': cipher
        }

        raw_payload = pickle.dumps(payload)
        self.hclient.send(raw_payload)
        print("[i] Sent Server Hello")
        return True

    def  get_vote(self):
        """Get Ballot"""
        total_count = None
        
        raw_payload = self.hclient.recv(2048)
        dec_payload = decrypt_a(raw_payload, self.privkey)
        payload = pickle.loads(dec_payload)
        
        INTEGRITY_LIST = None
        with open('integrity.pkl', 'rb') as f:
            INTEGRITY_LIST = pickle.loads(f.read())
        
        auth_num = INTEGRITY_LIST.pop() + 1
        
        if auth_num == payload['int_auth']:
            print("[i] Integrity Verified")
            with open('vote.pkl', 'rb') as f:
                total_count = pickle.loads(f.read())

            ballot = payload['ballot']
            for x in ballot.keys():
                if ballot[x] == 1:
                    total_count[x] = total_count[x] + 1
                    with open('vote.pkl', 'wb') as f:
                        f.write(pickle.dumps(total_count))
                    show_votes(total_count)

    def __del__(self):
        self.s_socket.close()

def main():
    """Main function to manage voting server"""    

    print("[i] Initializing Voting Server")
    server = Server()
    print(f"[i] Starting Voting Server")
    server.start()

    # Accept one connection at a time
    while True:
        print("\n[i] Waiting for connections")
        _conn = server.accept()
        conn = HClinet(_conn, server)
        server.register_handler(conn)
        if not server.say_hello():
            print("[i] Server/Client Hello Failed")

        server.get_vote()
        del conn

    del server

if __name__ == '__main__':
    main()
