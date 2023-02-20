#!/usr/bin/python3
"""
This file constains the class which defines the voting server and it's various functions
"""

import sys
import json
import socket
from time import sleep
from utils.utils import *

class Server:
    """Class to Initiate Voting Server"""

    def __init__(self):
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

    def __del__(self):
        self.s_socket.close()

class HClinet:
    """Client Handler Object for Clients"""
    def __init__(self, conn, server):
        self.conn = conn
        self.pubkey = server.pubkey
        self.privkey = server.privkey

    def __del__(self):
        self.conn.close()

def main():
    """Main function to manage voting server"""    

    print("[i] Initializing Voting Server")
    server = Server()
    server.start()

    # Accept one connection at a time
    while True:
        _conn = server.accept()
        conn = HClinet(_conn, server)
        del conn
        break;
    del server


if __name__ == '__main__':
    main()
