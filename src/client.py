#!/usr/bin/python3
import os
import sys
import json
import socket
from time import sleep
from utils.utils import *
from utils.consts import *
from cryptography.hazmat.primitives import serialization

# Unique UUID
UUID = {'a': b'A'*8, 'b': b'B'*8, 'c': b'C'*8 }

class Client:
    """Voting Client"""
    def __init__(self):
        try:
            print("[i] Reading Configuration Options")
            with open('config.json', 'r') as file:
                json_object = json.load(file)
            self.server_config = json_object['v_server']
            client_config = json_object['v_client']
            self.c_socket = socket.socket()
            self.rhost = self.server_config['host']
            self.rport = self.server_config['port']
            self.s_pub = None
            print("[i] Generating Server Keys")
            self.pubkey, self.privkey = gen_keys()
            key_dict = {
                'pub' : {
                    'name': client_config['keyfiles']['public'],
                    'val': self.pubkey
                },
                'priv' : {
                    'name' : client_config['keyfiles']['private'],
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
            sys.exit(-1)

        except Exception as e:
            eprint(f"[!] Error occured as: {e}")
            sys.exit(-1)

    def connect(self):
        print(f"[i] Trying to connect to Voting Server")
        try: 
            self.c_socket.connect((self.rhost, self.rport))
            print(f"[i] Connected to tcp://{self.rhost}:{self.rport}")
        except ConnectionRefusedError:
            eprint("[!] Server Unreachable!")
            eprint(f"[!] Retrying after 2s!")
            sleep(2)
            self.connect()

        except Exception as e:
            eprint(f"[!] Error Occured as: {e}")
            sys.exit(-1)

        if not self.s_pub:
            print("[i] Reading the Server's Public Key")
            try:
                with open(self.server_config['keyfiles']['public'], "rb") as key_file:
                    self.s_pub = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
            except Exception as e:
                eprint(f"[!] Exception occured as: {e}")
                sys.exit(-1)

def main():
    """Main function to run client functions"""
    print("[i] Initializing Voter Client")
    client = Client()
    client.connect()
    client.c_socket.close()
if __name__ == '__main__':
    main()