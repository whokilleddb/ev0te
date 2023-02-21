#!/usr/bin/python3
import os
import sys
import json
import pickle
import socket
import tkinter as tk
from tkinter import *
from time import sleep
from utils.utils import *
from utils.consts import *
from tkinter import simpledialog
from cryptography.hazmat.primitives import serialization

# Unique UUID
UUID = {'a': b'A'*8, 'b': b'B'*8, 'c': b'C'*8 }

class PartySelector:
    def __init__(self, options):
        self.value = tk.StringVar()
        self.options = options
        
        self.frame = tk.Frame()
        self.frame.pack()
        
        for key in self.options:
            button = tk.Radiobutton(self.frame, text=key, variable=self.value, value=key)
            button.pack(anchor="w")
            
        self.button = tk.Button(self.frame, text="Select", command=self.select)
        self.button.pack()
        
    def select(self):
        self.frame.quit()  # Stop the mainloop
        self.frame.destroy()  # Destroy the frame
        # Return the selected value
        return self.value.get()
        
def select_party(options):
    root = tk.Tk()
    selector = PartySelector(options)
    root.mainloop()
    # When the mainloop is finished, return the selected value
    return selector.select()

class cBallot:
    """Class to fetch ballot from Intermediate server"""
    def __init__(self, vid, biometric, pubkey, privkey):
        self.vid = vid
        self.i_pub = None
        self.pubkey = pubkey
        self.privkey = privkey
        self.biometric = biometric

        try:
            print("[i] Reading Configuration Options")
            with open('config.json', 'r') as file:
                json_object = json.load(file)
            iserver_config = json_object['i_server']
            self.cb_socket = socket.socket()
            self.rhost = iserver_config['host']
            self.rport = iserver_config['port']

            if not self.i_pub:
                print("[i] Reading Identity Server's Public Key")
            try:
                with open(iserver_config['keyfiles']['public'], "rb") as key_file:
                    self.i_pub = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
            except Exception as e:
                eprint(f"[!] Exception occured as: {e}")
                sys.exit(-1)

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
        """Connect to server"""
        try: 
            self.cb_socket.connect((self.rhost, self.rport))
            print(f"[i] Connected to tcp://{self.rhost}:{self.rport}")
        except ConnectionRefusedError:
            eprint("[!] Server Unreachable!")
            eprint(f"[!] Retrying after 2s!")
            sleep(2)
            self.connect()

    def req_ballot(self):
        """Send Vid"""
        vid_dict = {
            'nonce': random_bytes(),
            'vid': self.vid
        }

        payload = pickle.dumps(vid_dict)
        raw_payload = encrypt_a(payload, self.i_pub)
        self.cb_socket.send(raw_payload)
        print("[i] Requested Ballot")

        raw_payload = self.cb_socket.recv(2048)
        payload = decrypt(raw_payload, self.biometric.encode())

        auth_dict = pickle.loads(payload)
        
        int_auth = auth_dict['int_num'] + 1
        ballot = auth_dict['ballot']
        ballot_dict = {
            'int_auth': int_auth,
            'ballot': ballot
        }
        return ballot_dict

    def __del__(self):
        self.cb_socket.close()

class Client:
    """Voting Client"""
    def __init__(self, uuid):

        self.sid = None
        self.uuid = uuid
        self.tsession = None
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

    def say_hello(self):
        """Manage Client/Server hello"""
        nonce = random_bytes()
        chall = randnum()
        print("[i] Challenge Token Issued there:", chall)
        block = {
            'nonce': nonce,
            'chall': chall,
            'b': self.uuid['b']
        }

        raw_block = pickle.dumps(block)
        cipher = encrypt(raw_block, self.uuid['c'])
        payload = {
            'a': self.uuid['a'],
            'cipher': cipher
        }

        raw_payload = pickle.dumps(payload)

        self.c_socket.send(raw_payload)
        print("[i] Sent Client Hello")

        raw_payload = self.c_socket.recv(2048)
        
        print("[i] Received Server Hello")
        payload = pickle.loads(raw_payload)
        cipher = payload['cipher']
        raw_block = decrypt(cipher, self.uuid['b'])
        block = pickle.loads(raw_block)
        
        if self.uuid['c'] == block['c']:
            signature = block['signature']
            result = verify_sign(self.s_pub, str(chall+1).encode(), signature)
            if result:
                return True
        else:
            self.c_socket.close()
        return False

    def get_ballot(self, vid, biometric):
        """Get Ballot from identity server"""
        
        print("[i] Voter ID: ", vid)
        c_ballot = cBallot(vid, biometric, self.pubkey, self.privkey)
        c_ballot.connect()
        ballot = c_ballot.req_ballot()
        del c_ballot

        return ballot

    def cast_vote(self, ballot):
        ballot['nonce'] = randnum()
        payload = encrypt_a(pickle.dumps(ballot), self.s_pub)
        self.c_socket.send(payload)
        print("[i] Vote Cast!")

def get_user_vote(ballot):
    """Get Vote"""

    choice = select_party(ballot)
    ballot[choice] = 1
    return ballot


def main():
    """Main function to run client functions"""
    while True:
        print("[i] Initializing Voter Client")
        client = Client(UUID)
        client.connect()
        
        if client.say_hello():
            print("[i] Server verified!")
        else:
            eprint("[!] Invalid Server Signature")
            sys.exit(-1)

        # get VID input
        ROOT = tk.Tk()
        #ROOT.withdraw()

        # the input dialog
        vid = None
        biometric = None
        while True:
            vid = simpledialog.askstring(title="Voter ID", prompt="Enter voter id:")
            if vid:
                break

        while True:        
            biometric = simpledialog.askstring(title="Biometric", prompt="Enter biometric signature:")
            if biometric:
                break

        ballot_dict = client.get_ballot(vid, biometric)
        ballot = ballot_dict['ballot']

        # Get User Vote
        ballot_dict['ballot'] = get_user_vote(ballot)

        # Cast vote
        client.cast_vote(ballot_dict)

        client.c_socket.close()

if __name__ == '__main__':
    main()
