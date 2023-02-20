#!/usr/bin/env python3
import socket
import pickle
from utils.utils import *
from utils.consts import *

class cBallot: 
    """Class to fetch ballot from Intermediate server"""

    def __init__(self, rhost, rport, vid, pubkey, privkey):
        self.rhost = rhost          # Remote Host to connect to
        self.rport = rport          # Remote Port to connect to
        self.socket = socket.socket()
        self.pubkey = pubkey
        self.privkey = privkey
        self.i_pubkey = None
        self.vid = vid

        with open(PUBKEY_I, "rb") as key_file:
            self.i_pubkey = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    def connect(self):
        self.socket.connect((self.rhost, self.rport))
        print(f"[i] Connected to tcp://{self.rhost}:{self.rport}")

    def send_vid(self):
        """Send ViD"""
        vid_dict = {
            'nonce': randnum(),
            'vid': self.vid
        }
        payload = pickle.dumps(vid_dict)
        raw_payload = encrypt_a(payload, self.i_pubkey)
        self.socket.send(raw_payload)

    def fetch_enc(self, biometric):
        """Fetch Encrypted Ballot"""
        raw_payload = self.socket.recv(2048)
        dec_payload = decrypt(raw_payload, biometric.encode())
        payload = pickle.loads(dec_payload)
        ret_dict = {
            'int_num': payload['int_num'] + 1,
            'ballot': payload['ballot']
        }
        return ret_dict


    def get_ballot(self):
        """Get Ballot"""
        self.connect()
        self.send_vid()
        ret = self.fetch_enc('aaaaaaaaaaaaaaa')
        self.socket.close()
        return ret

