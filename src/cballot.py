#!/usr/bin/env python3
import socket

class cBallot: 
    """Class to fetch ballot from Intermediate server"""
    def __init__(self, rhost, rport, pubkey, privkey):
        self.rhost = rhost          # Remote Host to connect to
        self.rport = rport          # Remote Port to connect to
        self.socket = socket.socket()
        self.pubkey = pubkey
        self.privkey = privkey

    def connect(self):
        self.socket.connect((self.rhost, self.rport))
        print(f"[i] Connected to tcp://{self.rhost}:{self.rport}")
    