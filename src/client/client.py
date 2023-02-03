#!/usr/bin/env python3
import socket
from modules.bytemodules import *

class Client:
    def __init__(self):
        self.socket = socket.socket()
        self.host = None
        self.port = 0
        
    def connect(self, host="127.0.0.1", port=6969):
        self.host = host
        self.port = port
        self.socket.connect((host, port))
        print(f"[i] Connected to: {host}:{port}")

    def send(self, msg: Bytes):
        self.socket.send(msg.payload)

def main():
    client = Client()
    Client().connect()