#!/usr/bin/env python3
import socket

class Server:
    def __init__(self, host="127.0.0.1", port=6969):
        self.socket = socket.socket()
        self.host = host
        self.port = port
        self.conn = None
        self.addr = None

    def start(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen()
        print(f"[i] Listening For Connections over: {self.host}:{self.port}")
        self.conn, self.addr = self.socket.accept()

    def recv(self):
        with self.conn:
            print(f"[+] Connected by: {self.conn}")
            print(self.socket.recv(2048))


    def __del__(self):
        print("[i] Closing Socket")
        self.socket.close()    

def main():
    server = Server()
    server.start()
    server.recv()

if __name__ == '__main__':
    main()