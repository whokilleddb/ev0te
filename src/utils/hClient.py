#!/usr/bin/env python3

class HClinet:
    """Client Handler Object for Clients"""
    def __init__(self, conn, server):
        self.conn = conn
        self.pubkey = server.pubkey
        self.privkey = server.privkey

    def send(self, msg):
        self.conn.send(msg)

    def recv(self, size = 2048):
        return self.conn.recv(size)

    def close(self):
        return self.conn.close()

    def __del__(self):
        self.conn.close()