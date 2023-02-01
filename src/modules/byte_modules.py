#!/usr/bin/env python3

"""
This file contains the Bytes class which serves
as a wrapper for byte manipulation functions
"""
import os
import sys
import time
import random

# print if environment is dev
_print = lambda msg: print(msg) if (os.getenv("ENV") == "dev") or (os.getenv("ENV") == "development") else None
_eprint = lambda msg: print(msg, file=sys.stderr) if (os.getenv("ENV") == "dev") or (os.getenv("ENV") == "development") else None

class Bytes:
    """Byte manipulation object"""

    def __init__(self):
        self.str_payload = None
        self.byte_payload = None
        self.payload = None
        self.pad_bytes = None
        self.unpad_bytes = None

    def new(self, payload):
        """Store payload accordingly"""
        _print(f"[i] Raw Payload:\t{payload}")
        _print(f"[i] Payload Type:\t{type(payload)}")

        if isinstance(payload, str):
            self.str_payload = payload
            self.payload = self.byte_payload = payload.encode('utf-8')

        elif isinstance(payload, bytes):
            self.payload = self.byte_payload = payload

        else:
            raise Exception("Invalid Data Type: must be bytes or str")

        _print(f"[i] String Payload:\t{self.str_payload}")
        _print(f"[i] Byte Payload:\t{self.byte_payload}")


    def get_random_bytes(self, size: int = 32)->bytes:
        """This function returns a random bytes of specified length(default: 32)"""

        output = None
        _print(f"[i] Fetching {size} random bytes")

        # Seed with current time
        random.seed(time.time())

        # Generate random bytes of specified size
        output = bytes(random.getrandbits(8) for _ in range(size))

        if output[-1] == b' ':
            output = self.get_random_bytes(size)

        return output

    def pad(self, align: int)->bytes:
        """Pad bytes to given alignment"""
        pad_len = align - (len(self.payload) % align)
        self.pad_bytes = self.payload + pad_len*b' '
        return self.pad_bytes

    def unpad(self)->bytes:
        """Remove padding from bytes"""
        self.unpad_bytes = self.payload.rstrip()
        return self.unpad_bytes
