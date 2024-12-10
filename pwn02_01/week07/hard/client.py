import socket
import hmac
import argparse
import random
import asyncio
import logging
from asyncio import StreamReader, StreamWriter
from cmath import pi
from enum import Enum

from Crypto.Protocol.KDF import HKDF

from insecurelib import *

# Fill in the right target here
HOST = 'netsec.net.in.tum.de'
PORT = 20207
with open('client_public.pem', 'rb') as f:
    CLIENT_PUB_KEY = ECC.import_key(f.read())
with open('client_private.pem', 'rb') as f:
    CLIENT_PRV_KEY = ECC.import_key(f.read())
with open('server_public.pem', 'rb') as f:
    SERVER_PUB_KEY = ECC.import_key(f.read())

class PACKET_TYPE(Enum):
    KEY_EXCHANGE = 0x00
    CHALLENGE = 0x01
    RESPONSE = 0x02
    DATA = 0x03
    ERROR = 0x04

def calc_hmac(message: bytes, key: bytes) -> bytes:
    return hmac.new(key, message, digestmod='sha256').digest()

def derive_keys(Z):
    l = 256 # TODO the documentation states both 256 (l.291f) and 512 (l.437,440)
    hmac_key = HKDF(Z, l,"salty hmac",  "HMAC Key")
    enc_key = HKDF(Z, l,"salty encryption",  "Encryption Key")
    return hmac_key, enc_key


class Packet(object):
    def __init__(self, protocol_version:int, packet_type:int, seq:int, payload:bytes, hmac:bytes=bytes(32), valid:bool=True):
        self.protocol_version = protocol_version
        self.packet_type = packet_type
        self.seq = seq
        self.payload = payload
        self.valid = valid
        self.hmac = hmac
    def to_bytes(self):
        msg = bytes(self.protocol_version)[:1] + bytes(self.packet_type)[:1] + bytes(self.seq)[:2] + bytes(len(self.payload))[:4] + self.payload
        # pad to multiple of 32 bytes
        while len(msg) % 32 != 0:
            msg += bytes(1)
        return msg + self.hmac

def make_packet(protocol_version:int, packet_type:int, seq:int, payload:bytes, key:bytes, hmac0=False) -> bytes:
        msg0 = Packet(protocol_version, packet_type, seq, payload)
        if hmac0:
            return msg0.to_bytes()
        else:
            return Packet(protocol_version, packet_type, seq, payload, hmac=calc_hmac(msg0.to_bytes(), key)[:32]).to_bytes()

def parse_packet(msg:bytes, key=None):
        protocol_version = int.from_bytes(msg[0:1], byteorder='big')
        packet_type = int.from_bytes(msg[1:2], byteorder='big')
        seq = int.from_bytes(msg[2:4], byteorder='big')
        l = int.from_bytes(msg[4:8], byteorder='big')
        payload = msg[8:8+l]
        i = 8+l
        while i % 32 != 0:
            i += 1
        hmac = msg[i:i+32]
        if key is not None:
            valid = calc_hmac(Packet(protocol_version, packet_type, seq, payload).to_bytes(),key)[:32] == hmac
        else:
            valid = True
        return Packet(protocol_version, packet_type, seq, payload, hmac, valid)

def calculateX(a, g = STS_GENERATOR, p = STS_PRIME):
    return pow(g, a, mod=p)


def verify_signature(sig, Y, X):
    return verify(SERVER_PUB_KEY, message=f'{Y}{X}'.encode(), signature=sig)

def make_signature(y, x):
    return sign(CLIENT_PRV_KEY, message=f'{y}{x}'.encode())

def get_flag():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((HOST, PORT))
    sf = s.makefile('rw')  # we use a file abstraction for the sockets
    
    def write(m):
        sf.write(m.hex()+b'\n')
        sf.flush()
        print('Wrote:', m.hex())
    def read():
        ln = sf.readline().rstrip('\n')
        print('Got:', ln)
        return ln

    # Step 1
    xb = parse_packet(bytes.fromhex(read())).payload
    x = int.from_bytes(xb, byteorder='big')

    # Step 2
    b = 7 # TODO
    y = calculateX(b)
    yb = int.to_bytes(y, len(xb), byteorder='big').hex().encode()
    z = calculateX(x)
    hmac_key, enc_key = derive_keys(z)
    write(yb + make_signature(yb,xb))

    # Step 3
    read()


if __name__ == '__main__':
    get_flag()
