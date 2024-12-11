import socket
import hmac
import argparse
import random
import asyncio
import logging
from asyncio import StreamReader, StreamWriter
from enum import Enum

from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256, SHA512

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


def padn(l:int, n:int)->int:
    return n - (l % n)
def pad(msg:bytes, n:int)->bytes:
    return b'\0' * padn(len(msg), n)

def calc_hmac(message: bytes, key: bytes) -> bytes:
    return hmac.new(key, message, digestmod='sha256').digest()

def derive_keys(Z:bytes):
    l = 32 # = 256 bit
    hmac_key = HKDF(master=Z, key_len=l, salt=b"salty hmac", hashmod=SHA512, context=b"HMAC Key")
    enc_key = HKDF(master=Z, key_len=l, salt=b"salty encryption", hashmod=SHA512, context=b"Encryption Key")
    return hmac_key, enc_key


class Packet(object):
    def __init__(self, protocol_version:int, packet_type:PACKET_TYPE, seq:int, payload:bytes, hmac:bytes=bytes(32), valid:bool=None):
        self.protocol_version = protocol_version
        self.packet_type = packet_type
        self.seq = seq
        self.payload = payload
        self.valid = valid
        self.hmac = hmac
    def to_bytes(self):
        return self.protocol_version.to_bytes(1,byteorder='big') + self.packet_type.value.to_bytes(1,byteorder='big') + self.seq.to_bytes(2,byteorder='big') + len(self.payload).to_bytes(4,byteorder='big') + self.payload + self.hmac
    def compute_hmac(self, key):
        self.hmac = bytes(32)
        self.hmac = calc_hmac(self.to_bytes(), key)
        return self
    def __str__(self):
        return f"protocol_version: {self.protocol_version}, packet_type: {self.packet_type}, seq: {self.seq}, payload: {self.payload.hex()}, valid: {self.valid}, hmac: {self.hmac}"

def make_packet(protocol_version:int, packet_type:PACKET_TYPE, seq:int, payload:bytes, key:bytes=None) -> bytes:
        msg = Packet(protocol_version, packet_type, seq, payload)
        if key is not None:
            return msg.compute_hmac(key)
        return msg

def parse_packet(msg:bytes, key=None):
        protocol_version = int.from_bytes(msg[0:1], byteorder='big')
        packet_type = PACKET_TYPE(int.from_bytes(msg[1:2], byteorder='big'))
        seq = int.from_bytes(msg[2:4], byteorder='big')
        l = int.from_bytes(msg[4:8], byteorder='big')
        payload = msg[8:8+l]
        i = 8+l
        hmac = msg[i:i+32]
        if len(hmac) != 32:
            print('Unexpected end of message, hmac expected, got:', len(hmac), hmac)
        if key is not None:
            valid = calc_hmac(Packet(protocol_version, packet_type, seq, payload).to_bytes(),key) == hmac
        else:
            valid = None
        return Packet(protocol_version, packet_type, seq, payload, hmac, valid)

def gExpModP(a, g = STS_GENERATOR, p = STS_PRIME):
    return pow(g, a, mod=p)


def verify_signature(sig, m):
    return verify(SERVER_PUB_KEY, message=m, signature=sig)

def make_signature(m):
    return sign(CLIENT_PRV_KEY, message=m)

class Encrypted(object):
    def __init__(self, enc_key, iv, message):
        self.enc_key = enc_key
        self.iv = iv
        self.message = message
        # pad to multiple of 16 bytes
        self.message += pad(self.message, AES.block_size)
    
    def to_bytes(self):
        cipher = AES.new(self.key_enc, AES.MODE_CBC, self.iv)
        return self.iv + cipher.encrypt(self.message)

def parse_encrypted(enc_key, encrypted):
    ivlen = AES.block_size
    iv = encrypted[:ivlen]
    message = encrypted[ivlen:]
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    message = cipher.decrypt(message)
    return Encrypted(enc_key=enc_key, iv=iv, message=message)

def get_flag():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((HOST, PORT))
    sf = s.makefile('rw')  # we use a file abstraction for the sockets

    def write(m):
        sf.write(m.to_bytes().hex()+'\n')
        sf.flush()
        print('Wrote:', m, '\n=', m.to_bytes().hex())
    def read(key=None):
        ln = sf.readline().rstrip('\n')
        p = parse_packet(bytes.fromhex(ln), key=key)
        print('Got:', ln, '\n=', p)
        return p
    def debug(x):
        print(x)

    # Step 1
    p = read()
    xb = p.payload
    x = int.from_bytes(xb, byteorder='big')

    # Step 2
    b = 7 # TODO random
    y = gExpModP(b)
    yb = int.to_bytes(y, 256, byteorder='big', signed=False)
    z = gExpModP(b, g=x)
    debug('z = ' + str(z))
    zb = int.to_bytes(z, 256, byteorder='big', signed=False)
    hmac_key, enc_key = derive_keys(zb)
    p = make_packet(p.protocol_version, PACKET_TYPE.KEY_EXCHANGE, p.seq + 1, yb + make_signature(yb + xb), key=hmac_key)
    write(p)

    # Step 3
    p = read(hmac_key)
    if not verify_signature(p.payload, xb + yb):
        print('Invalid signature:', p.payload.decode())
        return
    
    # Data Transmit

    # Challenge response
    debug('Challenge response')
    p = read(hmac_key)
    if p.packet_type is not PACKET_TYPE.CHALLENGE:
        print('Expected challenge:', p)
        return
    challenge = parse_encrypted(enc_key, p.payload).message
    write(make_packet(p.protocol_version, PACKET_TYPE.RESPONSE, p.seq, make_signature(challenge), key=hmac_key))

    # Data Transmit
    # Flag
    p = read(hmac_key)
    if (p.packet_type == PACKET_TYPE.ERROR):
        print(p.payload.decode())
        return
    flag = parse_encrypted(enc_key, p.payload).message
    print(flag)


if __name__ == '__main__':
    get_flag()
