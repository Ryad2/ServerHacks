import hashlib
#import hmac
import socket
import base64
import itertools
from hashlib import sha256

import bitarray
from Crypto.Cipher import AES
#from Crypto.Hash import CMAC
#from cryptography.hazmat.primitives.ciphers import algorithms
#from cryptography.hazmat.primitives.cmac import CMAC

# Fill in the right target here
HOST = 'netsec.net.in.tum.de'  # TODO
PORT = 20105  # TODO
KEY = b"1337133713371337"
IV = b'\x00' * 16


def xor(self, other):
    return bytes(a ^ b for a, b in zip(self, other))

# pad to lenght by apending 0
def pad_back(self, n):
    return self + (b'\0' * (n - len(self)))

# pad to lenght by prepending 0
def pad_front(self, n):
    return (b'\0' * (n - len(self))) + self

# pad to lenght by apending 0 (bitarray)
def b_pad_back(self, n):
    t = bitarray.bitarray(n - len(self))
    return self + t

# pad to lenght by prepending 0 (bitarray)
def b_pad_front(self, n):
    t = bitarray.bitarray(n - len(self))
    return t + self

def pkcs7(message: bytes, block_size: int = 16) -> bytes:
    gap_size = block_size - (len(message) % block_size)
    return message + bytes([gap_size] * gap_size)


def calc_cbc_mac(message: bytes, iv: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    message = pkcs7(message)
    for m in itertools.batched(message, 16):
        iv = cipher.encrypt(xor(m, iv))[-16:]
    return iv


#def calc_cbc_mac_reference(message: bytes, iv: bytes, key: bytes) -> bytes:
#    cipher = AES.new(key, AES.MODE_CBC, iv)
#    message = pkcs7(message)
#    last_block = cipher.encrypt(message)[-16:]
#    return last_block

#def calc_hmac_reference(message: bytes, key: bytes) -> bytes:
#    return hmac.new(key, message, digestmod='sha256').digest()

def calc_hmac(message: bytes, key: bytes) -> bytes:
    key = pad_front(key, 128)
    localKey = key + bytes(128)
    ipad = bytes((x ^ 0x36) for x in localKey)
    opad = bytes((x ^ 0x5C) for x in localKey)
    innerHash = sha256(ipad + message).digest()
    outerHash = sha256(opad + innerHash).digest()
    return outerHash




# inspiration from wikipedia
def calc_cmac(message: bytes, key: bytes) -> bytes:
    AES_BYTE_LEN = 32
    AES_BIT_LEN = AES_BYTE_LEN * 8
    def b_normalize(b):
        return b_pad_front(b[-32:], AES_BIT_LEN)
    # b_ prefix for bitarrays

    # pad key with 0
    b_key = bitarray.bitarray()
    b_key.frombytes(key)
    b_key = b_normalize(b_key)
    key = b_key.tobytes()

    # create aes object
    cipher = AES.new(key, AES.MODE_CBC, bytes(16))
    #message = pkcs7(message)

    k0 = cipher.encrypt(key)
    b_k0 = bitarray.bitarray()
    b_k0.frombytes(k0)
    b_k0 = b_normalize(b_k0)

    def msb(n):
        return n[0]

    # 0x425
    b_constant = b_normalize(bitarray.bitarray('010000100101'))

    if msb(b_k0) == 0:
        b_k1 = b_normalize(b_k0 << 1)
    else:
        b_k1 = b_normalize(b_k0 << 1) ^ b_constant

    if msb(b_k1) == 0:
        b_k2 = b_normalize(b_k1 << 1)
    else:
        b_k2 = b_normalize(b_k1 << 1) ^ b_constant

    b_c = bitarray.bitarray(AES_BIT_LEN)

    b_message = bitarray.bitarray()
    b_message.frombytes(message)

    for m in itertools.batched(b_message, AES_BIT_LEN):
        b_m = bitarray.bitarray(m)
        if len(b_m) == AES_BIT_LEN:
            #mq = k1 ^ m
            c = cipher.encrypt((b_c ^ b_m).tobytes())
            b_c = bitarray.bitarray()
            b_c.frombytes(c)
        else:
            b_one = bitarray.bitarray('1')
            b_mq = b_normalize(b_k2 + b_one + b_m)
            c = cipher.encrypt((b_c ^ b_mq).tobytes())
            b_c = bitarray.bitarray()
            b_c.frombytes(c)
    return c

#def calc_cmac_reference(message: bytes, key: bytes) -> bytes:
#    c = CMAC.new(key, ciphermod=AES)
#    c.update(message)
#    return c.digest()



def get_flag():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    sf = s.makefile('rw')  # we use a file abstraction for the sockets

    message1 = sf.readline().rstrip('\n')
    print(message1)
    message1 = bytes.fromhex(message1)
    answer = f'{base64.b64encode(calc_hmac(message1, KEY))};{base64.b64encode(calc_cbc_mac(message1, IV, KEY))};{base64.b64encode(calc_cmac(message1, KEY))}'
    print(answer)
    sf.write(f'{answer}\n')
    sf.flush()
    print(sf.readline().rstrip('\n'))

    sf.close()
    s.close()


if __name__ == '__main__':
    get_flag()
