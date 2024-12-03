import hashlib
#import hmac
import socket
import base64
import itertools
from hashlib import sha256

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
    key = int.from_bytes(key, byteorder="big")
    localKey = key.to_bytes((key.bit_length()+7)//8, byteorder="big") + bytes(16)
    ipad = bytes((x ^ 0x36) for x in localKey)
    b_ipad = int.from_bytes(ipad, byteorder="big")
    opad = bytes((x ^ 0x5C) for x in localKey)
    b_opad = int.from_bytes(opad, byteorder="big")
    b_message = int.from_bytes(message, byteorder="big")
    innerHash = sha256((((1 << 32) - 1) & (b_ipad ^ b_message)).to_bytes(32, byteorder="big")).digest()
    b_innerHash = int.from_bytes(innerHash, byteorder="big")
    outerHash = sha256((b_opad ^ b_innerHash).to_bytes(32, byteorder="big")).digest()
    return outerHash




# inspiration from wikipedia
def calc_cmac(message: bytes, key: bytes) -> bytes:
    AES_BYTE_LEN = 32
    AES_BIT_LEN = AES_BYTE_LEN * 8

    # pad key with 0
    b_key = int.from_bytes(key, byteorder="big")
    key = b_key.to_bytes(AES_BYTE_LEN, byteorder="big")
    # Input bytes object (32 bytes)

    # create aes object
    cipher = AES.new(key, AES.MODE_CBC, bytes(16))
    #message = pkcs7(message)

    k0 = cipher.encrypt(key)
    b_k0 = int.from_bytes(k0, byteorder="big")

    def msb(n):
        return n & (1 << 31) != 0

    # 0x425
    b_constant = 0x425 # 0b010000100101

    if msb(b_k0) == 0:
        b_k1 = (b_k0 << 1)
    else:
        b_k1 = (b_k0 << 1) ^ b_constant

    if msb(b_k1) == 0:
        b_k2 = (b_k1 << 1)
    else:
        b_k2 = (b_k1 << 1) ^ b_constant

    b_c = 0

    for m in itertools.batched(message, AES_BYTE_LEN):
        b_m = int.from_bytes(m, byteorder="big")
        if len(m) == AES_BYTE_LEN:
            #mq = k1 ^ m
            c = cipher.encrypt((b_c ^ b_m).to_bytes(AES_BYTE_LEN, byteorder="big"))
            b_c = int.from_bytes(c, byteorder="big")
        else:
            b_mq = ((1<<33)-1) & ((b_k2 << (1 + len(m) * 8)) | (1 << (len(m) * 8)) | b_m)
            b_mq = int.from_bytes(b_mq.to_bytes(AES_BYTE_LEN, byteorder="big")[-32:], byteorder="big")
            c = cipher.encrypt((b_c ^ b_mq).to_bytes(AES_BYTE_LEN, byteorder="big"))
            b_c = int.from_bytes(c, byteorder="big")
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
