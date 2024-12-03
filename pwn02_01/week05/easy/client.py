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


def xor(self: bytes, other: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(self, other))

# pad to lenght by apending 0
def pad_back(self: bytes, n: int) -> bytes:
    return self + (b'\x00' * (n - len(self)))

# pad to lenght by prepending 0
def pad_front(self: bytes, n: int) -> bytes:
    return (b'\x00' * (n - len(self))) + self

def pkcs7(message: bytes, block_size: int = 16) -> bytes:
    gap_size = block_size - (len(message) % block_size)
    return message + bytes([gap_size] * gap_size)


def calc_cbc_mac(message: bytes, iv: bytes, key: bytes) -> bytes:
#    cipher = AES.new(key, AES.MODE_CBC, iv)
#    message = pkcs7(message)
#    for m in itertools.batched(message, 16):
#        x = xor(m, iv)
#        y = xor(m, x)
#        iv = cipher.encrypt(x)
#        iv = iv[-16:]
#    return iv[-16:]


#def calc_cbc_mac_reference(message: bytes, iv: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    message = pkcs7(message)
    last_block = cipher.encrypt(message)[-16:]
    return last_block

#def calc_hmac_reference(message: bytes, key: bytes) -> bytes:
#    return hmac.new(key, message, digestmod='sha256').digest()

def calc_hmac(message: bytes, key: bytes) -> bytes:
    localKey = pad_back(key, 64)
    
    ipad = bytes((x ^ 0x36) for x in localKey)
    opad = bytes((x ^ 0x5C) for x in localKey)

    innerHash = sha256(ipad + message).digest()
    outerHash = sha256(opad + innerHash).digest()
    return outerHash




# inspiration from wikipedia
def calc_cmac(message: bytes, key: bytes) -> bytes:
    AES_BYTE_LEN = 16
    AES_BIT_LEN = AES_BYTE_LEN * 8

    # pad key with 0
    b_key = int.from_bytes(key, byteorder="big")
    key = b_key.to_bytes(AES_BYTE_LEN, byteorder="big")
    # Input bytes object (32 bytes)

    # create aes object
    cipher = AES.new(key, AES.MODE_CBC, IV)
    #message = pkcs7(message)

    k0 = cipher.encrypt(IV)
    b_k0 = int.from_bytes(k0, byteorder="big")

    def msb(n):
        return n & (1 << (AES_BIT_LEN - 1)) != 0
    a = msb(0)
    b = msb(-1)

    if AES_BIT_LEN == 64:
        b_constant = 0x1B
    if AES_BIT_LEN == 128:
        b_constant = 0x87
    if AES_BIT_LEN == 256:
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
        m = bytes(m)
        b_m = int.from_bytes(m, byteorder="big")
        if len(m) == AES_BYTE_LEN:
            #else case; b_mq = b_k1 ^ m
            c = cipher.encrypt((b_c ^ b_m).to_bytes(AES_BYTE_LEN, byteorder="big"))
            b_c = int.from_bytes(c, byteorder="big")
        else:
            mq = m + b'\x80' + (b'\x00' * (AES_BYTE_LEN - len(m) - 1))
            b_mq = int.from_bytes(mq, byteorder="big")
            c = cipher.encrypt((b_c ^ b_mq).to_bytes(AES_BYTE_LEN, byteorder="big"))
            b_c = int.from_bytes(c, byteorder="big")
    return c[:AES_BYTE_LEN]

#def calc_cmac_reference(message: bytes, key: bytes) -> bytes:
#    c = CMAC.new(key, ciphermod=AES)
#    c.update(message)
#    return c.digest()



def get_flag():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    sf = s.makefile('rw')  # we use a file abstraction for the sockets

    message1 = sf.readline().rstrip('\n')
    #print(message1)
    message1 = bytes.fromhex(message1)
    #print("h",calc_hmac(message1,KEY),calc_hmac_reference(message1,KEY)) # OK
    #print("cbc",calc_cbc_mac(message1,IV,KEY),calc_cbc_mac_reference(message1,IV,KEY))
    #print("c",calc_cmac(message1,KEY),calc_cmac_reference(message1,KEY))
    answer = f'{base64.b64encode(calc_hmac(message1, KEY))};{base64.b64encode(calc_cbc_mac(message1, IV, KEY))};{base64.b64encode(calc_cmac(message1, KEY))}'
    #print(answer)
    sf.write(f'{answer}\n')
    sf.flush()
    print(sf.readline().rstrip('\n'))

    sf.close()
    s.close()


if __name__ == '__main__':
    get_flag()
