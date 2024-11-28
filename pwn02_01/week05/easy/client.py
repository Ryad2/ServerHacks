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

def pkcs7(message: bytes, block_size: int = 16) -> bytes:
    gap_size = block_size - (len(message) % block_size)
    return message + bytes([gap_size] * gap_size)

def batched_it(iterable, n):
    "Batch data into iterators of length n. The last batch may be shorter."
    # batched('ABCDEFG', 3) --> ABC DEF G
    if n < 1:
        raise ValueError('n must be at least one')
    it = iter(iterable)
    while True:
        chunk_it = itertools.islice(it, n)
        try:
            first_el = next(chunk_it)
        except StopIteration:
            return
        yield itertools.chain((first_el,), chunk_it)

def calc_cbc_mac(message: bytes, iv: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    message = pkcs7(message)
    for m in batched_it(message, 16):
        iv = cipher.encrypt(m ^ iv)[-16:]
    return iv


#def calc_cbc_mac_reference(message: bytes, iv: bytes, key: bytes) -> bytes:
#    cipher = AES.new(key, AES.MODE_CBC, iv)
#    message = pkcs7(message)
#    last_block = cipher.encrypt(message)[-16:]
#    return last_block

#def calc_hmac_reference(message: bytes, key: bytes) -> bytes:
#    return hmac.new(key, message, digestmod='sha256').digest()

def calc_hmac(message: bytes, key: bytes) -> bytes:
    localKey = bytes(key) + (b'\0' * 128)
    ipad = bytes((x ^ 0x36) for x in localKey)
    opad = bytes((x ^ 0x5C) for x in localKey)
    innerHash = sha256(ipad + message).digest()
    outerHash = sha256(opad + innerHash).digest()
    return outerHash




# inspiration from wikipedia
def calc_cmac(message: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, 0)
    #message = pkcs7(message)
    k0 = int(cipher.encrypt(key)[-32])

    def msb(n):
        return bitarray.bitarray(n)[0]

    if msb(k0) == 0:
        k1 = k0 << 1
    else:
        k1 = (k0 << 1) ^ 0x425

    if msb(k1) == 0:
        k2 = k1 << 1
    else:
        k2 = (k1 << 1) ^ 0x425

    c = 0
    for m in itertools.batched(message, 16):
        if len(m) == 16:
            #mq = k1 ^ m
            c = cipher.encrypt(c ^ m)[-16:]
        else:
            mq = (k2 << (16 - len(m)) + 1 << (15 - len(m))) ^ m
            c = cipher.encrypt(c ^ mq)[-16:]
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
