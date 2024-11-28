import hashlib
#import hmac
import socket
import base64
import itertools
import bitarray
from hashlib import sha256

#import bitarray
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

def byte_and(self, other):
    return bytes(a & b for a, b in zip(self, other))

def pkcs7(message: bytes, block_size: int = 16) -> bytes:
    gap_size = block_size - (len(message) % block_size)
    return message + bytes([gap_size] * gap_size)


def calc_cbc_mac(message: bytes, iv: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    message = pkcs7(message)
    # ideal but supported only since python 3.12
    #for m in itertools.batched(message, 16):
    for m in batched_it(message, 16):
        iv = cipher.encrypt(xor(m, iv))[-16:]
    return iv

# from https://stackoverflow.com/a/8998040
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

#def calc_cbc_mac_reference(message: bytes, iv: bytes, key: bytes) -> bytes:
#    cipher = AES.new(key, AES.MODE_CBC, iv)
#    message = pkcs7(message)
#    last_block = cipher.encrypt(message)[-16:]
#    return last_block

#def calc_hmac_reference(message: bytes, key: bytes) -> bytes:
#    return hmac.new(key, message, digestmod='sha256').digest()

def calc_hmac(message: bytes, key: bytes) -> bytes:
    ipad = xor(key, b'\3\6\3\6\3\6\3\6\3\6\3\6\3\6\3\6')
    opad = xor(key, b'\5\C\5\C\5\C\5\C\5\C\5\C\5\C\5\C')
    innerHash = sha256(ipad + message).digest()
    outerHash = sha256(opad + innerHash).digest()
    return outerHash




# inspiration from wikipedia
def calc_cmac(message: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, IV)
    #message = pkcs7(message)
    k0 = int(cipher.encrypt(key)[-16])

    def msb(n):
        return n & 0x8000000000000000 #bitarray.bitarray(n)[0]

    if msb(k0) == 0:
        k1 = k0 << 1
    else:
        k1 = (k0 << 1) ^ 0x425

    if msb(k1) == 0:
        k2 = k1 << 1
    else:
        k2 = (k1 << 1) ^ 0x425

    c = IV
    for m in batched_it(message, 16):
        if len(list(m)) == 16:
            #mq = k1 ^ m
            c = cipher.encrypt(xor(c, m))[-16:]
        else:
            mq = xor(
                (
                    k2.to_bytes(16,'big') 
                    + b'\0' * (16 - len(list(m)))
                ) + (
                    (1).to_bytes(16,'big')
                    + b'\1'
                    + b'\0' * (15 - len(list(m)))
                ),
                m
            )
            c = cipher.encrypt(xor(c, mq))[-16:]
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
