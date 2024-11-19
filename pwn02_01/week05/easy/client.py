import hmac
import socket

from Crypto.Cipher import AES
from Crypto.Hash.CMAC import CMAC

# Fill in the right target here
HOST = 'netsec.net.in.tum.de'  # TODO
PORT = 20105  # TODO
KEY = b"1337133713371337"
IV = b'\x00' * 16



def pkcs7(message: bytes, block_size: int = 16) -> bytes:
    gap_size = block_size - (len(message) % block_size)
    return message + bytes([gap_size] * gap_size)
def calc_cbc_mac(message: bytes, iv: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    message = pkcs7(message)
    last_block = cipher.encrypt(message)[-16:]
    return last_block

def calc_hmac(message: bytes, key: bytes) -> bytes:
    return hmac.new(key, message, digestmod='sha256').digest()


def calc_cmac(message: bytes, key: bytes) -> bytes:
    c = CMAC.new(key, ciphermod=AES)
    c.update(message)
    return c.digest()


def get_flag():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    sf = s.makefile('rw')  # we use a file abstraction for the sockets

    message1 = sf.readline().rstrip('\n')
    print(message1)
    message1 = message1.encode()
    answer = f'{calc_hmac(message1, KEY)};{calc_cbc_mac(message1, IV, KEY)};{calc_cmac(message1, KEY)}'

    sf.write(f'{answer}\n')
    sf.flush()
    print(sf.readline().rstrip('\n'))

    sf.close()
    s.close()


if __name__ == '__main__':
    get_flag()
