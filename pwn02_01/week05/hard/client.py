import socket
import base64

from Crypto.Cipher import AES

HOST = 'netsec.net.in.tum.de'
PORT = 20205

MAC_FAIL_PREFIX = 'MAC verification failed: expected '

def pkcs7(message: bytes, block_size: int = 16) -> bytes:
    gap_size = block_size - (len(message) % block_size)
    return message + bytes([gap_size] * gap_size)


def calc_cbc_mac(message: bytes, iv: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    message = pkcs7(message)
    last_block = cipher.encrypt(message)[-16:]
    return last_block


def xor(self, other):
    return bytes(a ^ b for a, b in zip(self, other))

def pad(self, n):
    return self + (b'0' * (n - len(self)))

def H(sf, m, iv, mac=None):
    print('Sent', 'm:', m, 'iv:', iv, 'mac:', mac)
    msg_enc = base64.b64encode(m).decode()
    iv_enc = base64.b64encode(iv).decode()
    if mac:
        mac_enc = base64.b64encode(mac).decode()
    else:
        # use any mac, assumed to be incorrect
        mac_enc = base64.b64encode(b'0' * 16).decode()
    
    request = f'{msg_enc};{iv_enc};{mac_enc}\n'
    sf.write(request)
    sf.flush()
    message = sf.readline().rstrip('\n')
    if mac == None:
        mac = message.lstrip(MAC_FAIL_PREFIX)[:32]
        mac = bytes.fromhex(mac)
        print('Got:', mac)
        return mac
    return message

def get_flag():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((HOST, PORT))
    sf = s.makefile('rw')  # we use a file abstraction for the sockets

    # final request message:
    #      0123456789abcdef
    m1 = b'type=secrets&num'
    m2 = b'ber=1337'
    m = m1 + m2

    # xor(iv, m1) = xor(a, b) = x
    # b must be of length 16, be split by '&' into 2 (or more) parts containing (at least) one '='
    #     0123456789abcdef
    b = b'0000=000&000=000'
    a = xor(m1, b)
    x = xor(a, b)
    iv = xor(x, m1)

    h = {}
    print('request 1')
    print(xor(a, b))
    h[x] = H(sf, iv=a, m=b)

    # xor(h[x], m2) = xor(c, b)
    c = xor(xor(h[x], pad(m2, 16)), b)

    print('request 2')
    print(xor(xor(c, b), h[x]))
    z = H(sf, iv=c, m=b)

    print('final request')
    print(H(sf, m=m, iv=iv, mac=z))

    sf.close()
    s.close()

if __name__ == '__main__':
    get_flag()
