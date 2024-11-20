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

def H(sf, msg, iv, mac=None):
    print('Sent', 'msg:', msg, 'iv:', iv, 'mac:', mac)
    msg_enc = base64.b64encode(msg).decode()
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
        mac = message.replace(MAC_FAIL_PREFIX, '')[:32]
        try:
            mac = bytes.fromhex(mac)
        except:
            print('not hex:', mac, 'from', message)
        print('Got:', mac)
        return mac
    return message

def get_flag():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((HOST, PORT))
    sf = s.makefile('rw')  # we use a file abstraction for the sockets

    # final request message:
    #      0123456789abcdef
    n1 = b'type=funfact&num'
    m1 = b'type=secrets&num'
    m2 = b'ber=1337'
    m = m1 + m2
    n = n1 + m2

    # message must be of length 16, be split by '&' into 2 (or more) parts containing (at least) one '='

    # b ^ n1 = m1 = 0 ^ m1 = iv ^ m1
    b = xor(n1, m1)
    iv = b'\0' * 16

    h = {}
    print('request 1')
    # this request is like asking for m, but uses n
    print('b ^n1=', xor(b, n1))
    print('iv^m1=', xor(iv, m1))
    mac = H(sf, iv=b, msg=n)

    print('final request')
    print(H(sf, msg=m, iv=iv, mac=mac))

    sf.close()
    s.close()

if __name__ == '__main__':
    get_flag()
