import socket
import base64

from Crypto.Cipher import AES

# Fill in the right target here
HOST = 'netsec.net.in.tum.de'  # TODO
PORT = 20205  # TODO
IV = b'\x00' * 16

def pkcs7(message: bytes, block_size: int = 16) -> bytes:
    gap_size = block_size - (len(message) % block_size)
    return message + bytes([gap_size] * gap_size)


def calc_cbc_mac(message: bytes, iv: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    message = pkcs7(message)
    last_block = cipher.encrypt(message)[-16:]
    return last_block


def get_flag():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((HOST, PORT))
    sf = s.makefile('rw')  # we use a file abstraction for the sockets

    #msg = b'type=funfact&number=1'
    msg = b'type=secret&number=1'
    msg_enc = base64.b64encode(msg).decode()
    iv_enc = base64.b64encode(IV).decode()
    #mac = calc_cbc_mac(msg, IV, b'1337133713371337')
    mac = bytes(0x24c46ef4) + bytes(0x11da3deb) + bytes(0x80d2aea6) + bytes(0xc2dfce3b)

    mac_enc = base64.b64encode(mac).decode()
    request = f'{iv_enc};{iv_enc};{mac_enc}\n'
    print(request)
    sf.write(f'{request}\n')
    sf.flush()
    print(sf.readline().rstrip('\n'))

    sf.close()
    s.close()


if __name__ == '__main__':
    get_flag()
