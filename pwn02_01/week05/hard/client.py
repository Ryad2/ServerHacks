import socket
import base64

from Crypto.Cipher import AES

# Fill in the right target here
HOST = 'netsec.net.in.tum.de'  # TODO
PORT = 20205  # TODO
IV = b'\x00' * 16
hof0 = 0x6594b1c75899dd37a3f18dd1f8ea291e

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

    #msg = b'type=secrets&num'
    msg = b'ber=1337'
    #msg = b'0123456789=1&1=1'
    #msg = b'type=secret&number=1'
    msg_enc = base64.b64encode(msg).decode()
    #iv_enc = base64.b64encode(msg).decode()
    iv_enc = "JMRu9BHaPeuA0q6mwt/OOw=="



    values = 0x24c46ef411da3deb80d2aea6c2dfce3b
    mac = values.to_bytes((values.bit_length() + 7) // 8, byteorder='big')
    mac_enc = base64.b64encode(mac).decode()

    request = f'{msg_enc};{iv_enc};{mac_enc}\n'
    print(request)
    sf.write(f'{request}\n')
    sf.flush()
    print(sf.readline().rstrip('\n'))
    sf.close()
    s.close()

if __name__ == '__main__':
    get_flag()
