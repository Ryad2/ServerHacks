import base64
import socket

from Crypto.Cipher import AES

# Fill in the right target here
HOST = 'this.is.not.a.valid.domain'  # TODO
PORT = 0  # TODO

COMMAND_KEY = b'u\x12K[\xab\x9e&e\xfcj\x0cQ\x01\xbf\x984'
COMMAND_IV = b'[\xc7\xdcsMMr\xe9\\-\x13@\xb3\xedO\x85'


def encrypt_command(command: str) -> str:
    padded = command + '_' * (AES.block_size - len(command) % AES.block_size)

    cipher = AES.new(COMMAND_KEY, AES.MODE_CBC, iv=COMMAND_IV)
    encrypted = cipher.encrypt(padded.encode())
    return base64.b64encode(encrypted).decode()


def get_flag():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((HOST, PORT))
    sf = s.makefile('rw')  # we use a file abstraction for the sockets

    message1 = sf.readline().rstrip('\n')
    # TODO

    sf.close()
    s.close()


if __name__ == '__main__':
    get_flag()
