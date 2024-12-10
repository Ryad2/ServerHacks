import base64
import socket

from Crypto.Cipher import AES

# Fill in the right target here
HOST = 'netsec.net.in.tum.de'
PORT = 20208

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
    print(message1)
    sf.flush()
    sf.write(encrypt_command("add 3371f6ba154693185cc3e5aac70ed1009a002cfa671e5c65a61103a94a857b3f313dcc52196652edc5b67b2b66646c6bb239ba0082d382abb20adf1fd0ce077432c0474fea8e5d62b391fd07b3f4c422f0531d37680006ed377eac814e38aa45fe94b7d747dbfb483741ff8e59f9078b7fb057ed6d76110ac3e3ce7227d0468c5a57e7dc991b25b99436e4ebec7b344c31572da46fff680db7d52697f706e0709891abaa265e56017fd6771c8150606bca6a064a3031a6746f011d01c6b1f48503f78f76a04f213aa4b1cc8eee85e4ae48b4b2546ec839b29f780473975f3a575bf7187f5ac3457a0651d8b5151b2be4") + "\n")
    sf.flush()
    message2 = sf.readline().rstrip('\n')
    print(message2)
    sf.close()
    s.close()


if __name__ == '__main__':
    get_flag()
