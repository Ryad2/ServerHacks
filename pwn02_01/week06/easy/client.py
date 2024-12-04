import socket
import random

# Fill in the right target here
HOST = 'netsec.net.in.tum.de'
PORT = 20106


def int_to_bytes(m):
    return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()


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
