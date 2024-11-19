import socket

# Fill in the right target here
HOST = 'netsec.net.in.tum.de'  # TODO
PORT = 20205  # TODO


def get_flag():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((HOST, PORT))
    sf = s.makefile('rw')  # we use a file abstraction for the sockets


    sf.close()
    s.close()


if __name__ == '__main__':
    get_flag()
