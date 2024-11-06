import socket

# Fill in the right target here
HOST = 'this.is.not.a.valid.domain'  # TODO
PORT = 0  # TODO


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
