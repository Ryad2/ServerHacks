import socket

# Fill in the right target here
HOST = 'localhost'  # TODO
PORT = 20003  # TODO


def create_packet(src_ip, dst_ip, protocol, src_port, dst_port) -> str:
    return f'{src_ip},{dst_ip},{protocol},{src_port},{dst_port}'


def get_flag():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((HOST, PORT))
    sf = s.makefile('rw')  # we use a file abstraction for the sockets

    # TODO

    sf.close()
    s.close()


if __name__ == '__main__':
    get_flag()
