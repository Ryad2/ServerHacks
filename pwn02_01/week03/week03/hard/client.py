import socket

# Fill in the right target here
HOST = 'netsec.net.in.tum.de'  # TODO
PORT = 20203  # TODO
#PORT = 1337


def create_packet(src_ip, dst_ip, protocol, src_port, dst_port) -> str:
    return f'{src_ip},{dst_ip},{protocol},{src_port},{dst_port}'


def get_flag():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((HOST, PORT))
    sf = s.makefile('rw')  # we use a file abstraction for the sockets

    server_ip = "131.159.15.68"
    server_port = "1337"
    own_ip = "161.40.0.1"
    own_port = "7331"

    icmp = create_packet(own_ip, server_ip, "ICMP", own_port, server_port)
    tcp = create_packet(own_ip, server_ip, "TCP", own_port, server_port)
    #print(icmp)
    #print(tcp)
    sf.write(icmp + "\n")
    sf.flush()
    sf.write(tcp + "\n")
    sf.flush()
    print(sf.readline().strip())

    sf.close()
    
    s.close()


if __name__ == '__main__':
    get_flag()
