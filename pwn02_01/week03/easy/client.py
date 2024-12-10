import socket

# Fill in the right target here
HOST = 'netsec.net.in.tum.de'  # TODO
PORT = 20103  # TODO


def get_flag():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((HOST, PORT))
    sf = s.makefile('rw')  # we use a file abstraction for the sockets

    message1 = sf.readline().rstrip('\n')
    sf.write("98\n")
    sf.flush()
    #print(sf.readlines(2944))
    solution = """[("192.168.0.92", "8.8.8.8", "udp", 20474, 53), ("192.168.0.92", "31.192.117.132", "tcp", 49722, 80), ("61.61.61.61", "192.168.0.148", "tcp", 55553, 23), ("192.168.0.92", "54.54.54.54", "tcp", 46465, 25)]"""
    #print(solution)
    sf.write(solution + "\n")
    sf.flush()
    
    #while "Correct answer" != sf.readline().strip():
    #    pass
    flag = ""
    while not flag.startswith("flag"):
        flag = sf.readline().strip()
    print(flag)
    #for i in sf.readlines():
    #    print(i)
    sf.close()
    s.close()


if __name__ == '__main__':
    get_flag()
