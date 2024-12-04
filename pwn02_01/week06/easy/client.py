import socket
import random

# Fill in the right target here
HOST = 'netsec.net.in.tum.de'
PORT = 20106


def int_to_bytes(m):
    return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()

def bytes_to_int(s):
    return int.from_bytes(s.encode(), 'big')


def is_prime(p, k=5):
    if p < 2:
        return False
    if p in (2, 3):
        return True
    if p % 2 == 0:
        return False

    # Write p-1 as 2^s * d
    s, d = 0, p - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    # Miller-Rabin test
    for _ in range(k):
        a = random.randint(2, p - 2)
        x = pow(a, d, p)
        if x in (1, p - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, p)
            if x == p - 1:
                break
        else:
            return False
    return True

def find_n_bit_prime(n):
    while True:
        p = random.randint(2**(n-1), 2**n - 1)
        if p % 2 == 0:
            p += 1
        if is_prime(p):
            return p

def get_flag():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((HOST, PORT))
    sf = s.makefile('rw')  # we use a file abstraction for the sockets

    sf.flush()
    bitcount_message = sf.readline().rstrip('\n')
    bitcount = int(bitcount_message.lstrip('Please send a secure public key in the format "e;n" where p and q each have ').rstrip(' bits'))
    prime = find_n_bit_prime(bitcount)
    e = 1
    n = prime**2
    sf.flush()
    sf.write(f'{e};{n}\n')
    sf.flush()
    print(int_to_bytes(int(sf.readline().rstrip('\n'))) )

    sf.close()
    s.close()


if __name__ == '__main__':
    get_flag()
