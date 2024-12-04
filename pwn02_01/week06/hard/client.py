#!/usr/bin/env python3
import random
import socket

# Kerckhoff’s principle for the win
# here are all the crypto primitives Alice and Bob are using
from insecurelib import KDRV256, HMAC, encrypt, decrypt

# Fill in the right target here
HOST = 'this.is.not.a.valid.domain'  # TODO
PORT1 = 20008
PORT2 = 20108


# note the numbers you encounter may be small for demonstration purposes.
# Anyway, please do NOT brute force.


# debug the data sent over the secure channel
# we don't know the key, there is not much to debug here, ...
def debug_secure_channel(s1, s2, data: str):
    data = data.rstrip('\n')  # remove trailing newline
    if len(data) >= 1024:
        print(f"from {s1} to {s2}: '{data[:1024]}...'")
    else:
        print(f"from {s1} to {s2}: '{data}...'")

    iv, ciphertext, mac = data.split(',')
    assert len(iv) == 16 * 2  # a hexlified byte is two bytes long, the IV should be 16 bytes
    assert (
        len(ciphertext) % (16 * 2) == 0
    )  # a hexlified byte is two bytes long, AES block size is 128 bit (16 byte)
    assert (
        len(mac) == 16 * 2
    )  # a quite short MAC. Hint: you still don't want to brute force it!


def main():
    # We connect to Alice and Bob and relay their messages.
    # They send all their communication over us. How convenient :-)
    # Dolev-Yao attacker model without any low-level effort.

    s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s1.connect((HOST, PORT1))
    s1f = s1.makefile('rw')  # file abstraction for the sockets

    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.connect((HOST, PORT2))
    s2f = s2.makefile('rw')

    # A -> B: p,g,X
    data = s1f.readline().rstrip('\n')
    print(f"from s1 to s2: '{data}'")
    p, g, X = map(int, data.split(','))

    # TODO: get the flag

    s1f.close()
    s2f.close()
    s1.close()
    s2.close()


if __name__ == '__main__':
    main()
