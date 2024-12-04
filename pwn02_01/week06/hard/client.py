#!/usr/bin/env python3
import random
import socket
from math import log2

# Kerckhoff’s principle for the win
# here are all the crypto primitives Alice and Bob are using
from insecurelib import KDRV256, HMAC, encrypt, decrypt

# Fill in the right target here
HOST = 'netsec.net.in.tum.de'
PORT1 = 20206
PORT2 = 20306
#PORT1 = 20008
#PORT2 = 20108


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
    p, g, X = map(int, data.split(','))
    #print(f"from s1 to s2:\np={p}\ng={g}\nX={X}\n")

    # trick s2 into choosing b s.t. shared key = g^(ab) = 1
    data = f'{X-1},{1},{X}'
    s2f.write(data+'\n')
    s2f.flush()

    data = s2f.readline().rstrip('\n')
    Y, sig = data.split(',')

    # examine cert
    iv , c, mac = sig.split(';')
    #print(f"from s2 to s1:\nY={Y}\niv={iv}\nc={c}\nmac={mac}\n")

    # forward s2 -> s1
    s1f.write(data + '\n')
    s1f.flush()

    # forward s1 -> s2
    data = s1f.readline().rstrip('\n')
    s2f.write(data + '\n')
    s2f.flush()

    # channel is now setup
    channel_shared_key = KDRV256((str(1)).encode())

    # s2 -> s1
    data = s2f.readline().rstrip('\n')
    data = decrypt(channel_shared_key, data).decode()
    p, g, X = map(int, data.split(','))

    # we only talk with s2 from now on
    b = 1
    Y = pow(g, b, mod=p)
    s2f.write(encrypt(channel_shared_key, str(Y).encode()).decode() + '\n')
    s2f.flush()

    #print("X=" + str(X))
    # session is now setup;
    session_shared_key = KDRV256((str(X)).encode())

    flagReq = 'Hey Bob, plz send me my f14g :-)'
    sessionFlagReq = encrypt(session_shared_key, flagReq.encode())
    #print( "sessionFlagReq1: " + sessionFlagReq.decode())
    channelFlagReq = encrypt(channel_shared_key, sessionFlagReq).decode()
    #print( "channelFlagReq1: " + channelFlagReq)
    s2f.write(channelFlagReq + '\n')
    s2f.flush()
    channelFlag = s2f.readline().rstrip('\n')
    #print("channel Flag: " + channelFlag)

    sessionFlag = decrypt(channel_shared_key, channelFlag).decode()
    #print('sessionFlag: ' + sessionFlag)

    flag = decrypt(session_shared_key, sessionFlag).decode()
    print(flag)

    # TODO: get the flag

    s1f.close()
    s2f.close()
    s1.close()
    s2.close()


if __name__ == '__main__':
    main()
