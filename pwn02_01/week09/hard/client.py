import hashlib
import socket
import struct
import time
import binascii

from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20

from protocol import *

HOST ='localhost' # 'netsec.net.in.tum.de'
PORT_SOURCE = 0
PORT_ALICE = 20209 if PORT_SOURCE == 0 else (42 if  PORT_SOURCE == 1 else 20011)
PORT_BOB = 20309 if PORT_SOURCE == 0 else (43 if  PORT_SOURCE == 1 else 20111)

def debug(x):
    print(x)
    pass

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))
def get_flag(delay=0.1):
    debug('connecting to client (alice)')
    # Open connection to Alice and Bob
    socket_alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_alice.settimeout(delay)
    socket_alice.connect((HOST, PORT_ALICE))

    debug('connecting to server (bob)')

    socket_bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_bob.connect((HOST, PORT_BOB))

    debug('Connected to Alice and Bob')

    # Receive initial HELLO from Alice and forward to Bob
    msg_hello = socket_alice.recv(1024)
    socket_bob.send(msg_hello)

    debug('Received HELLO message from Alice. ' + str(msg_hello))

    # Receive timestamp and passwd frames
    msg_ts = socket_bob.recv(1024)
    msg_passwd = socket_bob.recv(1024)

    debug('Received TIMESTAMP and PASSWORD message from Bob.')

    # Foward timestamp and data to alice with wait
    socket_alice.send(msg_ts)
    debug('Forwarded TIMESTAMP to Alice. ' + str(msg_ts))
    time.sleep(0.1)  # wait to make sure two packets are sent
    socket_alice.send(msg_ts)
    debug('Forwarded TIMESTAMP to Alice. ' + str(msg_ts))
    return
    socket_alice.send(msg_passwd)
    debug('Forwarded PASSWORD to Alice. ' + str(msg_passwd))

    # Receive ACK from Alice and forward to Bob to ensure increase of packet counter
    msg_ack = socket_alice.recv(1024)
    #socket_bob.send(msg_ack)
    debug('Received ACK from Alice. not forwarding. ' + str(msg_ack))

    def reset_alice_packet_counter():
        socket_alice.send(msg_ts)
        debug('Reset Alice\'s packet counter by resending TIMESTAMP')

    reset_alice_packet_counter()
    time.sleep(0.1)  # wait to make sure two packets are sent

    #debug('HELLO + TIMESTAMP ' + str(xor_bytes(msg_hello, msg_ts)))

    keystream = bytearray(0)

    #extract the flag byte
    no_flags = msg_ack[0] ^ pack_ack()[0]
    keystream.append(no_flags)
    debug(str(keystream))
    socket_alice.send(xor_bytes(keystream, struct.pach('>B', TYPE_PING<<4)))
    return
    debug("trying to guess keystream of length " + str(len(msg_passwd)))
    for i in range(1, len(msg_passwd)):
        #guess the checksum
        for checksum in range(0, 256):
            # generate data message with 0 payload
            length = len(keystream)
            data = struct.pack('>BBsB', (TYPE_DATA << 4) + 0x1, length, b'\0' * length, checksum)
            data = xor_bytes(data, keystream)
            # assume checksum should be 0; we receive ack if checksum = 0 ^ keystream
            debug("Testing byte " + str(i) + " with value " + str(checksum) + ":\t" + str(data))
            socket_alice.send(data)
            try:
                ack = socket_alice.recv(1024)
                keystream.append(checksum ^ (binascii.crc32(keystream[1:]) >> 24))
                reset_alice_packet_counter()
                time.sleep(delay) # wait for reset_alice_packet_counter be processed
                break
            except:
                if checksum == 255:
                    debug("Failed")
                pass

    decrypted_msg_password = xor_bytes(msg_passwd, keystream)
    password = parse_message(decrypted_msg_password)[1]
    password_hash = hashlib.sha256(password).digest()[:4]
    socket_bob.send(pack_passwd(password_hash))

    msg_flag = socket_bob.recv(1024)
    debug("msg_flag" + str(msg_flag))
    flag = msg_flag[1:]
    print (flag)


    # Close
    socket_bob.close()
    socket_alice.close()


if __name__ == '__main__':
    get_flag()