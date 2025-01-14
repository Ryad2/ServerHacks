import hashlib
import socket
import struct
import time
import binascii

from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20

from protocol import *

HOST = 'netsec.net.in.tum.de'
PORT_SOURCE = 0
PORT_ALICE = 20209 if PORT_SOURCE == 0 else (42 if  PORT_SOURCE == 1 else 20011)
PORT_BOB = 20309 if PORT_SOURCE == 0 else (43 if  PORT_SOURCE == 1 else 20111)

def debug(x):
    #print(x)
    pass

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))
def get_flag():
    debug("Open connection to Alice")
    socket_alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_alice.connect((HOST, PORT_ALICE))
    debug("Receive HELLO from Alice")
    msg_hello = socket_alice.recv(1024)
    debug("Received from Alice: " + str(msg_hello))
    debug("Close connection to Alice")
    socket_alice.close()

    debug('Open connection to Bob')
    socket_bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_bob.connect((HOST, PORT_BOB))
    debug("Forward HELLO to Bob: " + str(msg_hello))
    socket_bob.send(msg_hello)
    debug("Receive TIMESTAMP from Bob")
    msg_ts = socket_bob.recv(1024)
    debug("Received from Bob: " + str(msg_ts))
    debug("Receive PASSWORD from Bob")
    msg_passwd = socket_bob.recv(1024)
    debug("Received from Bob: " + str(msg_passwd))


    def test_send_alice(msg, delay=0.1):
        debug("Open connection to Alice")
        socket_alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_alice.settimeout(delay)
        socket_alice.connect((HOST, PORT_ALICE))
        debug("Receive HELLO from Alice")
        msg_hello = socket_alice.recv(1024)
        debug("Received from Alice: " + str(msg_hello))
        debug("Forward TIMESTAMP to Alice: " + str(msg_ts))
        socket_alice.send(msg_ts)
        # Wait to separate messages 
        time.sleep(delay)
        debug("Send test message to Alice: " + str(msg))
        socket_alice.send(msg)
        debug("Wait for ACK from Alice")
        try:
            ack = socket_alice.recv(1024)
            debug("Received ACK from Alice")
            rval = True
        except:
            debug("Received nothing from Alice")
            rval = False
        debug("Close connection to Alice")
        socket_alice.close()
        return rval

    debug("Recovering cipher stream for TIMESTAMP")
    cipher_stream = bytearray(0)

    debug("Extracting the first cipher stream byte from PASSWORD")
    cipher_stream.append(msg_passwd[0] ^ pack_passwd(bytes(0))[0])
    debug("Cipher_stream" + str(len(cipher_stream)) + ": " + str(cipher_stream))

    debug("PINGing Alice to check validity")
    if test_send_alice(xor_bytes(cipher_stream, struct.pack('>B', TYPE_PING << 4))):
        debug("Alice responded to PING")
    else:
        debug("Alice ingnored PING")

    debug("Recover cipher stream at position 1")
    for cipher_guess in range(0, 256):
        # Use DATA format, disable CHECKSUM flag
        data = struct.pack('>BB', (TYPE_DATA << 4), 0)
        # encrypt header (type, flag, length)
        data = xor_bytes(data, cipher_stream + struct.pack('>B', cipher_guess))
        debug("Recover cipher stream byte at position 1: testing for cipher_guess = " + str(cipher_guess))
        # Alice responds with ACK if length is read correctly
        if test_send_alice(data):
            # Add new value to cipher stream
            cipher_stream.append(cipher_guess)
            debug("Cipher_stream" + str(len(cipher_stream)) + ": " + str(cipher_stream))
            # Jump to guessing at next position
            break
        else:
            # Check if was last value
            if cipher_guess == 255:
                debug("Failed to recover cipher stream at position 1")
                return
            pass

    debug("Recover cipher stream from position " + str(len(cipher_stream)) + " up to position " + str(len(msg_passwd)))
    for i in range(len(cipher_stream), len(msg_passwd)):
        debug("Recover cipher stream at position " + str(i))
        # for all possible byte values
        for cipher_guess in range(0, 256):
            # Generate DATA message with payload = 0
            payload_length = len(cipher_stream) - 2
            payload = b'\0' * payload_length
            checksum = binascii.crc32(payload) >> 24
            # Use DATA format, enable CHECKSUM flag
            data = struct.pack('>BB' + str(payload_length) + 'sB', (TYPE_DATA << 4) + 0x1, payload_length, payload, checksum)
            # encrypt header (type, flag, length), encrypt payload, encrypt checksum
            data = xor_bytes(data, cipher_stream + struct.pack('>B', cipher_guess))
            # Since payload is known, checksum is known. We just try all possible byte values at this position to recover the cipher stream
            # If ACK is returned, encrypt(checksum) = checksum ^ cipher_guess holds for the used cipher_guess value.
            debug("Recover cipher stream byte at position " + str(i) + ": testing for cipher guess = " + str(cipher_guess))
            # Alice responds with ACK if checksum is valid
            if test_send_alice(data):
                # Add new value to cipher stream
                cipher_stream.append(cipher_guess)
                debug("Cipher_stream" + str(len(cipher_stream)) + ": " + str(cipher_stream))
                # Jump to guessing at next position
                break
            else:
                # Check if was last value
                if cipher_guess == 255:
                    debug("Failed to recover cipher stream at position " + str(i))
                    return
                pass

    debug("Recovered cipher stream up to position " + str(len(cipher_stream)))
    debug("Cipher_stream" + str(len(cipher_stream)) + ": " + str(cipher_stream))

    debug("Decrypt PASSWORD message: " + str(msg_passwd))
    decrypted_msg_password = xor_bytes(msg_passwd, cipher_stream)
    debug("Decrypted PASSWORD message: " + str(decrypted_msg_password))
    password = parse_message(decrypted_msg_password)[1]    
    password_hash = hashlib.sha256(password).digest()[:4]
    debug("Parsed decrypted PASSWORD message: password = " + str(password) + ", hash(password) = " + str(password_hash))
    debug("Send PASSWORD request to Bob")
    socket_bob.send(xor_bytes(pack_passwd(password_hash), cipher_stream))

    debug("Receive FLAG from Bob")
    msg_flag = socket_bob.recv(1024)
    debug("Received FLAG message from Bob: " + str(msg_flag))
    # flag is not encrypted
    flag = msg_flag[1:]
    print (flag.decode().rstrip('\n'))

    debug("Close conncetion to Bob")
    socket_bob.close()

if __name__ == '__main__':
    get_flag()