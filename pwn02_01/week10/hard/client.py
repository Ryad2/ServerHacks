import socket
import struct
import binascii
import dns.message
from datetime import datetime

# Fill in the right target here
HOST = 'this.is.not.a.valid.domain'  # TODO
PORT = 0  # TODO

HARDNESS = 300

# weird translation scheme used in NSEC3/by dnspython, found in dns.rdtypes.ANY.NSEC3
# see https://dnspython.readthedocs.io/en/latest/_modules/dns/rdtypes/ANY/NSEC3.html
b32_normal_to_hex = bytes.maketrans(
    b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',  # from
    b'0123456789ABCDEFGHIJKLMNOPQRSTUV',  # to
)

# Hint: https://data.iana.org/root-anchors/root-anchors.xml

# Since some signatures are very short-lived, we have
# to fix the time to the time when the messages were recorded
cert_time = datetime(2024, 1, 28, 23, 18, 0).timestamp()


def check_correctness(messages):
    # Please implement me
    return True


def main():
    s = socket.socket()
    s.connect((HOST, PORT))

    all_received_messages = []

    for _ in range(HARDNESS):
        message = s.recv(4)
        datalen = struct.unpack('>I', message)[0]
        message = b''
        while len(message) < datalen:
            x = s.recv(datalen)
            if not x:
                print('Something seems to be wrong with the server')
                exit(-1)
            message += x

        assert len(message) == datalen

        dns_messages = []
        for el in binascii.unhexlify(message).decode().split('\n\n'):
            dns_messages.append(dns.message.from_text(el))

        correctness = check_correctness(dns_messages)
        all_received_messages.append((message, correctness))

        s.send(bytes([correctness]))

    # Print f14g
    answer = s.recv(1024).decode()
    if 'flag' in answer:
        print(answer)
    else:
        incorrect_idx = int(answer.rstrip('!\n').split()[-1])
        incorrect_message, answered = all_received_messages[incorrect_idx]
        print(
            f'Incorrect message (You sent {answered}):\n\n{binascii.unhexlify(incorrect_message).decode()}'
        )
    s.close()


main()
