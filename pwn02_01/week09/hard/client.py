import socket
import time

HOST = 'invalid.hostname'
PORT_ALICE = 42
PORT_BOB = 43

# HOST = "127.0.0.1"
# PORT_ALICE = 20011
# PORT_BOB = 20111

# Open connection to Alice and Bob
socket_alice = socket.socket()
socket_alice.connect((HOST, PORT_ALICE))

socket_bob = socket.socket()
socket_bob.connect((HOST, PORT_BOB))

print('Connected to Alice and Bob')

# Receive initial HELLO from Alice and forward to Bob
msg_hello = socket_alice.recv(1024)
socket_bob.send(msg_hello)

print('Received HELLO message from Alice.')

# Receive timestamp and passwd frames
msg_ts = socket_bob.recv(1024)
msg_passwd = socket_bob.recv(1024)

print('Received TIMESTAMP and PASSWORD message from Bob.')

# Foward timestamp and data to alice with wait
socket_alice.send(msg_ts)
time.sleep(0.1)  # wait to make sure two packets are sent
socket_alice.send(msg_passwd)

print('Forwarded data to Alice.')

# Receive ACK from Alice and forward to Bob to ensure increase of packet counter
msg_ack = socket_alice.recv(1024)
socket_bob.send(msg_ack)

print('Received ACK from Alice, exiting.')

# Close
socket_bob.close()
socket_alice.close()
