#!/usr/bin/env python3

import os
import time
import struct
import argparse
import asyncio
import logging
import hashlib
import subprocess
import binascii
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

from protocol import *

log = logging.getLogger(__name__)
client_count = 0


class TetraProtocol(asyncio.Protocol):
    def __init__(self):
        self.client_id = client_count
        # This "timestamp" is used to synchronize client and server
        self.timestamp = int.from_bytes(get_random_bytes(4), 'big')
        # Both client and server should start with zero as default
        self.packet_counter = 0
        self.passwd = get_random_bytes(4)
        self.hash_passwd = hashlib.sha256(self.passwd).digest()[:4]

    def connection_made(self, transport):
        log_client(transport, self.client_id)
        self.transport = transport

    def data_received(self, data):
        log.debug(f'Using secret key: {binascii.hexlify(secret_key)}')
        # Use current (hopefully synchronized) packet counter as IV/nonce
        cipher = ChaCha20.new(key=secret_key, nonce=struct.pack('>Q', self.packet_counter))
        # Decrypt the incoming data
        data_decrypt = cipher.decrypt(data)

        log.debug(
            f'{self.client_id} reveived {binascii.hexlify(data_decrypt)}, packet counter {self.packet_counter}'
        )

        # Parse message and abort on failure
        try:
            message_parsed = parse_message(data_decrypt)
        except:
            log.error('Exception on parsing message!')
            message_parsed = None

        if not message_parsed:
            log.error(f'{self.client_id}: Unparseable message received.')
            return

        message_type = message_parsed[0]
        # Initial message, should always trigger a timestamp for synchronization and a flag
        if message_type == TYPE_HELLO:
            cipher = ChaCha20.new(key=secret_key, nonce=struct.pack('>Q', self.packet_counter))

            log.info(f'{self.client_id}: Received HELLO from client!')

            # Send timestamp (encrypted with current packet_counter) for synchronization purposes
            self.transport.write(cipher.encrypt(pack_timestamp(self.timestamp)))
            log.debug(f'{self.client_id}: Sending timestamp {self.timestamp}')

            time.sleep(0.5)
            # Initialize packet counter to timestamp
            self.packet_counter = self.timestamp
            # Initialize new cipher for sending purposes
            cipher = ChaCha20.new(key=secret_key, nonce=struct.pack('>Q', self.packet_counter))

            # Send the password encrypted
            log.info(f'{self.client_id}: sending passwd {self.passwd}')
            self.transport.write(cipher.encrypt(pack_passwd(self.passwd)))
        # This should only be sent by the server, should be dropped without ACK
        elif message_type == TYPE_TIMESTAMP:
            log.warning(f'{self.client_id}: Received unsolicited TIMESTAMP')
            return
        # This should only be sent by the server, should be dropped without ACK
        elif message_type == TYPE_PASSWD:
            hash_message = message_parsed[1]
            log.info(
                f'Password hash {hash_message} received, checking against {self.hash_passwd}'
            )
            if hash_message == self.hash_passwd:
                flag = subprocess.check_output('flag', shell=True)

                cipher = ChaCha20.new(
                    key=secret_key, nonce=struct.pack('>Q', self.packet_counter)
                )
                header = cipher.encrypt(bytes([TYPE_FLAG << 4]))

                self.transport.write(header + flag)

            return
        # This signals that a previously sent message has been received and that the sender
        # has incremented their packet_counter, therefore the server does so, too
        elif message_type == TYPE_ACK:
            log.info(f'{self.client_id}: Received ACK.')
            self.packet_counter += 1
        # This should only be sent by the server, should be dropped without ACK
        elif message_type == TYPE_DATA:
            log.warning(f'{self.client_id}: Received unsolicited DATA')
            return
        # Triggers an encrypted ACK, but does not increase packet_counter
        elif message_type == TYPE_PING:
            cipher = ChaCha20.new(key=secret_key, nonce=struct.pack('>Q', self.packet_counter))
            self.transport.write(cipher.encrypt(pack_ack()))
        elif message_type == TYPE_FLAG:
            cipher = ChaCha20.new(key=secret_key, nonce=struct.pack('>Q', self.packet_counter))
            self.transport.write(cipher.encrypt(pack_ack()))
        # Unknown messages are dropped
        else:
            log.info(f'{self.client_id} Unknown message type received, dropping.')
            return


def handle_client():
    client_count += 1
    return TetraProtocol()


async def main():
    cmd = argparse.ArgumentParser()
    cmd.add_argument('-p', '--port', type=int, default=20309)
    args = cmd.parse_args()

    # start server
    loop = asyncio.get_event_loop()
    server = await loop.create_server(lambda: TetraProtocol(), None, args.port)

    log.info(f'Starting to listen on port {args.port}...')

    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s ' '[%(module)s:%(lineno)d] %(message)s',
    )

    if not os.path.exists('shared_key.dat'):
        with open('shared_key.dat', 'wb') as f:
            secret_key = get_random_bytes(32)
            f.write(secret_key)
    else:
        with open('shared_key.dat', 'rb') as f:
            secret_key = f.read()

    if not os.path.exists('client_key.pub'):
        pass

    asyncio.run(main())
