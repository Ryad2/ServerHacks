#!/usr/bin/env python3

import os
import struct
import argparse
import asyncio
import logging
import binascii
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

from protocol import *

log = logging.getLogger(__name__)
client_count = 0


class TetraProtocol(asyncio.Protocol):
    def __init__(self):
        self.client_id = client_count
        # Both client and server should start with zero as default
        # This is later synchronized by the server to a timestamp
        self.packet_counter = 0

    def connection_made(self, transport):
        log_client(transport, self.client_id)
        self.transport = transport

        log.debug(f'Using secret key: {binascii.hexlify(secret_key)}')

        # Signal start of connection to the server by sending initial HELLO packet
        cipher = ChaCha20.new(key=secret_key, nonce=struct.pack('>Q', self.packet_counter))
        self.transport.write(cipher.encrypt(pack_hello()))

    def data_received(self, data):
        # Use current (hopefully synchronized) packet counter as IV/nonce
        cipher = ChaCha20.new(key=secret_key, nonce=struct.pack('>Q', self.packet_counter))
        # Decrypt the incoming data
        data_decrypt = cipher.decrypt(data)

        log.info(
            f'{self.client_id} reveived {binascii.hexlify(data_decrypt)}, packet counter {self.packet_counter}'
        )

        # Try to parse message
        try:
            message_type, flags = unpack_type_flags(data[0])
            log.info("message type: " + hex(message_type) + " flags: " + hex(flags))
            ks = ChaCha20.new(key=secret_key, nonce=struct.pack('>Q', self.packet_counter))
            log.info("keystream: " + str(ks.decrypt(bytes(10))))
            message_parsed = parse_message(data_decrypt)
        except Exception as e:
            log.error(f'Exception occured when parsing message: {e}')
            message_parsed = None

        # Abort on parsing failure
        if not message_parsed:
            log.error(f'{self.client_id}: Unparseable message received.')
            return

        message_type = message_parsed[0]
        # Initial message, should be sent and not received by client, abort
        if message_type == TYPE_HELLO:
            log.warning(f'{self.client_id}: Received unsolicited HELLO')
            return
        # This sets the packet counter to the received timestamp
        elif message_type == TYPE_TIMESTAMP:
            timestamp = message_parsed[1]
            log.info(f'{self.client_id} Received TIMESTAMP packet, setting to {timestamp}')
            self.packet_counter = timestamp
            return
        # This receives the flag, prints it and acknowledges the packet with ACK
        elif message_type == TYPE_PASSWD:
            flag = message_parsed[1]
            log.info(f'{self.client_id}: Received flag: {flag}')

            # Create new cipher for encrypting and sent the encrypted ACK
            cipher = ChaCha20.new(key=secret_key, nonce=struct.pack('>Q', self.packet_counter))
            self.transport.write(cipher.encrypt(pack_ack()))
        # Acknowlegment for received packet, this should only be sent and not received by the client, abort
        elif message_type == TYPE_ACK:
            log.warning(f'{self.client_id}: Received unsolicited ACK')
            return
        # DATA message, extract and display the message, check the checksum if available, trigger ACK
        elif message_type == TYPE_DATA:
            checksum_avail = message_parsed[1]
            payload = message_parsed[2]
            checksum = message_parsed[3]

            log.info(
                f"{self.client_id} Received DATA: {payload} length {len(payload)}, checksum: {checksum_avail} {checksum if checksum_avail else ''}"
            )
            if checksum_avail and (not verify_checksum(payload, checksum)):
                log.warning(f'{self.client_id}: Invalid checksum received.')
                return

            # Create new cipher for encrypting and sent the encrypted ACK
            cipher = ChaCha20.new(key=secret_key, nonce=struct.pack('>Q', self.packet_counter))
            self.transport.write(cipher.encrypt(pack_ack()))
        # This message provokes encrypted acknowlegment without increasing packet counter
        elif message_type == TYPE_PING:
            log.info(f'{self.client_id} Received Ping message.')
            # Create new cipher for encrypting and sent the encrypted ACK
            cipher = ChaCha20.new(key=secret_key, nonce=struct.pack('>Q', self.packet_counter))
            self.transport.write(cipher.encrypt(pack_ack()))
            return
            # Unknown message, abort
        else:
            log.info(f'{self.client_id} Unknown message type received, dropping.')
            return

        self.packet_counter += 1


def handle_client():
    client_count += 1
    return TetraProtocol()


async def main():
    cmd = argparse.ArgumentParser()
    cmd.add_argument('-p', '--port', type=int, default=20209)
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
