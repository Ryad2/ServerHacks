#!/usr/bin/env python3

import argparse
import asyncio
import logging
import subprocess
import random
from asyncio import StreamReader, StreamWriter

from insecurelib import *
from pwn_utils.utils import read_line_safe

log = logging.getLogger(__name__)
clients = {}  # task -> (reader, writer)

primes: list[int] | None = None
with open('bob_private.pem', 'rb') as f:
    bob_private = f.read()
    privKey = ECC.import_key(bob_private)
with open('alice_public.pem', 'rb') as f:
    alice_public = ECC.import_key(f.read())


# channel class, receives initial STS key exchange params
class AuthenticatedChannel:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.shared_key = None

    def is_authenticated(self) -> bool:
        return self.shared_key is not None

    async def send_encrypted(self, msg: bytes):
        """Sends an encrypted message. Adds newline to the message"""
        if not self.is_authenticated():
            return
        msg = encrypt(self.shared_key, msg)
        self.writer.write(msg + b'\n')
        await self.writer.drain()

    async def recv_encrypted(self) -> bytes | None:
        """receives encrypted message. Returns None if no message is received"""
        if not self.is_authenticated():
            return None
        data = await read_line_safe(self.reader)
        if data is None:
            return None
        return decrypt(self.shared_key, data)

    async def do_STS_key_exchange(self):
        # receive p,q and public keypart to other server (over the client) and wait for response
        pgX = await read_line_safe(self.reader)

        if pgX is None:
            return

        if pgX.count(',') != 2:
            self.writer.write('Invalid amount of arguments (expected 3; p,g,X)\n'.encode())
            await self.writer.drain()
            return

        p, g, X = map(int, pgX.split(','))

        # primality and size checks not necessary since fixed values from RFC 3526 are used for STS key exchange

        # create own public/private key parts:
        b = random.randint(1, p - 1)
        Y = pow(g, b, mod=p)

        # calculate shared key
        key = str(pow(X, b, mod=p))
        key = KDRV256(key.encode())

        # sign Y and X and send Y and signature
        sig = sign(privKey, f'{Y},{X}'.encode())
        sig = encrypt(key, sig)
        message = f'{Y},{sig.decode()}\n'.encode()
        self.writer.write(message)
        await self.writer.drain()

        answer_sig = await read_line_safe(self.reader)
        if answer_sig is None:
            return

        decrypted_sig = decrypt(key, answer_sig)
        if not verify(alice_public, message=f'{X},{Y}'.encode(), signature=decrypted_sig):
            self.writer.write('Signature verification failed\n'.encode())
            await self.writer.drain()
            return None

        self.shared_key = key


async def do_session_key_DH_exchange(channel: AuthenticatedChannel) -> bytes | None:
    """
    Initiates session key DH exchange.
    All communication is sent over the authenticated channel.
    """
    # pick p, g and private secret a + public part X=g^a mod p
    p = random.choice(primes)
    g = random.choice(primroots(p))
    a = random.randint(1, p - 1)
    X = pow(g, a, mod=p)

    # send p,q and public keypart
    pgX = f'{p},{g},{X}'
    await channel.send_encrypted(pgX.encode())

    Y = await channel.recv_encrypted()
    log.info(f'received "{Y}" as Y (public key)')

    if Y is None:
        await channel.send_encrypted('no public key received'.encode())
        return None

    Y = int(Y.decode().rstrip('\n'))
    if Y >= p:
        await channel.send_encrypted(f"Y ({Y}) can't be larger or equal to p ({p})!".encode())
        return None
    # calculate shared key
    key = str(pow(Y, a, mod=p))
    key = KDRV256(key.encode())
    return key


async def handle_client(client_reader: StreamReader, client_writer: StreamWriter):
    try:
        log_new_connection(client_writer)
    except Exception as e:
        log.error(f'EXCEPTION (get peername): {e} ({type(e)})')
        return

    try:
        authenticated_channel = AuthenticatedChannel(client_reader, client_writer)
        await authenticated_channel.do_STS_key_exchange()
        if not authenticated_channel.is_authenticated():
            log.info('Authenticated key exchange failed!')
            return

        # do session key DH exchange
        session_key = await do_session_key_DH_exchange(authenticated_channel)

        message = await authenticated_channel.recv_encrypted()

        if message is None:
            return

        decrypted_msg = decrypt(session_key, message.decode())
        print('decrypted_msg: ', decrypted_msg)

        if decrypted_msg.decode() != 'Hey Bob, plz send me my f14g :-)':
            await authenticated_channel.send_encrypted(
                'Critical error: unknown message'.encode()
            )
            return

        flag = subprocess.check_output('flag')
        encrypted_flag = encrypt(session_key, flag)
        await authenticated_channel.send_encrypted(encrypted_flag)

    except UnicodeDecodeError as e:
        try:
            client_writer.write(
                f"UnicodeDecodeError: {e} (yep, this leaks a lot about the plaintext, but you don't need it ;))\n".encode()
            )
        except Exception:
            log.exception("couldn't handle UnicodeDecodeError")
        return

    except Exception as e:
        print('Exception: ', e)
        pass


def accept_client(client_reader: StreamReader, client_writer: StreamWriter):
    task = asyncio.Task(handle_client(client_reader, client_writer))
    clients[task] = (client_reader, client_writer)

    def client_done(task):
        del clients[task]
        client_writer.close()
        log.info('connection closed')

    task.add_done_callback(client_done)


def log_new_connection(client_writer):
    remote = client_writer.get_extra_info('peername')
    if remote is None:
        log.error('Could not get ip of client')
        return
    log.info(f'new connection from: {remote[0]}:{remote[1]}')


def main():
    global primes

    cmd = argparse.ArgumentParser()
    cmd.add_argument('-p', '--port', type=int, default=20306)
    args = cmd.parse_args()

    # done as global list, so that we can simply pick one for every connection
    primes = get_primes(MIN_PRIME, MAX_PRIME)
    print('generated primes from {} to {}'.format(primes[0], primes[-1]))

    # start server
    loop = asyncio.get_event_loop()
    f = asyncio.start_server(accept_client, host=None, port=args.port)
    log.info('Server waiting for connections')
    loop.run_until_complete(f)
    loop.run_forever()

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s',
    )

    # "INFO:asyncio:poll took 25.960 seconds" is annyoing
    logging.getLogger('asyncio').setLevel(logging.WARNING)

    main()
