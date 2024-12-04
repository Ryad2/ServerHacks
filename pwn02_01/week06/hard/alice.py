#!/usr/bin/env python3
import argparse
import random
import asyncio
import logging
from asyncio import StreamReader, StreamWriter

from insecurelib import *
from pwn_utils.utils import read_line_safe

log = logging.getLogger(__name__)
clients = {}  # task -> (reader, writer)

primes: list[int] | None = None
with open('alice_private.pem', 'rb') as f:
    alice_private = f.read()
    privKey = ECC.import_key(alice_private)
with open('bob_public.pem', 'rb') as f:
    bob_public = ECC.import_key(f.read())


# channel class, initiates STS key exchange
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
        # pick p, g and private secret a + public part X=g^a mod p
        p = STS_PRIME
        g = STS_GENERATOR
        a = random.randint(1, p - 1)
        X = pow(g, a, mod=p)

        # send p,q and public keypart
        pgX = f'{p},{g},{X}\n'
        self.writer.write(pgX.encode())

        Ys = await read_line_safe(self.reader)
        log.info(f'received "{Ys}" as Ys (public key & sig server2)')

        if Ys is None:
            self.writer.write('no public key received\n'.encode())
            await self.writer.drain()
            return None

        Y, s = Ys.split(',')
        Y = int(Y)
        if Y >= p:
            self.writer.write(f"Y ({Y}) can't be larger or equal to p ({p})!".encode())
            await self.writer.drain()
            return None

        # calculate shared key
        key = str(pow(Y, a, mod=p))
        key = KDRV256(key.encode())

        # decrypt and verify signature
        decrypted_sig = decrypt(key, s)
        if not verify(bob_public, message=f'{Y},{X}'.encode(), signature=decrypted_sig):
            self.writer.write('Signature verification failed\n'.encode())
            await self.writer.drain()
            return None

        # sign X and Y and send signature
        sig = sign(privKey, f'{X},{Y}'.encode())
        sig = encrypt(key, sig)
        self.writer.write(sig + b'\n')
        await self.writer.drain()

        self.shared_key = key


async def do_session_key_DH_exchange(channel: AuthenticatedChannel) -> bytes | None:
    """
    Receives initial parameters and sends own public keypart.
    All communication is sent over the authenticated channel.
    """
    # receive p,q and public keypart to other server (over the client) and wait for response
    pgX = await channel.recv_encrypted()

    if pgX is None:
        return
    pgX = pgX.decode().rstrip('\n')

    if pgX.count(',') != 2:
        await channel.send_encrypted(
            'Invalid amount of arguments (expected 3; p,g,X)\n'.encode()
        )
        return

    p, g, X = map(int, pgX.split(','))

    # two checks to prevent DOSes and improve performance
    if not check_int_range(p):
        await channel.send_encrypted(f'{p} must be in [{0}..{MAX_PRIME}]'.encode())
        return
    if not check_int_range(g):
        await channel.send_encrypted(f'{g} must be in [{0}..{MAX_PRIME}]'.encode())
        return

    # check if parameters are valid
    if not is_prime(p):
        await channel.send_encrypted(f'{p} is not a prime number!'.encode())
        return

    if not is_primitive_root(g, p):
        await channel.send_encrypted(f'{g} is not a primitive root of {p}!'.encode())
        return

    if X >= p:
        await channel.send_encrypted(f"X ({X} can't be larger or equal to p {p}!".encode())
        return

    # create own public/private key parts:
    b = random.randint(1, p - 1)
    Y = pow(g, b, mod=p)

    await channel.send_encrypted(f'{Y}'.encode())

    # calculate shared key
    key = str(pow(X, b, mod=p))
    key = KDRV256(key.encode())
    return key


async def handle_client(client_reader: StreamReader, client_writer: StreamWriter):
    global primes
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

        msg = 'Hey Bob, plz send me my f14g :-)'
        encrypted_msg = encrypt(session_key, msg.encode())

        await authenticated_channel.send_encrypted(encrypted_msg)

        data = await authenticated_channel.recv_encrypted()
        print('Received data: ', data)
        if data is None:
            return

        decrypted_flag = decrypt(session_key, data.decode())
        print(f'flag: {decrypted_flag}')

    except Exception as e:
        try:
            error = f'something went wrong with the previous message! Error: {e}\n'
            client_writer.write(error.encode())
            await client_writer.drain()
        except Exception:
            return


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
    cmd.add_argument('-p', '--port', type=int, default=20206)
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
