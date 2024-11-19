import asyncio
import base64
import logging
import random
import subprocess
from asyncio import StreamReader, StreamWriter

from Crypto.Cipher import AES

from pwn_utils import utils

log = logging.getLogger(__name__)
clients = {}  # task -> (reader, writer)

KEY = random.randbytes(16)
FACT_STORE = {
    1: 'Rumors say that the most important secret is secret number 1337',
    2: 'The 6 security goals are Confidentiality, Integrity, Availability, Authenticity, Accountability and Controlled Access.',
    3: 'One of the first Computer Worms was the Morris Worm in 1988 (https://en.wikipedia.org/wiki/Morris_worm).',
    4: 'Cloudflare uses a wall of lava lamps to generate randomness (https://blog.cloudflare.com/lavarand-in-production-the-nitty-gritty-technical-details/).',
}

SECRET_STORE = {
    42: 'Answer to the Ultimate Question of Life, The Universe, and Everything',
}


def pkcs7(message: bytes, block_size: int = 16) -> bytes:
    gap_size = block_size - (len(message) % block_size)
    return message + bytes([gap_size] * gap_size)


def cbc_mac(message: bytes, iv: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    message = pkcs7(message)
    last_block = cipher.encrypt(message)[-16:]
    return last_block


def handle_message(message: bytes, iv: bytes, mac: bytes) -> str:
    kvs = [term.split(b'=') for term in message.split(b'&')]
    args = {key: value for key, value in kvs}
    type = args.get(b'type', b'')
    number = int(args.get(b'number', b'0'))

    expected_mac = cbc_mac(message, iv, KEY)
    if expected_mac != mac:
        if type == b'secrets':
            # don't give any info for secrets
            return 'MAC verification failed'
        return f'MAC verification failed: expected {expected_mac.hex()}, got {mac.hex()}'
    if type == b'funfact':
        return FACT_STORE.get(number, 'No funfact available')
    if type == b'secrets':
        if number == 1337:
            return subprocess.check_output('flag').decode()
        return SECRET_STORE.get(number, 'No secret available')
    return 'Unknown type'


async def handle_client(client_reader: StreamReader, client_writer: StreamWriter):
    try:
        remote = client_writer.get_extra_info('peername')
        if remote is None:
            log.error('Could not get ip of client')
            return
        remote = '%s:%s' % (remote[0], remote[1])
        log.info('new connection from: %s' % remote)
    except Exception as e:
        log.error('EXCEPTION (get peername): %s (%s)' % (e, type(e)))
        return

    try:
        while True:
            message = await utils.read_line_safe(client_reader)
            if message is None:
                return
            match message.split(';'):
                case [m, iv, mac]:
                    m = base64.b64decode(m)
                    iv = base64.b64decode(iv)
                    mac = base64.b64decode(mac)
                    answer = handle_message(m, iv, mac)
                    client_writer.write((answer + '\n').encode())
                    continue
                case _:
                    client_writer.write(
                        'Invalid message, expected format "message;iv;mac"\n'.encode()
                    )
    except Exception as e:
        utils.log_error(e, client_writer)


def accept_client(client_reader: StreamReader, client_writer: StreamWriter):
    task = asyncio.Task(handle_client(client_reader, client_writer))
    clients[task] = (client_reader, client_writer)

    def client_done(task):
        del clients[task]
        client_writer.close()
        log.info('connection closed')

    task.add_done_callback(client_done)


def main():
    # start server
    loop = asyncio.get_event_loop()
    f = asyncio.start_server(accept_client, host=None, port=20205)
    log.info('Server waiting for connections')
    loop.run_until_complete(f)
    loop.run_forever()


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s',
    )

    # "INFO:asyncio:poll took 25.960 seconds" is annyoing
    logging.getLogger('asyncio').setLevel(logging.WARNING)

    main()
