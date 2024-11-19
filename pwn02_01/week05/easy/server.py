import asyncio
import base64
import hmac
import logging
import random
import subprocess
from asyncio import StreamReader, StreamWriter

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

from pwn_utils import utils

log = logging.getLogger(__name__)
clients = {}  # task -> (reader, writer)

KEY = b'1337133713371337'


def pkcs7(message: bytes, block_size: int = 16) -> bytes:
    gap_size = block_size - (len(message) % block_size)
    return message + bytes([gap_size] * gap_size)


def calc_cbc_mac(message: bytes, iv: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    message = pkcs7(message)
    last_block = cipher.encrypt(message)[-16:]
    return last_block


def calc_hmac(message: bytes, key: bytes) -> bytes:
    return hmac.new(key, message, digestmod='sha256').digest()


def calc_cmac(message: bytes, key: bytes) -> bytes:
    c = CMAC.new(key, ciphermod=AES)
    c.update(message)
    return c.digest()


def check_challenge(challenge: bytes, hmac: bytes, cbc_mac: bytes, cmac: bytes) -> bool:
    return (
        hmac == calc_hmac(challenge, KEY)
        and cbc_mac == calc_cbc_mac(challenge, b'\x00' * 16, KEY)
        and cmac == calc_cmac(challenge, KEY)
    )


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
        challenge = random.randbytes(35)
        client_writer.write(challenge.hex().encode() + b'\n')
        answer = await utils.read_line_safe(client_reader)
        match answer.split(';'):
            case [hmac, cbc_mac, cmac]:
                hmac = base64.b64decode(hmac)
                cbc_mac = base64.b64decode(cbc_mac)
                cmac = base64.b64decode(cmac)
                if check_challenge(challenge, hmac, cbc_mac, cmac):
                    client_writer.write(subprocess.check_output('flag'))
                else:
                    client_writer.write(b'Invalid MACs!')
            case _:
                client_writer.write(b'Invalid input!')

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
    f = asyncio.start_server(accept_client, host=None, port=20105)
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
