import asyncio
import base64
import hashlib
import logging
import random
import struct
import subprocess
from asyncio import Task, StreamReader, StreamWriter

from Crypto.Cipher import AES

from pwn_utils import utils
from pwn_utils.utils import read_line_safe

log = logging.getLogger(__name__)
clients = {}  # task -> (reader, writer)

DATA: dict[Task, bytes] = {}

DATA_KEY = random.randbytes(16)

COMMAND_KEY = b'u\x12K[\xab\x9e&e\xfcj\x0cQ\x01\xbf\x984'
COMMAND_IV = b'[\xc7\xdcsMMr\xe9\\-\x13@\xb3\xedO\x85'

SALT = bytes.fromhex('42eb477bed55bd203e1a6484406b4e495ea9261cae1826d88ed4c5ea244d6d4a')
PW_HASH = bytes.fromhex(
    '1303f1a8a7a9ece424f6378a9ed645e4cee214cde674c80d1ba9ff0f783ad8a228d758fe1dd7541117c5e83b32805b4aa703d35690de6e97ea45f555e19abd03'
)


def get_pw_hash(password: str) -> bytes:
    return hashlib.scrypt(password.encode(), salt=SALT, n=16384, r=8, p=1)


def get_data(stored_data: bytes, offset: int, length: int) -> bytes:
    if offset >= len(stored_data):
        return b'Offset out of bounds\n'
    return stored_data[offset : offset + length]


# AES-CTR encryption implemented using AES-ECB to generate keystream.
# Not using AES-CTR directly to allow key-stream generation for replacing parts of the data.
def replace_data(stored_data: bytes, offset: int, new_plaintext: bytes) -> bytes:
    first_affected_block = int(offset / AES.block_size)
    last_affected_block = int((offset + len(new_plaintext) - 1) / AES.block_size)
    # calculate keystream used for affected blocks
    keystream = b''
    cipher = AES.new(DATA_KEY, AES.MODE_ECB)
    for block_id in range(first_affected_block, last_affected_block + 1):
        # 8 bytes of 0 and 8 bytes of little endian block id => 16 bytes
        keyblock = struct.pack('<QQ', 0, block_id)
        keystream += cipher.encrypt(keyblock)

    # calculate keystream for precise offset
    key_offset = offset % AES.block_size
    used_keystream = keystream[key_offset : (key_offset + len(new_plaintext))]
    new_cipher = bytes([a ^ b for a, b in zip(new_plaintext, used_keystream)])
    stored_data = (
        stored_data[:offset] + new_cipher + stored_data[(offset + len(new_plaintext)) :]
    )
    return stored_data


def add_data(stored_data: bytes, new_plaintext: bytes) -> bytes:
    # pad plaintext
    new_plaintext += b'*' * (AES.block_size - len(new_plaintext) % AES.block_size)
    new_blocks = int(len(new_plaintext) / AES.block_size)

    last_block = int(len(stored_data) / AES.block_size)
    next_block = last_block + 1 if last_block != 0 else 0
    keystream = b''

    cipher = AES.new(DATA_KEY, AES.MODE_ECB)
    for block_id in range(next_block, next_block + new_blocks + 1):
        keyblock = struct.pack('<QQ', 0, block_id)
        keystream += cipher.encrypt(keyblock)

    new_cipher = bytes([a ^ b for a, b in zip(new_plaintext, keystream)])
    return stored_data + new_cipher


def decrypt_command(command: bytes) -> str:
    return AES.new(COMMAND_KEY, AES.MODE_CBC, iv=COMMAND_IV).decrypt(command).decode()


def store_default_data(task: Task):
    with open('data.txt', 'r') as f:
        data = f.read().encode()
        flag = subprocess.check_output('flag').strip()
        new_stored_data = add_data(b'', data + flag + data)
        DATA[task] = new_stored_data


async def do_password_check(reader: StreamReader, writer: StreamWriter) -> bool:
    writer.write('enter password to replace data\n'.encode())
    password = await read_line_safe(reader)
    if not password:
        return False
    if get_pw_hash(password.strip()) != PW_HASH:
        writer.write('wrong password\n'.encode())
        return False
    return True


async def handle_command(reader: StreamReader, writer: StreamWriter, command_encoded: str):
    current_task = asyncio.current_task()
    if current_task not in DATA:
        store_default_data(current_task)
    stored_data = DATA[current_task]

    command = base64.b64decode(command_encoded)
    if len(command) % AES.block_size != 0:
        writer.write('invalid command length\n'.encode())
        return

    decrypted = decrypt_command(command).lower()
    # security check for replace, as information can be lost
    if 'replace' in decrypted:
        if not (await do_password_check(reader, writer)):
            return
    # remove padding
    decrypted = decrypted.replace('_', '')
    match decrypted.split(' '):
        case ['get', offset, length]:
            data = get_data(stored_data, int(offset), int(length))
            writer.write(b'DATA: ' + data.hex().encode() + b'\n')
        case ['replace', offset, hex_data]:
            data = bytes.fromhex(hex_data)
            new_data = replace_data(stored_data, int(offset), data)
            DATA[current_task] = new_data
            writer.write(b'replaced data\n')
        case ['add', hex_data]:
            data = bytes.fromhex(hex_data)
            new_data = add_data(stored_data, data)
            DATA[current_task] = new_data
            writer.write(b'appended data\n')
        case _:
            print(f'unknown command: {decrypted}')
            writer.write('unknown command\n'.encode())
    return


def accept_client(client_reader: StreamReader, client_writer: StreamWriter):
    task = asyncio.Task(handle_client(client_reader, client_writer))
    clients[task] = (client_reader, client_writer)

    def client_done(task):
        del clients[task]
        client_writer.close()
        log.info('connection closed')

    task.add_done_callback(client_done)


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
        client_writer.write('Welcome to the encrypted storage service\n'.encode())
        while True:
            line = await read_line_safe(client_reader)
            if not line:
                break
            await handle_command(client_reader, client_writer, line.strip())
        return
    except Exception as e:
        utils.log_error(e, client_writer)


def main():
    # start server
    loop = asyncio.get_event_loop()
    f = asyncio.start_server(accept_client, host=None, port=20208)
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
