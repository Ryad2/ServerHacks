import argparse
import asyncio
import logging
import random
import string
import subprocess
from hashlib import scrypt

from pwn_utils import utils
from pwn_utils.utils import log_error

log = logging.getLogger(__name__)
clients = {}  # task -> (reader, writer)
random_passwords = {}  # task  -> [passwords]
client_count = 0

password_store: dict[str, list[bytes]] = {
    'admin': [
        # example values
        b'\x1cJ\xaa\x88\x18\x0b7Sp\x0bJ\xef\x19\xf9\xdaw\xd3\x94\x027\xe9\xd7\xe5\x12\xbb7u\xbb\xc2\xa6kfQ\xb4\xcci\x05%3\xab\xce\x9ex\x0c:\xfb72\x86\xad\xc3|^\xdf\xebG\xbb@x\x04K~d\xf4',
        b'\x98\xf4\x11"\xffP\x80\xd8\x87\x7fi\x97j\x95E\xb2\x94\xb3\x80\x98c\n\xdc\xc7"\xcd\xa0\x85\xf2n\xe1\x86H\xe1\x81\x93\t%)U/\xb7\xadm\x95\xbf\xb5\x7f\x11\xd4\x99\x1e\xd5Sq\xabJ\xcf\xd2\x03o \xc2*',
        b'\x07\x03\xd7\x9a:\xc9\x9c:SD\xa3||\x976j\xbf;\xf1"\t\xf2\xa1\x1d\xc2K\x06\x9fI\xd9\xf2\xbe\xfa\xee\xcdbd\xf9\xcc\x17\xd4\x13`:QT\xee\x05\xa1ER\x18h\xa5\x17\xffI\xf5=\x12\xa6\x0c.*',
        b'\x1c\xb6B\xe1\xf6\x90\xc5i\xb7W\xe1\xec~\xec\xe8\xb9h\xfbSucYK\xb17D\xa2\x87\x1d\x8e\xb9\x01f]6\xc1\xdfX3\x813~F\x81T\x99[\x8b\x98\xf5\x94\xf4\\\xea}[$8M\x16\x05\xc5\x1bt',
    ]
}

allowed_characters = set(string.ascii_letters + string.digits + '!#;')

Failure = str
Success = bool

Result = Success | Failure


def calc_hashes(passwords: list[str], username: str) -> list[bytes]:
    return [
        scrypt(password.encode(), salt=username.encode(), n=16384, r=4, p=1)
        for password in passwords
    ]


def store_passwords(passwords: str, username: str) -> Result:
    if not set(passwords) <= allowed_characters:
        return 'Invalid characters in password'
    passwords = passwords.split(';')
    hashes = calc_hashes(passwords, username)
    password_store[username] = hashes
    return True


def check_passwords(passwords: str, username: str) -> Result:
    if username not in password_store:
        return 'Unknown user'
    if not set(passwords) <= allowed_characters:
        return 'Invalid characters in password'
    passwords = passwords.split(';')
    hashes = calc_hashes(passwords, username)
    stored = random_passwords[asyncio.current_task()]
    if stored != hashes:
        return f'Passwords do not match hashes {[h.hex() for h in password_store[username]]}'
    return True


async def read_username_and_passwords(client_reader, client_writer) -> tuple[str, str] | None:
    client_writer.write('Please enter username:\n'.encode())
    await client_writer.drain()
    username = await utils.read_line_safe(client_reader)
    client_writer.write('Please enter passwords:\n'.encode())
    passwords = await utils.read_line_safe(client_reader)
    if not username or not passwords:
        client_writer.write('Invalid input\n'.encode())
        await client_writer.drain()
        return
    return username, passwords


async def handle_register(client_reader, client_writer):
    username, passwords = await read_username_and_passwords(client_reader, client_writer)
    if not username or not passwords:
        return
    if username in password_store:
        client_writer.write('User already exists\n'.encode())
        await client_writer.drain()
        return
    res = store_passwords(passwords, username)
    if isinstance(res, Failure):
        client_writer.write(f'Error: {res}\n'.encode())
        await client_writer.drain()
        return
    client_writer.write('Passwords stored\n'.encode())
    await client_writer.drain()
    return


async def handle_get_secret(client_reader, client_writer) -> bool:
    username, passwords = await read_username_and_passwords(client_reader, client_writer)
    if not username or not passwords:
        return False
    if username != 'admin':
        client_writer.write('Missing permission to access secret\n'.encode())
        await client_writer.drain()
        return False
    res = check_passwords(passwords, username)
    if isinstance(res, Failure):
        client_writer.write(
            f'Passwords do not match hashes {[h.hex() for h in random_passwords[asyncio.current_task()]]}\n'.encode()
        )
        await client_writer.drain()
        return False
    secret = subprocess.check_output('flag').decode()
    client_writer.write(f'Secret: {secret}\n'.encode())
    await client_writer.drain()
    return True


def generate_passwords():
    passwords = [f'{"".join(random.sample(string.ascii_lowercase, 3))}123' for _ in range(5)]
    print(passwords)
    return calc_hashes(passwords, 'admin')


def accept_client(client_reader, client_writer, loop):
    global client_count

    client_id = client_count
    client_count += 1
    pws = generate_passwords()
    print([pw.hex() for pw in pws])
    task = loop.create_task(handle_client(client_reader, client_writer, client_id))
    random_passwords[task] = pws
    clients[task] = (client_reader, client_writer)

    def client_done(task):
        del clients[task]
        client_writer.close()
        log.info('[%d] connection closed' % client_id)

    task.add_done_callback(client_done)


async def handle_client(client_reader, client_writer, client_id):
    try:
        remote = client_writer.get_extra_info('peername')
        if remote is None:
            log.error('Could not get ip of client')
            return

        remote = '%s:%s' % (remote[0], remote[1])
        log.info('[%d] new connection from: %s' % (client_id, remote))
    except Exception:
        log.exception('get peername failed')
        return

    try:
        client_writer.write(
            'Please send command! Available commands: REGISTER and GET_SECRET\n'.encode()
        )
        await client_writer.drain()
        command = await utils.read_line_safe(client_reader)
        match command:
            case 'REGISTER':
                await handle_register(client_reader, client_writer)
            case 'GET_SECRET':
                success = await handle_get_secret(client_reader, client_writer)
                while not success:
                    success = await handle_get_secret(client_reader, client_writer)
            case _:
                client_writer.write('Invalid command\n'.encode())
                await client_writer.drain()
                return

    except Exception as e:
        log_error(e, client_writer)


def main():
    cmd = argparse.ArgumentParser()
    cmd.add_argument('-p', '--port', type=int, default=20204)
    args = cmd.parse_args()

    # start server
    loop = asyncio.get_event_loop()
    f = asyncio.start_server(lambda r, w: accept_client(r, w, loop), host=None, port=args.port)
    log.info('starting to listen on port %d...' % args.port)
    loop.run_until_complete(f)
    log.info('server waiting for connections...')

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s ' '[%(module)s:%(lineno)d] %(message)s',
    )
    main()
