import asyncio
import logging
import random
import subprocess
from asyncio import StreamReader, StreamWriter

from pwn_utils import utils

log = logging.getLogger(__name__)
clients = {}  # task -> (reader, writer)


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
        # random bit count to prevent hardcoded primes
        no_bits = random.randint(512, 1024)
        client_writer.write(
            f'Please send a secure public key in the format "e;n" where p and q each have {no_bits} bits\n'.encode()
        )
        await client_writer.drain()
        resp = await utils.read_line_safe(client_reader)
        if not resp:
            return
        match resp.split(';'):
            case [e, n]:
                if not e.isdigit() or not n.isdigit():
                    client_writer.write('Invalid input\n'.encode())
                    await client_writer.drain()
                    return
                e, n = int(e), int(n)
                if not (no_bits * 2 - 1 <= n.bit_length() <= no_bits * 2):
                    client_writer.write('Wrong bit count\n'.encode())
                    await client_writer.drain()
                    return
                flag = subprocess.check_output('flag').decode().strip()
                m = int.from_bytes(flag.encode(), 'big')
                c = pow(m, e, n)
                client_writer.write(f'{c}\n'.encode())
            case _:
                client_writer.write('Invalid input\n'.encode())
                await client_writer.drain()
                return
        return
    except Exception as e:
        utils.log_error(e, client_writer)


def main():
    # start server
    loop = asyncio.get_event_loop()
    f = asyncio.start_server(accept_client, host=None, port=20106)
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
