import asyncio
import subprocess
import random
import binascii
import struct
import logging
import json

HARDNESS = 300

MESSAGE_FILES: dict[str, bool] = json.load(open('message_file_correctness.json'))
# MESSAGE_FILES = {
#     "some_trace.txt": True,  # REDACTED
#     "some_faulty_trace.txt": False,  # REDACTED
# }

log = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s ' '[%(module)s:%(lineno)d] %(message)s',
)

client_count = 0


def log_client(client, client_id):
    try:
        remote = client.get_extra_info('peername')
        if remote is None:
            log.error(f'[{client_id}] Could not get ip of client.')
            return

        log.info(f'[{client_id}] New connection from: {remote[0]}:{remote[1]}')
    except Exception:
        log.exception(f'[{client_id}] Could not get peername.')
        return


msgs: list[tuple[list[str], bool]] = []
for fn, c in MESSAGE_FILES.items():
    with open(fn) as f:
        msgs.append((f.read().split('\n\n'), c))


class DNSSecOracle(asyncio.Protocol):
    def __init__(self):
        self.client_id = 0
        self.state = 0
        self.transport = None
        self.next_correct: bool = True
        self.correct = 0
        self.first_wrong: int | None = None

    def connection_made(self, transport):
        self.client_id = client_count
        self.state = 0
        self.transport = transport
        self.next_correct = True
        self.correct = 0

        log_client(self.transport, self.client_id)

        self.send_challenge()

    def check_response(self, answer: bool):
        return answer == self.next_correct

    def generate_challenge(self):
        msg: tuple[list[str], bool] = random.choice(msgs)
        chall_sel, corr = msg

        if corr and random.random() > 0.5:
            chall = chall_sel.copy()
            ind_del = random.randrange(0, len(chall) - 1)
            del chall[ind_del]  # Uh oh, some hacker must have dropped a message :O
            self.next_correct = False
        else:
            chall = chall_sel
            self.next_correct = corr

        return binascii.hexlify('\n\n'.join(chall).encode())

    def send_challenge(self):
        data = self.generate_challenge()
        datalen = struct.pack('>I', len(data))
        self.transport.write(datalen + data)

    def data_received(self, data: bytes):
        if not len(data) == 1:
            self.transport.close()
            return

        response: bool = bool(data[0])
        print(f'{response=}, {type(response)=}')
        if self.check_response(response):
            self.correct += 1
        elif self.first_wrong is None:
            self.first_wrong = self.state

        self.state += 1

        if self.state == HARDNESS:
            if self.correct == HARDNESS:
                flag = subprocess.check_output('/bin/flag')
                self.transport.write(flag)
            else:
                self.transport.write(
                    (
                        f'There must have been an error somewhere :< You had {self.correct}/{HARDNESS} correct! '
                        f'Your first wrong answer was at index {self.first_wrong}!'
                    ).encode()
                )
            self.transport.close()
        else:
            self.send_challenge()


def start_server():
    global client_count

    client_count += 1
    return DNSSecOracle()


async def main():
    loop = asyncio.get_running_loop()

    server = await loop.create_server(lambda: start_server(), None, 20210)

    async with server:
        await server.serve_forever()


asyncio.run(main())
