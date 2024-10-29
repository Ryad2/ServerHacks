import hashlib
import logging
import time

import threading

from scapy.config import conf
from scapy.layers.inet import TCP, IP
from scapy.packet import Packet
from scapy.sendrecv import send, sniff

from random import randrange

log = logging.getLogger(__name__)
TCP_CLIENTS = {}  # ((IP, port) -> [sent_packets])

SERVER_IP = '131.159.15.68' # don't use the domain name in this case
SERVER_PORT = 20102
COOKIE_SECRET = 'TASTY_COOKIES123'

SRC_PORT = randrange(10000, 50000)

def generate_syn_cookie(client_ip: str, client_port: int, server_secret: str):
    # TODO: please implement me!
    return 0


def handle_packet(packet: Packet):
    # TODO: please implement me!
    packet.show()

# Function to start the packet sniffing
def start_sniffing():    
    sniff(
        filter=f'tcp port {SERVER_PORT}', # this should filter all packets relevant for this challenge.
        prn=handle_packet,
        store=False,
        monitor=True,
        iface='eth0', # set to your interface. IMPORTANT: SET TO enX0 FOR AUTOGRADER!!!
    )

COOKIE = generate_syn_cookie(SERVER_IP, SERVER_PORT, COOKIE_SECRET)

# Run the server in a separate thread
def main():
    conf.use_pcap = False
    server_thread = threading.Thread(target=start_sniffing)
    server_thread.start()

    time.sleep(1) # wait for the sniffer to start.

    # TODO: send intial first byte 


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s',
    )

    logging.getLogger('asyncio').setLevel(logging.WARNING)

    main()
