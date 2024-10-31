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

SRC_PORT = 46732 # randrange(10000, 50000)

def generate_syn_cookie(client_ip: str, client_port: int, server_secret: str):
    hash_input = f'{client_ip}{client_port}{server_secret}'.encode()
    return int(hashlib.sha256(hash_input).hexdigest(), 16) % (2**32)

def handle_packet(packet: Packet):
    if packet.haslayer(TCP) and packet[TCP].dport == SRC_PORT:
        if ('S' in packet[TCP].flags):
            #print('received syn&ack')
            #packet[TCP].show()
            iseq = packet[TCP].seq
            iack = packet[TCP].ack
            ip = IP(dst=SERVER_IP)
            oack = TCP(
                sport=SRC_PORT,
                dport=SERVER_PORT,
                flags='A',
                seq=iack,
                ack=iseq,
            )
            #print('send ack')
            #oack.show()
            send(ip/oack)
        else:
            #print('received ack:')
            #packet[TCP].show()
            #print('result:')
            print(packet.payload.payload.payload.load)
    #elif packet.haslayer(TCP) and packet[TCP].sport == SRC_PORT:
        #print('sending:')
        #packet[TCP].show()
        

# Function to start the packet sniffing
def start_sniffing():    
    sniff(
        filter=f'tcp port {SERVER_PORT}', # this should filter all packets relevant for this challenge.
        prn=handle_packet,
        store=False,
        monitor=True,
        iface='enX0', # set to your interface. IMPORTANT: SET TO enX0 FOR AUTOGRADER!!!
    )

COOKIE = generate_syn_cookie(SERVER_IP, SERVER_PORT, COOKIE_SECRET)

# Run the server in a separate thread
def main():
    conf.use_pcap = False
    server_thread = threading.Thread(target=start_sniffing)
    server_thread.start()

    time.sleep(1) # wait for the sniffer to start.

    ip = IP(
        dst=SERVER_IP,
    )
    osyn = TCP(
        sport=SRC_PORT,
        dport=SERVER_PORT,
        flags='S',
        seq=COOKIE,
        ack=0,
    )
    send(ip/osyn)


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s',
    )

    logging.getLogger('asyncio').setLevel(logging.WARNING)

    main()          
