import hashlib
import logging
import subprocess

import threading

from scapy.config import conf
from scapy.layers.inet import TCP, IP
from scapy.packet import Packet
from scapy.sendrecv import send, sniff

log = logging.getLogger(__name__)
TCP_CLIENTS = {}  # ((IP, port) -> [sent_packets])

SERVER_IP = '131.159.15.68'  # TODO
SERVER_PORT = 20102
COOKIE_SECRET = 'TASTY_COOKIES123'
INITIAL_SEQ = 1337


# The cookie is calculated by first taking the sha256 hash of (clientIP || clientPort || serverSecret) and then
# converting the hex digest to an integer
# The cookie is then this result modulo 2^32 to fit the 32-bit field
def generate_syn_cookie(client_ip: str, client_port: int, server_secret: str):
    hash_input = f'{client_ip}{client_port}{server_secret}'.encode()
    return int(hashlib.sha256(hash_input).hexdigest(), 16) % (2**32)


def get_initial_syn(ip, port, ack) -> Packet:
    ip = IP(dst=ip)
    syn = TCP(sport=SERVER_PORT, dport=port, flags='SA', seq=INITIAL_SEQ, ack=ack)
    return ip / syn


def get_rst(ip, port, ack) -> Packet:
    ip = IP(dst=ip)
    syn = TCP(sport=SERVER_PORT, dport=port, flags='R', seq=INITIAL_SEQ, ack=ack)
    return ip / syn


def handle_packet(packet: Packet):
    if packet.haslayer(TCP) and packet[TCP].dport == SERVER_PORT:
        if 'F' in packet[TCP].flags or 'R' in packet[TCP].flags:
            print('Received FIN or Reset packet:', packet.summary())
            if (packet[IP].src, packet[TCP].sport) in TCP_CLIENTS:
                del TCP_CLIENTS[(packet[IP].src, packet[TCP].sport)]
            return
        
        print('Received packet:', packet.summary())
        
        # Extract the TCP layer
        tcp_layer = packet[TCP]
        src_ip = packet[IP].src
        src_port = tcp_layer.sport
        seq = packet[TCP].seq
        ack = packet[TCP].ack
        
        expected_cookie = generate_syn_cookie(SERVER_IP, SERVER_PORT, COOKIE_SECRET)
        
        if (src_ip, src_port) not in TCP_CLIENTS:
            print('New client:', src_ip, src_port, seq)
            # first packet from client to initiate handshake
            
            
            if (not 'S' in packet[TCP].flags) or (not packet[TCP].seq == expected_cookie):
                print(f'Invalid cookie {seq}, expected {expected_cookie}')
                rst = get_rst(src_ip, src_port, seq)
                send(rst)
            else:    
                TCP_CLIENTS[(src_ip, src_port)] = 1
                initial_syn = get_initial_syn(src_ip, src_port, seq)
                
                print(f'Cookie {expected_cookie} and packet is correct')
                print(f'Sending packet: {initial_syn.summary()}')
                send(initial_syn)
        
        else:
            if ('S' in packet[TCP].flags) or (not seq == expected_cookie) or (not ack == INITIAL_SEQ):
                print(f'Invalid cookie {seq}, expected {expected_cookie}')
                rst = get_rst(src_ip, src_port, seq)
                send(rst)
            else:
                print(f'Cookie {expected_cookie} and packet is again correct')
                
                flag = subprocess.check_output('flag').decode()
                ip = IP(dst=src_ip)
                syn_ack = TCP(
                    sport=SERVER_PORT,
                    dport=src_port,
                    flags='A',
                    seq=ack,
                    ack=seq,
                ) / flag
                
                send(ip / syn_ack)
            
            del TCP_CLIENTS[(src_ip, src_port)]


# Function to start the packet sniffing
def start_sniffing():
    print('Starting TCP server on port:', SERVER_PORT)
    sniff(
        filter=f'tcp port {SERVER_PORT}',
        prn=handle_packet,
        store=False,
        monitor=True,
        iface='enX0',
    )


# Run the server in a separate thread
def main():
    conf.use_pcap = False
    server_thread = threading.Thread(target=start_sniffing)
    server_thread.start()


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s',
    )

    # "INFO:asyncio:poll took 25.960 seconds" is annyoing
    logging.getLogger('asyncio').setLevel(logging.WARNING)

    main()
