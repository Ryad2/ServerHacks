import socket

# Just some imports you might need
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives.asymmetric import padding

# Fill in the right target here
HOST = 'netsec.net.in.tum.de'
PORT = 20108

DOMAIN_NAME = "exzellenteforschung.de"
ISSUER_NAME = "Nolan Nets CA"
ITERATIONS = 100

with open("ca.pem", 'rb') as pem_in:
    ca_cert = x509.load_pem_x509_certificate(pem_in.read())
    ca_pubkey = ca_cert.public_key()


def validate_certificate(certificate):
    # ToDo: please implement me!
    return True


def get_flag():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((HOST, PORT))
    sf = s.makefile('rw')  # we use a file abstraction for the sockets
    print(sf.readline().strip())

    for _ in range(ITERATIONS):
        try:
            m = sf.readline().rstrip('\n')
            m_decode = bytes.fromhex(m)
            cert = x509.load_pem_x509_certificate(m_decode)
            correct = validate_certificate(cert)
        except ValueError:
            print(m)
            return            
        
        print(f"Sending {correct}")
        sf.write(f'{correct}\n')
        sf.flush()
        
    flag = sf.readline().rstrip('\n')
    print(f"Flag: {flag}")

    sf.close()
    s.close()


if __name__ == '__main__':
    get_flag()
