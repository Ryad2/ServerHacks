import socket

# Just some imports you might need
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime

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

    issuer = certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(issuer) == 0 or issuer[0].value != ISSUER_NAME:
        return False


    if certificate.not_valid_before > datetime.utcnow() or certificate.not_valid_after < datetime.utcnow():
        return False


    try:
        san = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        dns_names = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        dns_names = []

    subject_cn = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    subject_cn_val = subject_cn[0].value if subject_cn else ""

    if DOMAIN_NAME not in dns_names and DOMAIN_NAME != subject_cn_val:
        return False


    try:
        ca_pubkey.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm
        )
    except Exception:
        return False

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
