import base64
import socket
import hashlib
import random

from Crypto.Cipher import AES

# Fill in the right target here
HOST = 'netsec.net.in.tum.de'
PORT = 20208

COMMAND_KEY = b'u\x12K[\xab\x9e&e\xfcj\x0cQ\x01\xbf\x984'
COMMAND_IV = b'[\xc7\xdcsMMr\xe9\\-\x13@\xb3\xedO\x85'
SALT = bytes.fromhex('42eb477bed55bd203e1a6484406b4e495ea9261cae1826d88ed4c5ea244d6d4a')
PW_HASH = bytes.fromhex(
    '1303f1a8a7a9ece424f6378a9ed645e4cee214cde674c80d1ba9ff0f783ad8a228d758fe1dd7541117c5e83b32805b4aa703d35690de6e97ea45f555e19abd03'
)

max_data_length = 1000000000000000000000000000000000000000

def debug(x):
    #print(x)
    pass

def encrypt_command(command: str) -> str:
    padded = command + '_' * (AES.block_size - len(command) % AES.block_size)
    cipher = AES.new(COMMAND_KEY, AES.MODE_CBC, iv=COMMAND_IV)
    encrypted = cipher.encrypt(padded.encode())
    return base64.b64encode(encrypted).decode()


def reverse_add_data(ciphered_data: bytes, data_key: bytes) -> bytes:
    from Crypto.Cipher import AES
    import struct

    # Nombre de blocs ajoutés
    new_blocks = len(ciphered_data) // AES.block_size

    # Génération du keystream
    cipher = AES.new(data_key, AES.MODE_ECB)
    keystream = b''
    # next_block = 0 car stored_data était vide
    for block_id in range(0, new_blocks + 1):
        keyblock = struct.pack('<QQ', 0, block_id)
        keystream += cipher.encrypt(keyblock)

    # XOR pour récupérer le plaintext avec padding
    padded_plaintext = bytes(a ^ b for a, b in zip(ciphered_data, keystream))

    # Retrait du padding '*'
    # Le padding se trouve à la fin, on supprime les '*' à la fin de la chaîne
    plaintext = padded_plaintext.rstrip(b'*')
    return plaintext


def guess_password():
    # Brute force password
    # cost parameter 2 ** n
    ne = 16384
    # exact log2
    for i in range(0,32):
        if ne == 2 ** i:
            n = i
            break
    # block size
    r = 8
    # parallelism parameter
    p = 1
    # salt
    s = SALT
    s64 = base64.b64encode(s[:32]).decode()
    # scrypt checksum
    h = hashlib.scrypt("password".encode(), salt=s, n=ne, r=r, p=p)
    h64 = base64.b64encode(h[:32]).decode()
    # scrypt format
    scrypt= f"SCRYPT:{n}:{r}:{p}:{s64}:{h64}"
    debug('Hash: ' + str(scrypt))
    with open('hash', 'w') as hf:
        hf.write(scrypt)
    # externally guess password from hash was not feasible
    with open('password', 'r') as pf:
        password = pf.read()
    debug('Password: ' + str(password))
    return password


def get_flag():
    password = '' #guess_password()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((HOST, PORT))
    sf = s.makefile('rw')  # we use a file abstraction for the sockets

    def write(m):
        sf.write(m + '\n')
        sf.flush()
        debug('Wrote: ' + str(m))
    def read():
        sf.flush()
        ln = sf.readline().rstrip('\n')
        debug('Got: ' + str(ln))
        return ln
    def cmd_get(f:int = 0, t:int = max_data_length) -> str:
        return encrypt_command(f'get {f} {t}')
    def cmd_replace(f:int = 0, d:bytes = bytes(0)) -> str:
        return encrypt_command(f'replace {f} {d.hex()}')
    def cmd_replace_obfuscated(f:int = 0, d:bytes = bytes(0)) -> str:
        return encrypt_command(f'r_e_p_l_a_c_e {f} {d.hex()}')
    def cmd_add(d:bytes = bytes(0)) -> str:
        return encrypt_command(f'add {d.hex()}')
    def get(f:int = 0, t:int = max_data_length) -> bytes:
        debug(f'Get from {f} to {t}')
        write(cmd_get(f,t))
        return bytes.fromhex(read().lstrip('DATA: '))
    def replace(f:int = 0, d:bytes = bytes(0), p = password):
        debug(f'Replace from {f} using password {p} with {d}')
        write(cmd_replace(f,d))
        if 'enter password to replace data' == read():
            write(p)
            read()
    def replace_obfuscated(f:int = 0, d:bytes = bytes(0), password_on_hack_fail = password):
        debug(f'Replace from {f} using hack with {d}')
        write(cmd_replace_obfuscated(f,d))
        if 'enter password to replace data' == read():
            debug('Obfuscating failed to ignore password check')
            write(password_on_hack_fail)
            read()
    def add(d:bytes = bytes(0)):
        print(f'Add {d}')
        write(cmd_add(d))
        read()


    # multiple solutions possible
    SEND_STRATEGIES = ['SEND ZERO', 'SEND DATA']
    SEND_STRATEGY = random.choice(SEND_STRATEGIES)


    msg_welcome = read()

    # get data containing encrypted flag
    containing_encrypted_flag = get()

    if SEND_STRATEGY == 'SEND ZERO':
        # replace all data with 0
        toSend = bytes(len(containing_encrypted_flag))
    if SEND_STRATEGY == 'SEND DATA':
        # re-encrypt data using symmetric method
        toSend = containing_encrypted_flag
    
    # obfuscate command to use replace without password
    replace_obfuscated(d= toSend)

    # get all data again
    got = get()
    
    if SEND_STRATEGY == 'SEND ZERO':
        # 0 xor encryption_stream = encryption_stream
        encryption_stream = got
        # encrypted xor encryption_stream = data
        containing_flag = bytes([a ^ b for a, b in zip(containing_encrypted_flag, encryption_stream)])
    if SEND_STRATEGY == 'SEND DATA':
        # server decrypted for us
        # newdata = encrypt (data xor encryption_stream) = data xor encryption_stream xor encryption_stream = data
        containing_flag = got

    flag_position = containing_flag.find(b'flag')
    flag = containing_flag[flag_position : flag_position + 42]
    print(flag.decode())

    sf.close()
    s.close()


if __name__ == '__main__':
    get_flag()
