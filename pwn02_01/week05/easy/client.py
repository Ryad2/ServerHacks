
import socket
import base64

import hashlib


from Crypto.Cipher import AES




# Fill in the right target here
HOST = 'netsec.net.in.tum.de'  # TODO
PORT = 20105  # TODO
KEY = b'1337133713371337'

IV = b'\x00' * 16




def pkcs7(message: bytes, block_size: int = 16) -> bytes:
    padding_len = block_size - (len(message) % block_size)
    padding = bytes([padding_len] * padding_len)
    return message + padding

def calc_cbc_mac_reference(message: bytes, iv: bytes, key: bytes) -> bytes:
    # Vérification des types et des longueurs de clé et IV
    assert isinstance(key, bytes) and len(key) in (16, 24, 32), "La clé doit être de 16, 24 ou 32 octets"
    assert isinstance(iv, bytes) and len(iv) == 16, "L'IV doit être de 16 octets"

    # Application du padding PKCS#7
    padded_message = pkcs7(message, block_size=16)

    # Création du chiffreur AES en mode CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Chiffrement du message paddé
    ciphertext = cipher.encrypt(padded_message)

    # Le CBC-MAC est le dernier bloc du ciphertext
    cbc_mac = ciphertext[-16:]

    return cbc_mac





def calc_hmac_reference(message: bytes, key: bytes) -> bytes:
    # Taille du bloc pour SHA-256
    block_size = 64  # 512 bits

    # Si la clé est plus longue que le bloc, on la hache
    if len(key) > block_size:
        key = hashlib.sha256(key).digest()

    # Si la clé est plus courte que le bloc, on la complète avec des zéros
    if len(key) < block_size:
        key = key.ljust(block_size, b'\x00')

    # Création des paddings interne et externe
    o_key_pad = bytes((x ^ 0x5C) for x in key)  # 0x5C = 92 en décimal
    i_key_pad = bytes((x ^ 0x36) for x in key)  # 0x36 = 54 en décimal

    # Calcul du haché interne
    inner_hash = hashlib.sha256(i_key_pad + message).digest()

    # Calcul du haché externe
    hmac_result = hashlib.sha256(o_key_pad + inner_hash).digest()

    return hmac_result











def calc_cmac_reference(message: bytes, key: bytes) -> bytes:
    def xor_bytes(a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    def left_shift(bit_string):
        shifted = int.from_bytes(bit_string, byteorder='big') << 1
        shifted &= (1 << 128) - 1  # Assure que c'est sur 128 bits
        return shifted.to_bytes(16, byteorder='big')

    # Constante pour AES (polynôme irréductible)
    const_Rb = bytes.fromhex('00000000000000000000000000000087')

    # Étape 1: Générer les sous-clés K1 et K2
    zero_block = bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    L = cipher.encrypt(zero_block)

    def generate_subkey(K):
        if (K[0] & 0x80):  # Si MSB == 1
            subkey = left_shift(K)
            subkey = xor_bytes(subkey, const_Rb)
        else:
            subkey = left_shift(K)
        return subkey

    K1 = generate_subkey(L)
    K2 = generate_subkey(K1)

    # Étape 2: Préparer le message
    block_size = 16  # 128 bits pour AES
    n = (len(message) + block_size - 1) // block_size  # Nombre de blocs

    if n == 0:
        n = 1
        flag = False
    else:
        if (len(message) % block_size) == 0:
            flag = True  # Dernier bloc complet
        else:
            flag = False  # Dernier bloc incomplet

    # Découper le message en blocs
    blocks = [message[i*block_size:(i+1)*block_size] for i in range(n)]

    # Étape 3: Gérer le dernier bloc
    if flag:
        # Bloc complet, on XOR avec K1
        M_last = xor_bytes(blocks[-1], K1)
    else:
        # Bloc incomplet, padding et XOR avec K2
        padding_len = block_size - len(blocks[-1])
        padding = bytes([0x80] + [0x00]*(padding_len - 1))
        M_last = xor_bytes(blocks[-1] + padding, K2)

    # Étape 4: Calculer le CMAC
    cipher = AES.new(key, AES.MODE_ECB)
    X = bytes(16)  # Chaînage initial

    for i in range(n - 1):
        X = cipher.encrypt(xor_bytes(X, blocks[i]))

    X = cipher.encrypt(xor_bytes(X, M_last))

    return X  # Le CMAC est le dernier bloc chiffré




def get_flag():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    sf = s.makefile('rw')  # we use a file abstraction for the sockets

    message1 = sf.readline().rstrip('\n')
    #print(message1)
    message1 = bytes.fromhex(message1)
    answer = f'{base64.b64encode(calc_hmac_reference(message1, KEY)).decode()};{base64.b64encode(calc_cbc_mac_reference(message1,IV, KEY)).decode()};{base64.b64encode(calc_cmac_reference(message1, KEY)).decode()}'
    #print(answer)
    sf.write(answer + '\n')
    sf.flush()
    print(sf.readline().rstrip('\n'))

    sf.close()
    s.close()


if __name__ == '__main__':
    get_flag()
