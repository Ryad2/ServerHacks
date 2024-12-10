import base64
import socket

from Crypto.Cipher import AES

# Fill in the right target here
HOST = 'netsec.net.in.tum.de'
PORT = 20208

COMMAND_KEY = b'u\x12K[\xab\x9e&e\xfcj\x0cQ\x01\xbf\x984'
COMMAND_IV = b'[\xc7\xdcsMMr\xe9\\-\x13@\xb3\xedO\x85'


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


def get_flag():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((HOST, PORT))
    sf = s.makefile('rw')  # we use a file abstraction for the sockets

    message1 = sf.readline().rstrip('\n')
    print(message1)
    sf.flush()
    sf.write(encrypt_command("add 3371f6ba154693185cc3e5aac70ed1009a002cfa671e5c65a61103a94a857b3f313dcc52196652edc5b67b2b66646c6bb239ba0082d382abb20adf1fd0ce077432c0474fea8e5d62b391fd07b3f4c422f0531d37680006ed377eac814e38aa45fe94b7d916d9af4f3d10a9d957ad508f7cb453b36e75160898e39f7020874dd85057ed8a9e4c25b99436e4ebec7b344c31572da46fff680db7d52697f706e0709891abaa265e56017fd6771c8150606bca6a064a3031a6746f011d01c6b1f48503f78f76a04f213aa4b1cc8eee85e4ae48b4b2546ec839b29f780473975f3a575bf7187f5ac3457a0651d8b5151b2be4") + "\n")
    sf.flush()
    message2 = sf.readline().rstrip('\n')
    print(message2)





    sf.flush()
    sf.write(encrypt_command("get 0 1000000000000000000000000000000000000000") + "\n")
    sf.flush()
    message2 = sf.readline().rstrip('\n')
    print(message2)
    table = bytes.fromhex(message2[6:])
    print(table)

    3371f6ba154693185cc3e5aac70ed1009a002cfa671e5c65a61103a94a857b3f313dcc52196652edc5b67b2b66646c6bb239ba0082d382abb20adf1fd0ce077432c0474fea8e5d62b391fd07b3f4c422f0531d37680006ed377eac814e38aa45fe94b7d916d9af4f3d10a9d957ad508f7cb453b36e75160898e39f7020874dd85057ed8a9e4c25b99436e4ebec7b344c31572da46fff680db7d52697f706e0709891abaa265e56017fd6771c8150606bca6a064a3031a6746f011d01c6b1f48503f78f76a04f213aa4b1cc8eee85e4ae48b4b2546ec839b29f780473975f3a575bf7187f5ac3457a0651d8b5151b2be4
    3371f6ba154693185cc3e5aac70ed1009a002cfa671e5c65a61103a94a857b3f313dcc52196652edc5b67b2b66646c6bb239ba0082d382abb20adf1fd0ce077432c0474fea8e5d62b391fd07b3f4c422f0531d37680006ed377eac814e38aa45fe94b08b468cfc196a47ac8e59f8538d7fbc54e969771d0e9ebbc92422d446df0c56ec89cd1f25b99436e4ebec7b344c31572da46fff680db7d52697f706e0709891abaa265e56017fd6771c8150606bca6a064a3031a6746f011d01c6b1f48503f78f76a04f213aa4b1cc8eee85e4ae48b4b2546ec839b29f780473975f3a575bf7187f5ac3457a0651d8b5151b2be4
    0019f0778f12f2b6e0bd0e0b780671d439c026ddf05055f619a1518fd4b8baff9fca29ec89912e01d6178d5f0fe48709e0f35ecb3835c895df4ad0424c429b6ef434fccc100b09fe35d8ae09a229f71d32607013d580fabd94ece3b458b253a42c4a73780b04575524f52389e37b01a3034d85b04f9cde84c7fa5fb190b3bc4db199df58adcb11de053ada719c698256f26ee291789800cccd33033f361827cc15cfa06c2ca0360e4f32787394155ccff1a258e2396366dabb3dc0c65f58346d0f9f7e03cc97b307c275f07b7c39f2ecb613ff1b3ffdb8794fdf77fbc6fa243ea551c5c8134b0589319d7bfe2aa2dc986ba1ed4c0bcf49b8cb17911cb5504aa1


    sf.close()
    s.close()


if __name__ == '__main__':
    get_flag()
