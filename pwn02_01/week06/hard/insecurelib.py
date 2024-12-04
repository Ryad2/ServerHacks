#!/usr/bin/env python3

"""
WARNING: cryptolib only for demonstration purposes
Never use the following crypto functions in any production code!
The code features:
   * Timing side channels
   * Only works for horribly small numbers
   * No permormance at all
"""

import math

from Crypto.Hash import HMAC as realHMAC
from binascii import hexlify, unhexlify
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from random import getrandbits

from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey
from Crypto.Signature import eddsa

# used for the session key exchange where performance matters
MIN_PRIME = 10000
MAX_PRIME = 20000

# for STS key exchange use secure parameters from RFC3526 (group #14): https://www.ietf.org/rfc/rfc3526.txt
STS_GENERATOR = 2
STS_PRIME = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF


def check_int_range(i: int):
    return 0 <= i <= MAX_PRIME


def is_prime(num: int):
    """
    basic primality test for the given number
    """
    # WARNING: horribly insecure example code!

    for j in range(2, int(math.sqrt(num) + 1)):
        if (num % j) == 0:
            return False
    return True


def get_primes(min_prime: int, max_prime: int):
    """
    calculate primes that are in the range [min_prime, max_prime]
    """

    # WARNING: horribly insecure example code!

    # http://stackoverflow.com/questions/2068372/fastest-way-to-list-all-primes-below-n/3035188#3035188
    def primes(n):
        """Returns a list of primes < n"""
        sieve = [True] * n
        for i in range(3, int(n**0.5) + 1, 2):
            if sieve[i]:
                sieve[i * i :: 2 * i] = [False] * ((n - i * i - 1) // (2 * i) + 1)

        return [2] + [i for i in range(3, n, 2) if sieve[i]]

    primes_up_to = primes(max_prime + 1)

    # what takes so long is the debug here
    for p in primes_up_to:
        assert is_prime(p)

    return [p for p in primes_up_to if p >= min_prime]


def primefactors(x: int):
    """
    compute primefactors of a number
    """
    # WARNING: horribly insecure example code!

    factorlist = []
    loop = 2
    while loop <= x:
        if x % loop == 0:
            x /= loop
            factorlist.append(loop)
        else:
            loop += 1
    return factorlist


def primroots(p: int):
    """
    given one prime number, compute all primitive roots of it
    """
    # WARNING: horribly insecure example code!

    g = get_primitive_root(p)  # get first primitive root
    znorder = p - 1
    is_coprime = lambda x: math.gcd(x, znorder) == 1
    good_odd_integers = filter(is_coprime, range(1, p, 2))
    all_primroots = [pow(g, k, mod=p) for k in good_odd_integers]
    all_primroots.sort()
    return all_primroots


def is_primitive_root(g: int, p: int):
    """
    test if DH parameters are correct
    """
    # WARNING: horribly insecure example code!

    phi = p - 1
    for factor in set(primefactors(phi)):
        # if pow(m,int(phi/factor))%p equals one for any prime factor, it isn't a primitive root, otherwise it is
        if pow(g, int(phi / factor), mod=p) == 1:
            return False

    return True


def get_primitive_root(p: int):
    """
    compute a primitive root of a prime p
    """
    # WARNING: horribly insecure example code!

    # p is prime, so phi(p) is p-1
    phi = p - 1

    # check all 2<=g<p if they are a primitive root of p, stop at the first one
    for g in range(2, p):
        is_prim_root = True
        for factor in set(primefactors(phi)):
            # if pow(g,int(phi/factor))%p equals one for any prime factor, it isn't a primitive root, otherwise it is
            if pow(g, int(phi / factor), mod=p) == 1:
                is_prim_root = False
                break

        # if we found one root, stop
        if is_prim_root:
            return g


def KDRV256(b: bytes):
    """
    Key Derivation Function.
    returns a 256-bit key
    """

    h = SHA256.new()
    h.update(b)
    return h.digest()


def HMAC(k: bytes, b: bytes):
    """
    returns: 128-bit MAC
    128-bit MAC is very short but should be enough in comparison with
    those horribly small numbers we use in NetSec
    """
    h = realHMAC.new(k)
    h.update(b)
    return h.digest()


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    key: 256 bit
        first 128 bit for AES
        last 128 bit for MAC
    plaintext: in binary
    returns: IV,ciphertext,MAC
            binary
    """
    # WARNING: horribly insecure example code!
    assert len(key) == 32  # AES-128 + 128-bit MAC

    key_enc = key[:16]
    key_int = key[16:]

    # Cryptographically insecure randomness in IV
    iv = bytes(getrandbits(8) for _ in range(AES.block_size))

    # add padding
    # http://stackoverflow.com/questions/14179784/python-encrypting-with-pycrypto-aes
    padding_length = 16 - (len(plaintext) % 16)
    plaintext += bytes([padding_length]) * padding_length

    # encrypt plaintext
    cipher = AES.new(key_enc, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)

    mac = HMAC(key_int, ciphertext)

    message = hexlify(iv) + b';' + hexlify(ciphertext) + b';' + hexlify(mac)
    return message


def decrypt(key: bytes, message: str) -> bytes:
    """
    key: 256 bit
    message: IV,ciphertext,MAC
            where IV,ciphertext,MAC are hexlified strings
            string
    example: "696e46845a0e69c18747b76fc087d3b5,15...0c,448ca984c4dd3f3454d1f311443802ed"
    returns: decrypted plaintext
            binary
    """
    # WARNING: horribly insecure example code!
    assert len(key) == 32  # AES-128 + 128-bit MAC

    key_enc = key[:16]
    key_int = key[16:]

    assert not message.endswith('\n'), 'message should not end with a newline!'

    try:
        iv, ciphertext, mac = message.split(';')
        iv = unhexlify(iv)
        ciphertext = unhexlify(ciphertext)
        mac = unhexlify(mac)
        assert len(mac) == 16

    except Exception as e:
        raise Exception(f'iv;cipertext;mac not readable in message "{message}": {e}')

    # check MAC
    # TODO: timing side channel? NetSec hint: probably not practically exploitable
    mac_computed = HMAC(key_int, ciphertext)
    if mac_computed != mac:
        raise Exception('MAC verification error')

    # decrypt ciphertext
    cipher = AES.new(key_enc, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    # remove padding
    plaintext = plaintext[: -plaintext[-1]]

    return plaintext


def sign(key: EccKey, message: bytes) -> bytes:
    """
    key: private key
    message: in binary
    returns: signature
    """
    signer = eddsa.new(key, 'rfc8032')
    signature = signer.sign(message)
    return signature


def verify(key: EccKey, message: bytes, signature: bytes) -> bool:
    """
    key: public key
    message: in binary
    signature: in binary
    returns: True if signature is valid
    """
    verifier = eddsa.new(key, 'rfc8032')
    try:
        verifier.verify(message, signature)
        return True
    except ValueError:
        return False


def test():
    assert len(HMAC(b'keyXkeyXkeyXkeyX', 'foobar'.encode())) == 16

    assert len(KDRV256(b'creating long keys from low-entropy input is still weak')) == 32

    assert decrypt(b'keyX' * 8, encrypt(b'keyX' * 8, b'foobar').decode()) == b'foobar'

    assert (
        decrypt(b'keyX' * 8, encrypt(b'keyX' * 8, b'foobar' * 32).decode()) == b'foobar' * 32
    )

    assert (
        decrypt(b'keyX' * 8, encrypt(b'keyX' * 8, b'X' * 16).decode()) == b'XXXXXXXXXXXXXXXX'
    )

    assert decrypt(b'keyX' * 8, encrypt(b'keyX' * 8, b'').decode()) == b''

    key = ECC.generate(curve='ed25519')
    private_key = key
    public_key = key.public_key()
    message = b'hello world'
    signature = sign(private_key, message)
    assert verify(public_key, message, signature)
    assert not verify(public_key, message + b'!', signature)

    print('tests ok')


if __name__ == '__main__':
    test()
