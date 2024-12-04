from Crypto.PublicKey import ECC


def generate_keys() -> tuple[str, str]:
    key = ECC.generate(curve='ed25519')
    private_key = key.export_key(format='PEM')
    public_key = key.public_key().export_key(format='PEM')
    return private_key, public_key


def write_keys(name: str, private_key: str, public_key: str):
    with open(f'{name}_private.pem', 'wb') as f:
        f.write(private_key.encode())
    with open(f'{name}_public.pem', 'wb') as f:
        f.write(public_key.encode())


if __name__ == '__main__':
    privA, pubA = generate_keys()
    privB, pubB = generate_keys()
    write_keys('alice', privA, pubA)
    write_keys('bob', privB, pubB)
    print('Keys generated and written to files')
