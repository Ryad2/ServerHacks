import json
import socket
import string
import itertools
from hashlib import scrypt

HOST = 'netsec.net.in.tum.de'
PORT = 20204

ENTER_USERNAME = 'Please enter username:'
ENTER_PASSWORD = 'Please enter passwords:'
LOGIN_SYNTAX_FAIL = 'Invalid input'
LOGIN_INVALID_PASSWORD_START = 'Passwords do not match hashes '
USERNAME = 'admin'
ENTER_ACTION = 'Please send command! Available commands: REGISTER and GET_SECRET'
GET_SECRET = 'GET_SECRET'
PASSWORD_CHARACTERS = set(string.ascii_letters + string.digits + '!#;')

#possible_passwords = [''.join(i) + '123' for i in itertools.product(string.ascii_letters, repeat=3)]
TEST_HASHES = ['60472ad202dce92d5b5b1ade3f1863136e99c6368f72024c719f4997eecd0e3127529f7aa360ba951d56efa79030d6eb8a51a2fa6ca1700094cc2ebc1c880606',
			   'fe17799b85ffc86d3c0e44d9922ab3669b42c90ccb37b13d6c57b495f42c7918604d683f06d7f8d3a79d252e822ff93c51c89237432d5fa2f45b94ce9be1d7c0',
			   'f93f85741c71609d5ed3efac9887c9ca100c272f8ec61f6bbe1061e85e530f68683917a41e8943e47854930a4ac3a45412503977afe03bcc842e1c821d30adaf',
			   'f6b9e69ad9e83fc00338919ea3e1a990f6a6ee9cc2e76dad48657d1c92aa0bf975e513f5ce82e707fba68ce2de155d660bca6fdf2deb182f1fce0f045da38ed2',
			   '850187bb771ad86e8c73e801aaf7530afb4c5210d5040a844cd1666e442ca776d7e7da884075f847c9ffff60102542364253970a6ed0a225c0bd4f1cfd00a4d9']

def get_secret(sf):
	message = sf.readline().rstrip('\n')
	print(message)
	if ENTER_ACTION != message:
		print('did not receive action request')
	sf.write(GET_SECRET + '\n')

def enter_password(sf, passwords):
	message = sf.readline().rstrip('\n')
	print(message)
	if ENTER_USERNAME != message:
		print('did not receive username request')
	sf.write(USERNAME + '\n')

	message = sf.readline().rstrip('\n')
	print(message)
	if ENTER_PASSWORD != message:
		print('did not receive password request')	
	password = passwords.join(';')
	sf.write(password + '\n')

def get_hashes(sf):
	enter_password(sf, 'a')
	message = sf.readline().rstrip('\n')
	print(message)
	if message.startswith(LOGIN_INVALID_PASSWORD_START):
		hashes = message.lstrip(LOGIN_INVALID_PASSWORD_START) # remove message from start
		hashes = hashes.split(';')
		return hashes


def force_hashes_lookup(hashes):
	with open('fichier.json', 'r', encoding='utf-8') as fichier:
		m = json.load(fichier)
	return [m[hash] for hash in hashes]

def force_hashes(hashes):
	to_guess = set(hashes)
	print(hashes[0])
	passwords = {}
	for a in string.ascii_lowercase:
		if not to_guess: break
		for b in string.ascii_lowercase:
			if not to_guess: break
			for c in string.ascii_lowercase:
				if not to_guess: break
				password = ''.join([a, b, c, '1', '2', '3'])
				hash = scrypt(password.encode(), salt=USERNAME.encode(), n=16384, r=4, p=1).hex()

				#print(hash, password)
				if hash in to_guess:
					passwords[hash] = password
					to_guess.remove(hash)
	return [passwords[hash] for hash in hashes]

def create_dictionary():
	p = {}
	for a in string.ascii_lowercase:
		print(a)
		for b in string.ascii_lowercase:
			for c in string.ascii_lowercase:
				password = ''.join([a, b, c, '1', '2', '3'])
				p[scrypt(password.encode(), salt=USERNAME.encode(), n=16384, r=4, p=1).hex()] = password
	return p

def save_to_file(map):
	with open('fichier.json', 'w', encoding='utf-8') as fichier:
		json.dump(map, fichier, ensure_ascii=False, indent=4)

def get_flag():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	s.connect((HOST, PORT))
	sf = s.makefile('rw')

	get_secret(sf)
	hashes = [h.unhex() for h in get_hashes(sf)]
	print(hashes)
	passwords = ';'.join(force_hashes_lookup(hashes))
	print(passwords)
	enter_password(sf, passwords)
	message = sf.readline().rstrip('\n')
	print(message)
	if LOGIN_SYNTAX_FAIL == message:
		print('invalid syntax')
	return message

	sf.close()
	s.close()	


if __name__ == '__main__':
	get_flag()
	#print(force_hashes_lookup(TEST_HASHES))
	#save_to_file(create_dictionary())
