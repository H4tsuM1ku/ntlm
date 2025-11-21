from Crypto.Cipher import DES, ARC4
from Crypto.Hash import HMAC, MD5, MD4
from ntlm.utils import Z

def md4(message):
	temp = MD4.new()
	temp.update(message)

	return temp.digest()

def md5(message):
	temp = MD5.new()
	temp.update(message)

	return temp.digest()

def hmac_md5(key, message):
	temp = HMAC.new(key, digestmod=MD5)
	temp.update(message)

	return temp.digest()

def des(key, message):
	key = adjust_key_parity(key)

	temp = DES.new(key, DES.MODE_ECB)
	temp = temp.encrypt(message)

	return temp

def desl(key, message):
	temp = des(key[:7], message) + des(key[7:14], message) + des(key[14:] + Z(5), message)
	return temp

def rc4k(key, message):
	temp = ARC4.new(key)
	temp = temp.encrypt(message)

	return temp

def adjust_key_parity(input_key):
	"""
	Expand 7-byte key material into an 8-byte DES key with parity bits.
	"""
	key = []

	for i in range(8):
		if i == 0:
			key.append(input_key[i] & 0xFE)
		elif i == 7:
			key.append((input_key[i-1] << 1) & 0xFE)
		else:
			key.append(((input_key[i-1] << (8-i) ) | (input_key[i] >> i)) & 0xFE)

	return bytes(key)