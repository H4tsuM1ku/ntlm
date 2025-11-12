from ntlm.utils import Z
from Crypto.Cipher import DES, ARC4
from Crypto.Hash import HMAC, MD5, MD4

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
    key.append(input_key[0] & 0xFE)
    key.append(((input_key[0] << 7) | (input_key[1] >> 1)) & 0xFE)
    key.append(((input_key[1] << 6) | (input_key[2] >> 2)) & 0xFE)
    key.append(((input_key[2] << 5) | (input_key[3] >> 3)) & 0xFE)
    key.append(((input_key[3] << 4) | (input_key[4] >> 4)) & 0xFE)
    key.append(((input_key[4] << 3) | (input_key[5] >> 5)) & 0xFE)
    key.append(((input_key[5] << 2) | (input_key[6] >> 6)) & 0xFE)
    key.append((input_key[6] << 1) & 0xFE)
    return bytes(key)