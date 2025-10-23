from Crypto.Cipher import DES
from Crypto.Hash import MD4
import hashlib

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

def LMOWFv1(password):
	password = password[:14].ljust(14, '\0')
	password = password.upper().encode("ascii")

	key1, key2 = adjust_key_parity(password[:7]), adjust_key_parity(password[7:14])
	cipher1, cipher2 = DES.new(key1, DES.MODE_ECB), DES.new(key2, DES.MODE_ECB)

	LM_hash = cipher1.encrypt(b"KGS!@#$%") + cipher2.encrypt(b"KGS!@#$%")

	return LM_hash

def NTOWFv1(password):
	password = password.encode("utf-16-le")
	
	NT_hash = MD4.MD4Hash()
	NT_hash.update(password)

	return NT_hash.digest()