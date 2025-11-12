import secrets

def nonce(N):
	return secrets.randbits(N)

def Z(N):
	return bytes(N)