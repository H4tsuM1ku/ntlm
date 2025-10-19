import secrets

def nonce(N):
	return secrets.randbits(N)