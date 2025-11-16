import secrets

def nonce(N):
	return secrets.randbits(N).to_bytes((N + 7) // 8, "little")

def Z(N):
	return bytes(N)