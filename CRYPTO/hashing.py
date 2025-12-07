from .utils import des, md4, hmac_md5

def lmowfv1(password):
	password = password[:14].ljust(14, '\x00')
	password = password.upper().encode("ascii")

	LM_hash = des(password[:7], b"KGS!@#$%") + des(password[7:14], b"KGS!@#$%")

	return LM_hash

def ntowfv1(password):
	password = password.encode("utf-16-le")
	NT_hash = md4(password)

	return NT_hash

def lmowfv2(password, user, userdom):
	return NTowfv2(password, user, userdom)

def ntowfv2(password, user, userdom):
	NT_hash = ntowfv1(password) 

	user = user.upper()
	userdom = userdom

	NTv2_hash = hmac_md5(NT_hash, user+userdom)

	return NTv2_hash