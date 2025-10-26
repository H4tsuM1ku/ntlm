from .utils import des, md4, hmac_md5

def LMOWFv1(password):
	password = password[:14].ljust(14, '\x00')
	password = password.upper().encode("ascii")

	LM_hash = des(password[:7], b"KGS!@#$%") + des(password[7:14], b"KGS!@#$%")

	return LM_hash

def NTOWFv1(password):
	password = password.encode("utf-16-le")
	NT_hash = md4(password)

	return NT_hash

def LMOWFv2(password, user, userdom):
	return NTOWFv2(password, user, userdom)

def NTOWFv2(password, user, userdom):
	NT_hash = NTOWFv1(password) 

	user = user.upper().encode("utf-16-le")
	userdom = userdom.encode("utf-16-le")

	NTv2_hash = hmac_md5(NT_hash, user+userdom)

	return NTv2_hash