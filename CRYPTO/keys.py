from .utils import des, md5, md4, hmac_md5
from ntlm.utils import Z
from ntlm.constants import NTLMSSP_REVISION_W2K3

def KXKEY(flags, SessionBaseKey, ResponseKeyLM, ServerChallenge, LmChallengeResponse):
	key_exchange_key = SessionBaseKey

	if flags.dict["NEGOTIATE_NTLM"]:
		if flags.dict["NEGOTIATE_LM_KEY"]:
			key_exchange_key = des(ResponseKeyLM[:7], LmChallengeResponse[:8]) + des(ResponseKeyLM[7:8]+b"\xBD\xBD\xBD\xBD\xBD\xBD", LmChallengeResponse[:8])
		elif flags.dict["REQUEST_NON_NT_SESSION_KEY"]:
			key_exchange_key = ResponseKeyLM[:8] + Z(8)
		elif flags.dict["NEGOTIATE_EXTENDED_SESSIONSECURITY"]:
			key_exchange_key = hmac_md5(SessionBaseKey, ServerChallenge + LmChallengeResponse[:8])

	return key_exchange_key

def SIGNKEY(flags, ExportedSessionKey, Mode):
	sign_key = b""

	if flags.dict["NEGOTIATE_EXTENDED_SESSIONSECURITY"]:
		if Mode == "Client":
			sign_key = md5(ExportedSessionKey + b"session key to client-to-server signing key magic constant")
		else:
			sign_key = md5(ExportedSessionKey + b"session key to server-to-client signing key magic constant")

	return sign_key

def SEALKEY(flags, ExportedSessionKey, NTLMRevisionCurrent, Mode):
	if flags.dict["NEGOTIATE_EXTENDED_SESSIONSECURITY"]:
		if flags.dict["NEGOTIATE_128"]:
			seal_key = ExportedSessionKey
		elif flags.dict["NEGOTIATE_56"]:
			seal_key = ExportedSessionKey[:7]
		else:
			seal_key = ExportedSessionKey[:5]

		if Mode == "Client":
			seal_key = md5(seal_key + b"session key to client-to-server sealing key magic constant")
		else:
			seal_key = md5(seal_key + b"session key to server-to-client sealing key magic constant")
	elif flags.dict["NEGOTIATE_LM_KEY"] or (flags.dict["NEGOTIATE_DATAGRAM"] and NTLMRevisionCurrent >= NTLMSSP_REVISION_W2K3):
		if flags.dict["NEGOTIATE_56"]:
			seal_key = ExportedSessionKey[:6] + b"\xA0"
		else:
			seal_key = ExportedSessionKey[:4] + b"\xE5\x38\xB0"
	else:
		seal_key = ExportedSessionKey

	return seal_key