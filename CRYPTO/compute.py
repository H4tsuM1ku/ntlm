from .utils import md4, md5, hmac_md5, desl, rc4k
from ntlm.utils import Z
from ntlm.STRUCTURES import NTLMv2_CLIENT_CHALLENGE

def compute_response(flags, ResponseKeyNT, ResponseKeyLM, ServerChallenge, ClientChallenge):
	if flags.dict["ANONYMOUS"]:
		NtChallengeResponse = Z(1)
		LmChallengeResponse = Z(1)

	if flags.dict["NEGOTIATE_NTLM"]:
		if flags.dict["NEGOTIATE_EXTENDED_SESSIONSECURITY"]:
			NtChallengeResponse = desl(ResponseKeyNT, md5(ServerChallenge + ClientChallenge)[:8])
			LmChallengeResponse = ClientChallenge + Z(16)
		else:
			NtChallengeResponse = desl(ResponseKeyNT, ServerChallenge)
			LmChallengeResponse = desl(ResponseKeyLM, ServerChallenge)

			if not flags.dict["NEGOTIATE_LM_KEY"]:
				LmChallengeResponse = NtChallengeResponse

		SessionBaseKey = md4(ResponseKeyNT)
	else:
		temp = NTLMv2_CLIENT_CHALLENGE().pack()
		NTProofStr = hmac_md5(ResponseKeyNT, ServerChallenge + temp)

		NtChallengeResponse = NTProofStr + temp
		LmChallengeResponse = hmac_md5(ResponseKeyNT, ServerChallenge + ClientChallenge) + ClientChallenge

		SessionBaseKey = hmac_md5(ResponseKeyNT, NTProofStr)

		return (LmChallengeResponse, NtChallengeResponse, SessionBaseKey, temp)

	return (LmChallengeResponse, NtChallengeResponse, SessionBaseKey, Z(0))

def compute_MIC():
	if flags.dict["NEGOTIATE_KEY_EXCH"] and (flags.dict["NEGOTIATE_ALWAYS_SIGN"] or flags.dict["NEGOTIATE_SIGN"] or flags.dict["NEGOTIATE_SEAL"]):
		ExportedSessionKey = rc4k(KeyExchangeKey, EncryptedRandomSessionKey)
		return hmac_md5(ExportedSessionKey, negotiate+challenge+authenticate)
	else:
		return hmac_md5(KeyExchangeKey, negotiate+challenge+authenticate)