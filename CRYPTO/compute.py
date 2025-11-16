from .utils import md4, md5, hmac_md5, desl, rc4k
from ntlm.utils import Z
from ntlm.CRYPTO import LMOWFv1, NTOWFv1, LMOWFv2, NTOWFv2
from ntlm.STRUCTURES import NTLMv2_CLIENT_CHALLENGE

def compute_response(flags, infos, ClientChallenge):
	if flags.dict["ANONYMOUS"]:
		NtChallengeResponse = Z(0)
		LmChallengeResponse = Z(1)

	if flags.dict["NEGOTIATE_EXTENDED_SESSIONSECURITY"] and flags.dict["NEGOTIATE_TARGET_INFO"]:
		ResponseKeyNT, ResponseKeyLM = NTOWFv2(infos["password"], infos["user"], infos["domain"]), LMOWFv2(infos["password"], infos["user"], infos["domain"])

		temp = NTLMv2_CLIENT_CHALLENGE(infos["target_info"], ClientChallenge).to_bytes()
		NTProofStr = hmac_md5(ResponseKeyNT, infos["server_challenge"] + temp)

		NtChallengeResponse = NTProofStr + temp
		LmChallengeResponse = hmac_md5(ResponseKeyLM, infos["server_challenge"] + ClientChallenge) + ClientChallenge

		SessionBaseKey = hmac_md5(ResponseKeyNT, NTProofStr)

		return (LmChallengeResponse, NtChallengeResponse, SessionBaseKey)
	else:
		if flags.dict["NEGOTIATE_NTLM"]:
			ResponseKeyNT, ResponseKeyLM = NTOWFv1(infos["password"]), LMOWFv1(infos["password"])
			if flags.dict["NEGOTIATE_EXTENDED_SESSIONSECURITY"]:
				NtChallengeResponse = desl(ResponseKeyNT, md5(infos["server_challenge"] + ClientChallenge)[:8])
				LmChallengeResponse = ClientChallenge + Z(16)
			else:
				NtChallengeResponse = desl(ResponseKeyNT, infos["server_challenge"])
				LmChallengeResponse = desl(ResponseKeyLM, infos["server_challenge"])

				if not flags.dict["NEGOTIATE_LM_KEY"]:
					LmChallengeResponse = NtChallengeResponse

		SessionBaseKey = md4(ResponseKeyNT)

	return (LmChallengeResponse, NtChallengeResponse, SessionBaseKey)

def compute_MIC():
	if flags.dict["NEGOTIATE_KEY_EXCH"] and (flags.dict["NEGOTIATE_ALWAYS_SIGN"] or flags.dict["NEGOTIATE_SIGN"] or flags.dict["NEGOTIATE_SEAL"]):
		ExportedSessionKey = rc4k(KeyExchangeKey, EncryptedRandomSessionKey)
		return hmac_md5(ExportedSessionKey, negotiate + challenge + authenticate)
	else:
		return hmac_md5(KeyExchangeKey, negotiate + challenge + authenticate)