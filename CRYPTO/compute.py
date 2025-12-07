from ntlm.utils import Z
from ntlm.STRUCTURES import Ntlmv2ClientChallenge

from .hashing import lmowfv1, ntowfv1, lmowfv2, ntowfv2
from .utils import md4, md5, hmac_md5, desl, rc4k

def compute_response(flags, username, password, domain_name, target_info, server_challenge, client_challenge):
	if flags.dict["ANONYMOUS"]:
		NtChallengeResponse = Z(0)
		LmChallengeResponse = Z(1)

	if flags.dict["NEGOTIATE_EXTENDED_SESSIONSECURITY"] and flags.dict["NEGOTIATE_TARGET_INFO"]:
		ResponseKeyNT, ResponseKeyLM = ntowfv2(password, username, domain_name), lmowfv2(password, username, domain_name)

		temp = Ntlmv2ClientChallenge(target_info, client_challenge).to_bytes()
		NTProofStr = hmac_md5(ResponseKeyNT, server_challenge + temp)

		NtChallengeResponse = NTProofStr
		LmChallengeResponse = hmac_md5(ResponseKeyLM, server_challenge + client_challenge)

		SessionBaseKey = hmac_md5(ResponseKeyNT, NTProofStr)

		return (LmChallengeResponse, NtChallengeResponse, SessionBaseKey, temp)
	else:
		if flags.dict["NEGOTIATE_NTLM"]:
			ResponseKeyNT, ResponseKeyLM = ntowfv1(password), lmowfv1(password)
			if flags.dict["NEGOTIATE_EXTENDED_SESSIONSECURITY"]:
				NtChallengeResponse = desl(ResponseKeyNT, md5(server_challenge + client_challenge)[:8])
				LmChallengeResponse = client_challenge + Z(16)
			else:
				NtChallengeResponse = desl(ResponseKeyNT, server_challenge)
				LmChallengeResponse = desl(ResponseKeyLM, server_challenge)

				if not flags.dict["NEGOTIATE_LM_KEY"]:
					LmChallengeResponse = NtChallengeResponse

		SessionBaseKey = md4(ResponseKeyNT)

	return (LmChallengeResponse, NtChallengeResponse, SessionBaseKey, Z(0))

def compute_MIC(KeyExchangeKey, EncryptedRandomSessionKey, negotiate, challenge, authenticate):
	if flags.dict["NEGOTIATE_KEY_EXCH"] and (flags.dict["NEGOTIATE_ALWAYS_SIGN"] or flags.dict["NEGOTIATE_SIGN"] or flags.dict["NEGOTIATE_SEAL"]):
		ExportedSessionKey = rc4k(KeyExchangeKey, EncryptedRandomSessionKey)
		return hmac_md5(ExportedSessionKey, negotiate + challenge + authenticate)
	else:
		return hmac_md5(KeyExchangeKey, negotiate + challenge + authenticate)