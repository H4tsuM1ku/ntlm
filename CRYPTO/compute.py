from .utils import Z, md4, md5, hmac_md5, desl
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

		SessionBaseKey = hmac_md5(ResponseKeyNT,NTProofStr)

	return (LmChallengeResponse, NtChallengeResponse, SessionBaseKey)