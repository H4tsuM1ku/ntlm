from .base import MESSAGE, FIELDS
from ntlm.utils import nonce, Z
from ntlm.constants import NUL, NTLMSSP_REVISION_W2K3, NtLmAuthenticate, MsvAvFlags
from ntlm.STRUCTURES import NEGOTIATE_FLAGS, VERSION, RESPONSE, AV_PAIR_LIST
from ntlm.CRYPTO import rc4k, compute_response, compute_MIC, KXKEY, SIGNKEY, SEALKEY

class AUTHENTICATE(MESSAGE):
	"""docstring for AUTHENTICATE"""
	def __init__(self, flags=NEGOTIATE_FLAGS(0x40000201), infos={}, version_infos=(NUL, NUL, NUL), oem_encoding="cp850"):
		super(AUTHENTICATE, self).__init__(NtLmAuthenticate)

		encoding = super(AUTHENTICATE, self).charset(flags, oem_encoding)
		client_challenge = nonce(64)

		if flags.dict["NEGOTIATE_KEY_EXCH"]:
			LmChallengeResponse, NtChallengeResponse, SessionKey = compute_response(flags, infos, client_challenge)
			KeyExchangeKey = KXKEY(flags, SessionKey, infos["password"], infos["server_challenge"], LmChallengeResponse)
			
			if flags.dict["NEGOTIATE_SIGN"] or flags.dict["NEGOTIATE_SEAL"]:
				ExportedSessionKey = nonce(16)
				EncryptedRandomSessionKey = rc4k(KeyExchangeKey, ExportedSessionKey)
			else:
				ExportedSessionKey = KeyExchangeKey
				EncryptedRandomSessionKey = Z(0)

		lm_response, nt_response = RESPONSE(LmChallengeResponse), RESPONSE(NtChallengeResponse)

		offset = 80
		self.Version = Z(0)
		if flags.dict["NEGOTIATE_VERSION"]:
			self.Version = VERSION(*version_infos, NTLMSSP_REVISION_W2K3)
			offset += 8
	
		self.LmChallengeResponseFields, offset = FIELDS(lm_response, offset), offset + len(lm_response)
		self.NtChallengeResponseFields, offset = FIELDS(nt_response, offset), offset + len(nt_response)

		self.DomainNameFields, offset = FIELDS(infos["domain"], offset), offset + len(infos["domain"])
		self.UserNameFields, offset = FIELDS(infos["user"], offset), offset + len(infos["user"])
		self.WorkstationFields, offset = FIELDS(infos["workstation"], offset), offset + len(infos["workstation"])

		self.EncryptedRandomSessionKeyFields = FIELDS(EncryptedRandomSessionKey, offset)

		self.NegotiateFlags = flags

		self.MIC = Z(16)

		self.Payload += lm_response.to_bytes()
		self.Payload += nt_response.to_bytes()
		self.Payload += infos["domain"].encode(encoding)
		self.Payload += infos["user"].encode(encoding)
		self.Payload += infos["workstation"].encode(encoding)
		self.Payload += EncryptedRandomSessionKey

		for av_pair in infos["target_info"].av_pairs:
			if av_pair.av_id == MsvAvFlags and av_pair.value & 0x00000002 and flags.dict["NEGOTIATE_EXTENDED_SESSIONSECURITY"]:
				self.MIC = compute_MIC(infos["negotiate_message"], infos["server_challenge"], self)

		if self.MIC == Z(16):
			self.MIC = Z(0)