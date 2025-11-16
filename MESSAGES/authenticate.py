from .base import MESSAGE, FIELDS
from ntlm.utils import nonce, Z
from ntlm.constants import NUL, NTLMSSP_REVISION_W2K3, NtLmAuthenticate, MsvAvFlags
from ntlm.STRUCTURES import NEGOTIATE_FLAGS, VERSION, RESPONSE
from ntlm.CRYPTO import rc4k, compute_response, KXKEY, SIGNKEY, SEALKEY

class AUTHENTICATE(MESSAGE):
	"""docstring for AUTHENTICATE"""
	def __init__(self, flags=NEGOTIATE_FLAGS(0x40000201), infos={}, av_list={}, version_infos=(NUL, NUL, NUL), oem_encoding="cp850"):
		super(AUTHENTICATE, self).__init__(NtLmAuthenticate)

		encoding = super(AUTHENTICATE, self).charset(flags, oem_encoding)

		try:
			if len(infos["user"]):
				user_name = infos["user"].encode(encoding)
			if len(infos["password"]):
				password = infos["password"]
			if len(infos["server_challenge"]):
				server_challenge = infos["server_challenge"]
			if len(infos["domain"]) and flags.dict["NEGOTIATE_OEM_DOMAIN_SUPPLIED"]:
				domain_name = infos["domain"].encode(encoding)
			if len(infos["workstation"]) and flags.dict["NEGOTIATE_OEM_WORKSTATION_SUPPLIED"]:
				workstation_name = infos["workstation"].encode(encoding)
		except:
			domain_name, user_name, workstation_name = (Z(0),)*3
			password = ""
			server_challenge = nonce(64)

		client_challenge = nonce(64)

		if flags.dict["NEGOTIATE_KEY_EXCH"]:
			LmChallengeResponse, NtChallengeResponse, SessionKey, temp = compute_response(flags, password, server_challenge, client_challenge)
			KeyExchangeKey = KXKEY(flags, SessionKey, password, server_challenge, LmChallengeResponse)
			
			if flags.dict["NEGOTIATE_SIGN"] or flags.dict["NEGOTIATE_SEAL"]:
				ExportedSessionKey = struct.pack("<I", nonce(16))
				EncryptedRandomSessionKey = rc4k(KeyExchangeKey, ExportedSessionKey)
			else:
				ExportedSessionKey = KeyExchangeKey
				EncryptedRandomSessionKey = Z(0)

		if flags.dict["NEGOTIATE_NTLM"] and flags.dict["NEGOTIATE_EXTENDED_SESSIONSECURITY"]:
			lm_response, nt_response = RESPONSE(LmChallengeResponse, 2, temp), RESPONSE(NtChallengeResponse, 2, temp)
		else:
			lm_response, nt_response = RESPONSE(LmChallengeResponse), RESPONSE(NtChallengeResponse)

		offset = 80
		self.Version = Z(0)
		if flags.dict["NEGOTIATE_VERSION"]:
			self.Version = VERSION(*version_infos, NTLMSSP_REVISION_W2K3)
			offset += 8
	
		self.LmChallengeResponseFields, offset = FIELDS(lm_response, offset), offset + len(lm_response)
		self.NtChallengeResponseFields, offset = FIELDS(nt_response, offset), offset + len(nt_response)

		self.DomainNameFields, offset = FIELDS(domain_name, offset), offset + len(domain_name)
		self.UserNameFields, offset = FIELDS(user_name, offset), offset + len(user_name)
		self.WorkstationFields, offset = FIELDS(workstation_name, offset), offset + len(workstation_name)

		self.EncryptedRandomSessionKeyFields = FIELDS(EncryptedRandomSessionKey, offset)

		self.NegotiateFlags = flags

		self.MIC = Z(16)

		self.Payload += lm_response.to_bytes()
		self.Payload += nt_response.to_bytes()
		self.Payload += domain_name
		self.Payload += user_name
		self.Payload += workstation_name
		self.Payload += EncryptedRandomSessionKey

		if flags.dict["NEGOTIATE_EXTENDED_SESSIONSECURITY"] and MsvAvFlags in av_list and av_list[MsvAvFlags] & 0x00000002:
			self.MIC = compute_MIC(infos["negotiate_message"], server_challenge, self)
		else:
			self.MIC = Z(0)