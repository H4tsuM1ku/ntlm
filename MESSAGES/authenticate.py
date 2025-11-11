from .base import MESSAGE, FIELDS
from ntlm.constants import NUL, NTLMSSP_REVISION_W2K3, NtLmAuthenticate, MsvAvFlags
from ntlm.STRUCTURES import VERSION, LM_RESPONSE, LMv2_RESPONSE, NTLM_RESPONSE, NTLMv2_RESPONSE
from ntlm.CRYPTO import Z, nonce, rc4k, compute_response, KXKEY, SIGNKEY, SEALKEY
import struct

class AUTHENTICATE(MESSAGE):
	"""docstring for AUTHENTICATE"""
	def __init__(self, flags, infos={}, av_list={}, version_infos=(NUL, NUL, NUL), oem_encoding="cp850"):
		super(AUTHENTICATE, self).__init__(NtLmAuthenticate)

		offset = 88
		encoding = super(AUTHENTICATE, self).charset(flags, oem_encoding)
		version = VERSION()

		domain_name = infos["domain"].encode(encoding) if flags.dict["NEGOTIATE_OEM_DOMAIN_SUPPLIED"] and len(infos["domain"]) else Z(0)
		user_name = infos["user"].encode(encoding) if infos["user"] else Z(0)
		workstation_name = infos["workstation"].encode(encoding) if flags.dict["NEGOTIATE_OEM_WORKSTATION_SUPPLIED"] and len(infos["workstation"]) else Z(0)
		client_challenge = nonce(64)
		server_challenge = infos["server_challenge"]
		ResponseKeyNT, ResponseKeyLM = infos["NT_hash"], infos["LM_hash"]

		if flags.dict["NEGOTIATE_KEY_EXCH"]:
			LmChallengeResponse, NtChallengeResponse, SessionKey, temp = compute_response(flags,  ResponseKeyNT, ResponseKeyLM, server_challenge, client_challenge)
			KeyExchangeKey = KXKEY(flags, SessionKey, ResponseKeyLM, server_challenge, LmChallengeResponse)
			
			if flags.dict["NEGOTIATE_SIGN"] or flags.dict["NEGOTIATE_SEAL"]:
				ExportedSessionKey = struct.pack("<I", nonce(16))
				EncryptedRandomSessionKey = rc4k(KeyExchangeKey, ExportedSessionKey)
			else:
				ExportedSessionKey = KeyExchangeKey
				EncryptedRandomSessionKey = Z(0)

			ClientSigningKey = SIGNKEY(flags, ExportedSessionKey, "Client") 
			ServerSigningKey = SIGNKEY(flags, ExportedSessionKey, "Server") 
			ClientSealingKey = SEALKEY(flags, ExportedSessionKey, infos["negotiate_message"].Version[-1], "Client") 
			ServerSealingKey = SEALKEY(flags, ExportedSessionKey, infos["negotiate_message"].Version[-1], "Server")
			
		if flags.dict["NEGOTIATE_NTLM"] and flags.dict["NEGOTIATE_EXTENDED_SESSIONSECURITY"]:
			lm_response, nt_response = LM_RESPONSE(LmChallengeResponse).pack(), NTLM_RESPONSE(NtChallengeResponse).pack()
		else:
			lm_response, nt_response = LMv2_RESPONSE(LmChallengeResponse, temp).pack(), NTLMv2_RESPONSE(NtChallengeResponse, temp).pack()

		self.LmChallengeResponseFields, offset = FIELDS(lm_response, offset).pack(), offset + len(lm_response)
		self.NtChallengeResponseFields, offset = FIELDS(nt_response, offset).pack(), offset + len(nt_response)

		self.DomainNameFields, offset = FIELDS(domain_name, offset).pack(), offset + len(domain_name)
		self.UserNameFields, offset = FIELDS(user_name, offset).pack(), offset + len(user_name)
		self.WorkstationFields, offset = FIELDS(workstation_name, offset).pack(), offset + len(workstation_name)

		self.EncryptedRandomSessionKeyFields, offset = FIELDS(EncryptedRandomSessionKey, offset).pack(), offset + len(EncryptedRandomSessionKey)

		self.NegotiateFlags = flags.pack

		self.Version = version.get_version()
		if flags.dict["NEGOTIATE_VERSION"]:
			self.Version = version.get_version(*version_infos, NTLMSSP_REVISION_W2K3)

		self.MIC = Z(16)

		self.Payload += lm_response
		self.Payload += nt_response
		self.Payload += struct.pack(f"<{len(domain_name)}s", domain_name)
		self.Payload += struct.pack(f"<{len(user_name)}s", user_name)
		self.Payload += struct.pack(f"<{len(workstation_name)}s", workstation_name)
		self.Payload += EncryptedRandomSessionKey

		if MsvAvFlags in av_list and av_list[MsvAvFlags] & 0x00000002:
			self.MIC = compute_MIC(infos["negotiate_message"], infos["server_challenge"], self.pack())