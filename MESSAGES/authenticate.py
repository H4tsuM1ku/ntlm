from .base import MESSAGE, FIELDS
from ntlm.constants import NUL, NTLMSSP_REVISION_W2K3, NtLmAuthenticate
from ntlm.STRUCTURES import VERSION
import struct

class AUTHENTICATE(MESSAGE):
	"""docstring for AUTHENTICATE"""
	def __init__(self, flags, domain_name="", user_name="", workstation_name="", major_version=NUL, minor_version=NUL, build=NUL, oem_encoding="cp850"):
		super(AUTHENTICATE, self).__init__(NtLmAuthenticate)

		offset = 88
		encoding = super(AUTHENTICATE, self).charset(flags, oem_encoding)
		version = VERSION()

		lm_response = LMv2_RESPONSE() if flags.dict["NEGOTIATE_EXTENDED_SESSIONSECURITY"] else LM_RESPONSE()
		nt_reponse = NTLMv2_RESPONSE() if flags.dict["NEGOTIATE_EXTENDED_SESSIONSECURITY"] else NTLM_RESPONSE()

		domain_name = domain_name.encode(encoding) if flags.dict["NEGOTIATE_OEM_DOMAIN_SUPPLIED"] and len(domain_name) else b""
		user_name = user_name.encode(encoding) if user_name else b""
		workstation_name = workstation_name.encode(encoding) if flags.dict["NEGOTIATE_OEM_WORKSTATION_SUPPLIED"] and len(workstation_name) else b""

		#session_key = None if flags.dict["NEGOTIATE_KEY_EXCH"]

		self.LmChallengeResponseFields, offset = FIELDS(lm_response, offset).pack(), offset + len(lm_response)
		self.NtChallengeResponseFields, offset = FIELDS(nt_reponse, offset).pack(), offset + len(nt_reponse)

		self.DomainNameFields, offset = FIELDS(domain_name, offset).pack(), offset + len(domain_name)
		self.UserNameFields, offset = FIELDS(user_name, offset).pack(), offset + len(user_name)
		self.WorkstationFields, offset = FIELDS(workstation_name, offset).pack(), offset + len(workstation_name)

		self.EncryptedRandomSessionKeyFields, offset = FIELDS(session_key, offset).pack(), offset + len(session_key)

		self.NegotiateFlags = flags.pack

		self.Version = version.get_version()
		if flags.dict["NEGOTIATE_VERSION"]:
			self.Version = version.get_version(major_version, minor_version, build, NTLMSSP_REVISION_W2K3)

		self.MIC = struct.pack("<16s", b"\x00"*16)

		self.Payload += lm_response.pack()
		self.Payload += nt_reponse.pack()
		self.Payload += struct.pack(f"<{len(domain_name)}s", domain_name)
		self.Payload += struct.pack(f"<{len(user_name)}s", user_name)
		self.Payload += struct.pack(f"<{len(workstation_name)}s", workstation_name)
		self.Payload += session_key.pack()

		if flags.dict["NEGOTIATE_EXTENDED_SESSIONSECURITY"] and flag.dict["NEGOTIATE_ALWAYS_SIGN"] and av_list[MsvAvFlags] & 0x00000002:
			self.MIC = compute_MIC(negotiate_message, challenge_message, self)