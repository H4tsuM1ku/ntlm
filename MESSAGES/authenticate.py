from .base import MESSAGE, FIELDS
from ntlm.constants import NtLmAuthenticate
from ntlm.STRUCTURES import VERSION
import struct

class AUTHENTICATE(MESSAGE):
	"""docstring for AUTHENTICATE"""
	def __init__(self, flags, domain_name="", user_name="", workstation_name="", major_version=0x0, minor_version=0x0, build=0x0, revision=0x0F, oem_encoding="cp850"):
		super(AUTHENTICATE, self).__init__(NtLmAuthenticate)

		offset = 88 if flags.dict["NEGOTIATE_VERSION"] else 80
		encoding = super(AUTHENTICATE, self).charset(flags, oem_encoding)
		version = VERSION()

		lm_response = LMv2_RESPONSE() if flags.dict["NEGOTIATE_EXTENDED_SESSIONSECURITY"] else LM_RESPONSE()
		nt_reponse = NTLMv2_RESPONSE() if flags.dict["NEGOTIATE_EXTENDED_SESSIONSECURITY"] else NTLM_RESPONSE()

		domain_name = domain_name.encode(encoding) if flags.dict["NEGOTIATE_OEM_DOMAIN_SUPPLIED"] and len(domain_name) else b""
		user_name = user_name.encode(encoding) if user_name else b""
		workstation_name = workstation_name.encode(encoding) if flags.dict["NEGOTIATE_OEM_WORKSTATION_SUPPLIED"] and len(workstation_name) else b""

		#session_key = None if flags.dict["NEGOTIATE_KEY_EXCH"]

		self.LmChallengeResponseFields = FIELDS(lm_response, offset).pack()
		self.NtChallengeResponseFields = FIELDS(nt_reponse, offset, len(lm_response)).pack()

		self.DomainNameFields = FIELDS(domain_name, offset, len(lm_response)\
															+len(nt_reponse)).pack()

		self.UserNameFields = FIELDS(user_name, offset, len(lm_response)\
														+len(nt_reponse)\
														+len(domain_name)).pack()

		self.WorkstationFields = FIELDS(workstation_name, offset, len(lm_response)\
																	+len(nt_reponse)\
																	+len(domain_name)\
																	+len(user_name)).pack()

		self.EncryptedRandomSessionKeyFields = FIELDS(session_key, offset, len(lm_response)\
																			+len(nt_response)\
																			+len(domain_name)\
																			+len(user_name)\
																			+len(workstation_name)).pack()

		self.NegotiateFlags = flags.pack

		self.Version = version.get_version()
		if flags.dict["NEGOTIATE_VERSION"]:
			self.Version = version.get_version(major_version, minor_version, build, revision)

		self.MIC = struct.pack()

		self.Payload += lm_response.pack()
		self.Payload += nt_reponse.pack()
		self.Payload += struct.pack(f"<{len(domain_name)}s", domain_name)
		self.Payload += struct.pack(f"<{len(user_name)}s", user_name)
		self.Payload += struct.pack(f"<{len(workstation_name)}s", workstation_name)
		self.Payload += session_key.pack()

		if flags.dict["NEGOTIATE_EXTENDED_SESSIONSECURITY"] and flag.dict["NEGOTIATE_ALWAYS_SIGN"] and av_list:
			self.MIC = compute_MIC(negotiate_message, challenge_message, self)