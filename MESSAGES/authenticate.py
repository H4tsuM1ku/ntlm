from .base import MESSAGE, FIELDS
from ntlm.constants import NtLmAuthenticate
from ntlm.STRUCTURES import VERSION
import struct

class AUTHENTICATE(MESSAGE):
	"""docstring for AUTHENTICATE"""
	def __init__(self):
		super(AUTHENTICATE, self).__init__(NtLmAuthenticate)

		lm_response = LMv2_RESPONSE() if flags.dict["NEGOTIATE_EXTENDED_SESSIONSECURITY"] else LM_RESPONSE()
		nt_reponse = NTLMv2_REPONSE() if flags.dict["NEGOTIATE_EXTENDED_SESSIONSECURITY"] else NTLM_REPONSE()

		domain_name = domain_name.encode(encoding) if flags.dict["NEGOTIATE_OEM_DOMAIN_SUPPLIED"] and len(domain_name) else b""
		user_name = user_name.encode(encoding) if user_name else b""
		workstation_name = workstation_name.encode(encoding) if flags.dict["NEGOTIATE_OEM_WORKSTATION_SUPPLIED"] and len(workstation_name) else b""

		session_key = None

		self.LmChallengeResponseFields = FIELDS(lm_response).pack()
		self.NtChallengeResponseFields = FIELDS(nt_reponse, len(lm_response)).pack()

		self.DomainNameFields = FIELDS(domain_name, len(lm_response)\
													+len(nt_reponse)).pack()

		self.UserNameFields = FIELDS(user_name, len(lm_response)\
												+len(nt_reponse)\
												+len(domain_name)).pack()

		self.WorkstationFields = FIELDS(workstation_name, len(lm_response)\
															+len(nt_reponse)\
															+len(domain_name)\
															+len(user_name)).pack()

		self.EncryptedRandomSessionKeyFields = FIELDS(session_key, len(lm_response)\
																	+len(nt_response)\
																	+len(domain_name)\
																	+len(user_name)\
																	+len(workstation_name)).pack()

		self.NegotiateFlags = flags.pack

		self.Version = VERSION(major_version, minor_version, build).pack() if flags.dict["NEGOTIATE_VERSION"] else VERSION(0, 0, 0).pack()

		#self.MIC = None

		self.Payload += struct.pack(f"<{target_name_length}s", target_name)
		self.Payload += target_info.pack()