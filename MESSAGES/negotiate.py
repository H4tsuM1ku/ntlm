from .base import MESSAGE, FIELDS
from ntlm.constants import NUL, NTLMSSP_REVISION_W2K3, NtLmNegotiate
from ntlm.CRYPTO import Z
from ntlm.STRUCTURES import VERSION
import struct

class NEGOTIATE(MESSAGE):
	"""docstring for NEGOTIATE"""
	def __init__(self, flags, infos={}, version_infos=(NUL, NUL, NUL), oem_encoding="cp850"):
		super(NEGOTIATE, self).__init__(NtLmNegotiate)

		offset = 40
		encoding = super(NEGOTIATE, self).charset(flags, oem_encoding)
		version = VERSION()

		domain_name = infos["domain"].encode(encoding) if flags.dict["NEGOTIATE_OEM_DOMAIN_SUPPLIED"] and len(infos["domain"]) else Z(0)
		workstation_name = infos["workstation"].encode(encoding) if flags.dict["NEGOTIATE_OEM_WORKSTATION_SUPPLIED"] and len(infos["workstation"]) else Z(0)

		self.NegotiateFlags = flags.pack

		self.DomainNameFields, offset = FIELDS(domain_name, offset).pack(), offset+len(domain_name)
		self.WorkstationFields, offset = FIELDS(workstation_name, offset).pack(), offset+len(workstation_name)

		self.Version = version.get_version()
		if flags.dict["NEGOTIATE_VERSION"]:
			self.Version = version.get_version(*version, NTLMSSP_REVISION_W2K3)

		self.Payload += struct.pack(f"<{len(domain_name)}s", domain_name)
		self.Payload += struct.pack(f"<{len(workstation_name)}s", workstation_name)