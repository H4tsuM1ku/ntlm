from .base import MESSAGE, FIELDS
from ntlm.utils import Z
from ntlm.constants import NUL, NTLMSSP_REVISION_W2K3, NtLmNegotiate
from ntlm.STRUCTURES import VERSION
import struct

class NEGOTIATE(MESSAGE):
	"""docstring for NEGOTIATE"""
	def __init__(self, flags, infos={}, version_infos=(NUL, NUL, NUL), oem_encoding="cp850"):
		super(NEGOTIATE, self).__init__(NtLmNegotiate)

		offset = 40
		encoding = super(NEGOTIATE, self).charset(flags, oem_encoding)

		domain_name = infos["domain"].encode(encoding) if flags.dict["NEGOTIATE_OEM_DOMAIN_SUPPLIED"] and len(infos["domain"]) else Z(0)
		workstation_name = infos["workstation"].encode(encoding) if flags.dict["NEGOTIATE_OEM_WORKSTATION_SUPPLIED"] and len(infos["workstation"]) else Z(0)

		self.NegotiateFlags = flags

		self.DomainNameFields, offset = FIELDS(domain_name, offset), offset + len(domain_name)
		self.WorkstationFields, offset = FIELDS(workstation_name, offset), offset + len(workstation_name)

		self.Version = VERSION()
		if flags.dict["NEGOTIATE_VERSION"]:
			self.Version.set_version(*version_infos, NTLMSSP_REVISION_W2K3)

		self.Payload += domain_name
		self.Payload += workstation_name