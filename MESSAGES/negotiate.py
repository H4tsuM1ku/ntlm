from .base import MESSAGE, FIELDS
from ntlm.utils import Z
from ntlm.constants import NUL, NTLMSSP_REVISION_W2K3, NtLmNegotiate
from ntlm.STRUCTURES import NEGOTIATE_FLAGS, VERSION

class NEGOTIATE(MESSAGE):
	"""docstring for NEGOTIATE"""
	def __init__(self, flags=NEGOTIATE_FLAGS(1), infos={}, version_infos=(NUL, NUL, NUL), oem_encoding="cp850"):
		super(NEGOTIATE, self).__init__(NtLmNegotiate)

		encoding = super(NEGOTIATE, self).charset(flags, oem_encoding)

		domain_name = infos["domain"].encode(encoding) if flags.dict["NEGOTIATE_OEM_DOMAIN_SUPPLIED"] and len(infos["domain"]) else Z(0)
		workstation_name = infos["workstation"].encode(encoding) if flags.dict["NEGOTIATE_OEM_WORKSTATION_SUPPLIED"] and len(infos["workstation"]) else Z(0)

		self.NegotiateFlags = flags

		offset = 32
		self.Version = Z(0)
		if flags.dict["NEGOTIATE_VERSION"]:
			self.Version = VERSION(*version_infos, NTLMSSP_REVISION_W2K3)
			offset += 8

		self.DomainNameFields, offset = FIELDS(domain_name, offset), offset + len(domain_name)
		self.WorkstationFields, offset = FIELDS(workstation_name, offset), offset + len(workstation_name)

		self.Payload += domain_name
		self.Payload += workstation_name