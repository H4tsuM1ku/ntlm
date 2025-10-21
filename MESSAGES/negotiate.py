from .base import MESSAGE, FIELDS
from ntlm.constants import NUL, NtLmNegotiate
from ntlm.STRUCTURES import VERSION
import struct

class NEGOTIATE(MESSAGE):
	"""docstring for NEGOTIATE"""
	def __init__(self, flags, domain_name="", workstation_name="", major_version=NUL, minor_version=NUL, build=NUL, oem_encoding="cp850"):
		super(NEGOTIATE, self).__init__(NtLmNegotiate)

		offset = 40
		encoding = super(NEGOTIATE, self).charset(flags, oem_encoding)
		version = VERSION()

		domain_name = domain_name.encode(encoding) if flags.dict["NEGOTIATE_OEM_DOMAIN_SUPPLIED"] and len(domain_name) else b""
		workstation_name = workstation_name.encode(encoding) if flags.dict["NEGOTIATE_OEM_WORKSTATION_SUPPLIED"] and len(workstation_name) else b""

		self.NegotiateFlags = flags.pack

		self.DomainNameFields, offset = FIELDS(domain_name, offset).pack(), offset+len(domain_name)
		self.WorkstationFields, offset = FIELDS(workstation_name, offset).pack(), offset+len(workstation_name)

		self.Version = version.get_version()
		if flags.dict["NEGOTIATE_VERSION"]:
			self.Version = version.get_version(major_version, minor_version, build)

		self.Payload += struct.pack(f"<{len(domain_name)}s", domain_name)
		self.Payload += struct.pack(f"<{len(workstation_name)}s", workstation_name)