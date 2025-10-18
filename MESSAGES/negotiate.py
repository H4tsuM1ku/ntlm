from .base import MESSAGE, FIELDS
from ntlm.constants import NtLmNegotiate
from ntlm.STRUCTURES import VERSION
import struct

class NEGOTIATE(MESSAGE):
	"""docstring for NEGOTIATE"""
	def __init__(self, flags, domain_name="", workstation_name="", major_version=0x0, minor_version=0x0, build=0x0, oem_encoding="cp850"):
		super(NEGOTIATE, self).__init__(NtLmNegotiate)

		offset = 40 if flags.dict["NEGOTIATE_VERSION"] else 32
		encoding = super(NEGOTIATE, self).charset(flags, oem_encoding)

		domain_name = domain_name.encode(encoding) if flags.dict["NEGOTIATE_OEM_DOMAIN_SUPPLIED"] and len(domain_name) else b""
		workstation_name = workstation_name.encode(encoding) if flags.dict["NEGOTIATE_OEM_WORKSTATION_SUPPLIED"] and len(workstation_name) else b""

		self.NegotiateFlags = flags.pack

		self.DomainNameFields = FIELDS(domain_name, offset).pack()
		self.WorkstationFields = FIELDS(workstation_name, offset, len(domain_name)).pack()

		self.Version = VERSION(major_version, minor_version, build).pack() if flags.dict["NEGOTIATE_VERSION"] else b""

		self.Payload += struct.pack(f"<{len(domain_name)}s", domain_name)
		self.Payload += struct.pack(f"<{len(workstation_name)}s", workstation_name)