from .base import MESSAGE, DOMAIN_NAME_FIELDS, WORKSTATION_FIELDS
from ntlm.constants import NtLmNegotiate
from ntlm.STRUCTURES import NEGOTIATE_FLAGS, VERSION
import struct

class NEGOTIATE(MESSAGE):
	"""docstring for NEGOTIATE"""
	def __init__(self, flags, domain_name="", workstation_name="", major_version=0x0, minor_version=0x0, build=0x0, oem_encoding="cp850"):
		super(NEGOTIATE, self).__init__(NtLmNegotiate)
		encoding = super(NEGOTIATE, self).encode(flags, oem_encoding)

		self.NegotiateFlags = flags.pack

		domain_name = domain_name.encode(encoding)
		workstation_name = workstation_name.encode(encoding)

		domain_name_length = len(domain_name)
		workstation_name_length = len(workstation_name)

		match (flags.dict["NEGOTIATE_OEM_WORKSTATION_SUPPLIED"], flags.dict["NEGOTIATE_OEM_DOMAIN_SUPPLIED"]):
			case (1, 1):
				self.DomainNameFields = DOMAIN_NAME_FIELDS(domain_name).pack()
				self.WorkstationFields = WORKSTATION_FIELDS(domain_name, workstation_name).pack()
			case (1, 0):
				self.WorkstationFields = WORKSTATION_FIELDS(workstation_name).pack()
			case (0, 1):
				self.DomainNameFields = DOMAIN_NAME_FIELDS(domain_name).pack()
			case (0, 0):
				self.DomainNameFields = DOMAIN_NAME_FIELDS("").pack()
				self.WorkstationFields = WORKSTATION_FIELDS("").pack()

		if flags.dict["NEGOTIATE_VERSION"]:
			self.Version = VERSION(major_version, minor_version, build).pack()
		else:
			self.Version = VERSION(0, 0, 0).pack()
		
		if domain_name_length:
			self.DomainName = struct.pack(f"<{domain_name_length}s", domain_name)

		if workstation_name_length:
			self.WorkstationName = struct.pack(f"<{workstation_name_length}s", workstation_name)