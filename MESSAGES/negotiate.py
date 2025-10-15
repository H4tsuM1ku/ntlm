from .base import MESSAGE, DOMAINNAMEFIELDS, WORKSTATIONFIELDS
from ntlm.STRUCTURES import NEGOTIATEFLAGS, VERSION
import struct

class NEGOTIATE(MESSAGE):
	"""docstring for NEGOTIATE"""
	def __init__(self, flags, domain_name="", workstation_name="", major_version=0x0, minor_version=0x0, build=0x0, oem_encoding="cp850"):
		super(NEGOTIATE, self).__init__(0x000000001)
		self.NegotiateFlags = NEGOTIATEFLAGS(*flags).to_bytes()

		match (flags[20], flags[21]):
			case (1, 1):
				encoding = "utf-16-le"
			case (0, 1):
				encoding = "utf-16-le"
			case (1, 0):
				encoding = oem_encoding
			case (0, 0):
				raise Exception("SEC_E_INVALID_TOKEN: You need to choose a character set encoding")

		domain_name = domain_name.encode(encoding)
		workstation_name = workstation_name.encode(encoding)

		domain_name_length = len(domain_name)
		workstation_name_length = len(workstation_name)

		match (flags[11], flags[12]):
			case (1, 1):
				self.DomainNameFields = DOMAINNAMEFIELDS(domain_name).to_bytes()
				self.WorkstationFields = WORKSTATIONFIELDS(workstation_name, domain_name_length).to_bytes()
			case (1, 0):
				self.WorkstationFields = WORKSTATIONFIELDS(workstation_name).to_bytes()
			case (0, 1):
				self.DomainNameFields = DOMAINNAMEFIELDS(domain_name).to_bytes()
			case (0, 0):
				pass

		if flags[3]:
			self.Version = VERSION(major_version, minor_version, build).to_bytes()
		
		if domain_name_length:
			self.DomainName = struct.pack(f">{domain_name_length}s", domain_name)

		if workstation_name_length:
			self.WorkstationName = struct.pack(f">{workstation_name_length}s", workstation_name)

	def to_bytes(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)