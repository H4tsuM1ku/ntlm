from .base import MESSAGE_INTERFACE, FIELDS
from ntlm.constants import NtLmNegotiate
from ntlm.STRUCTURES import VERSION
import struct

class NEGOTIATE(MESSAGE_INTERFACE):
	"""docstring for NEGOTIATE"""
	def __init__(self, flags, domain_name="", workstation_name="", major_version=0x0, minor_version=0x0, build=0x0, oem_encoding="cp850"):
		self.message = MESSAGE_INTERFACE(NtLmNegotiate)

		encoding = super(NEGOTIATE, self).charset(flags, oem_encoding)

		domain_name = domain_name.encode(encoding) if flags.dict["NEGOTIATE_OEM_DOMAIN_SUPPLIED"] and len(domain_name) else ""
		workstation_name = workstation_name.encode(encoding) if flags.dict["NEGOTIATE_OEM_WORKSTATION_SUPPLIED"] and len(workstation_name) else ""

		self.message.NegotiateFlags = flags.pack

		self.message.DomainNameFields = FIELDS(domain_name).pack()
		self.message.WorkstationFields = FIELDS(workstation_name, len(domain_name)).pack()

		self.message.Version = VERSION(major_version, minor_version, build).pack() if flags.dict["NEGOTIATE_VERSION"] else VERSION(0, 0, 0).pack()

		self.message.Payload += struct.pack(f"<{len(domain_name)}s", domain_name)
		self.message.Payload += struct.pack(f"<{len(workstation_name)}s", workstation_name)

	def pack(self):
		return self.message.pack()