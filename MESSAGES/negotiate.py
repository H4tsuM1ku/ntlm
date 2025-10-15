from .base import MESSAGE, DOMAINNAMEFIELDS, WORKSTATIONFIELDS
from ntlm.STRUCTURES import NEGOTIATEFLAGS, VERSION

class NEGOTIATE(MESSAGE):
	"""docstring for NEGOTIATE"""
	def __init__(self, flags, domain_name=None, workstation_name=None):
		super(NEGOTIATE, self).__init__(0x000000001)
		self.NegotiateFlags = NEGOTIATEFLAGS(*flags).to_bytes()

		print(domain_name, workstation_name)

		match (flags[11], flags[12]):
			case (1, 1):
				self.DomainNameFields = DOMAINNAMEFIELDS(domain_name).to_bytes()
				self.WorkstationFields = WORKSTATIONFIELDS(workstation_name, len(domain_name)).to_bytes()
			case (1, 0):
				self.WorkstationFields = WORKSTATIONFIELDS(workstation_name).to_bytes()
			case (0, 1):
				self.DomainNameFields = DOMAINNAMEFIELDS(domain_name).to_bytes()
			case (0, 0):
				pass

		if flags[3]:
			self.Version = VERSION().to_bytes

	def to_bytes(self):
		values = [getattr(self, attr) for attr in vars(self)]
		print(values)
		return b"".join(values)