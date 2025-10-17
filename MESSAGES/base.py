import struct

class MESSAGE(object):
	"""docstring for Base MESSAGE"""
	def __init__(self, message_type):
		self.Signature = struct.pack(">8s", b'NTLMSSP\0')
		self.MessageType = struct.pack(">I", message_type)

class DOMAIN_NAME_FIELDS(object):
	"""docstring for Base MESSAGE"""
	def __init__(self, domain_name):
		self.DomainNameLen = struct.pack(">H", len(domain_name))
		self.DomainNameMaxLen = self.DomainNameLen
		self.DomainNameBufferOffset = struct.pack(">I", 0)

	def pack(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)

class WORKSTATION_FIELDS(object):
	"""docstring for Base MESSAGE"""
	def __init__(self, workstation_name, offset=0):
		self.WorkstationLen = struct.pack(">H", len(workstation_name))
		self.WorkstationMaxLen = self.WorkstationLen
		self.WorkstationBufferOffset = struct.pack(">I", 0+offset)

	def pack(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)