import struct

class MESSAGE(object):
	"""docstring for Base MESSAGE"""
	def __init__(self, message_type):
		self.Signature = struct.pack("<8s", b'NTLMSSP\0')
		self.MessageType = struct.pack("<I", message_type)

	def encode(self, flags, oem_encoding):
		match (flags.dict["NEGOTIATE_UNICODE"], flags.dict["NEGOTIATE_OEM"]):
			case (1, 1) | (1, 0):
				encoding = "utf-16-le"
			case (0, 1):
				encoding = oem_encoding
			case (0, 0):
				raise Exception("SEC_E_INVALID_TOKEN: You need to choose a character set encoding")
		return encoding

	def pack(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)

class DOMAIN_NAME_FIELDS(object):
	"""docstring for Base MESSAGE"""
	def __init__(self, domain_name):
		self.DomainNameLen = struct.pack("<H", len(domain_name))
		self.DomainNameMaxLen = self.DomainNameLen
		self.DomainNameBufferOffset = struct.pack("<I", 0)

	def pack(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)

class WORKSTATION_FIELDS(object):
	"""docstring for Base MESSAGE"""
	def __init__(self, workstation_name, offset=0):
		self.WorkstationLen = struct.pack("<H", len(workstation_name))
		self.WorkstationMaxLen = self.WorkstationLen
		self.WorkstationBufferOffset = struct.pack("<I", 0+offset)

	def pack(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)

class TARGET_NAME_FIELDS(object):
	"""docstring for TARGET_NAME_FIELDS"""
	def __init__(self, target_name):
		self.TargetNameLen = struct.pack("<H", len(target_name))
		self.TargetNameMaxLen = self.TargetNameLen
		self.TargetNameBufferOffset = struct.pack("<I", 0)

	def pack(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)

class TARGET_INFO_FIELDS(object):
	"""docstring for TARGET_NAME_FIELDS"""
	def __init__(self, target_info, offset=0):
		self.TargetInfoLen = struct.pack("<H", len(target_info))
		self.TargetInfoMaxLen = self.TargetInfoLen
		self.TargetInfoBufferOffset = struct.pack("<I", 0+offset)

	def pack(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)