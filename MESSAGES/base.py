from ntlm.constants import NtLmNegotiate, NtLmChallenge, NtLmAuthenticate
import struct

class MESSAGE(object):
	"""docstring for Base MESSAGE"""
	def __init__(self, message_type):
		self.Signature = struct.pack("<8s", b'NTLMSSP\0')
		self.MessageType = struct.pack("<I", message_type)

		if message_type == NtLmNegotiate:
			self.NegotiateFlags		= None
			self.DomainNameFields	= None
			self.WorkstationFields	= None
		elif message_type == NtLmChallenge:
			self.TargetNameFields	= None
			self.NegotiateFlags		= None
			self.ServerChallenge	= None
			self.Reserved			= None
			self.TargetInfoFields	= None
		elif message_type == NtLmAuthenticate:
			self.LmChallengeResponseFields			= None
			self.NtChallengeResponseFields			= None
			self.DomainNameFields					= None
			self.UserNameFields						= None
			self.WorkstationFields					= None
			self.EncryptedRandomSessionKeyFields	= None
			self.NegotiateFlags						= None

		self.Version = None

		if message_type == NtLmAuthenticate:
			self.MIC = None

		self.Payload = b""

	def charset(self, flags, oem_encoding):
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

class FIELDS(object):
	"""docstring for Base MESSAGE"""
	def __init__(self, name, default_offset, variable_offset=0):
		self.NameLen = struct.pack("<H", len(name))
		self.NameMaxLen = self.NameLen
		self.NameBufferOffset = struct.pack("<I", 0+default_offset+variable_offset)

	def pack(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)