from ntlm.constants import NUL, NtLmNegotiate, NtLmChallenge, NtLmAuthenticate
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

	def to_bytes(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)

	def from_bytes(self, message_bytes):
		self.Signature = struct.unpack("8s", message_bytes[:8])
		self.MessageType = struct.unpack("<I", message_bytes[8:12])

		if self.MessageType == NtLmNegotiate:
			self.NegotiateFlags		= struct.unpack("<I", message_bytes[12:16])
			self.DomainNameFields	= struct.unpack("<Q", message_bytes[16:24])
			self.WorkstationFields	= struct.unpack("<Q", message_bytes[24:32])
			offset = 32
		elif self.MessageType == NtLmChallenge:
			self.TargetNameFields	= struct.unpack("<Q", message_bytes[12:20])
			self.NegotiateFlags		= struct.unpack("<I", message_bytes[20:24])
			self.ServerChallenge	= struct.unpack("<Q", message_bytes[24:32])
			self.Reserved			= struct.unpack("<Q", message_bytes[32:40])
			self.TargetInfoFields	= struct.unpack("<Q", message_bytes[40:48])
			offset = 48
		elif self.MessageType == NtLmAuthenticate:
			self.LmChallengeResponseFields			= struct.unpack("<Q", message_bytes[12:20])
			self.NtChallengeResponseFields			= struct.unpack("<Q", message_bytes[20:28])
			self.DomainNameFields					= struct.unpack("<Q", message_bytes[28:36])
			self.UserNameFields						= struct.unpack("<Q", message_bytes[36:44])
			self.WorkstationFields					= struct.unpack("<Q", message_bytes[44:52])
			self.EncryptedRandomSessionKeyFields	= struct.unpack("<Q", message_bytes[52:60])
			self.NegotiateFlags						= struct.unpack("<I", message_bytes[60:64])
			offset = 64

		self.Version = struct.unpack("<Q", message_bytes[offset:offset+8])
		offset += 8

		if self.MessageType == NtLmAuthenticate:
			self.MIC = struct.unpack("<I", message_bytes[offset:offset+16])
			offset += 16

		self.Payload = struct.unpack(f"{len(message_bytes)-offset}s", message_bytes[offset:])

class FIELDS(object):
	"""docstring for Base MESSAGE"""
	def __init__(self, name, offset):
		self.NameLen = struct.pack("<H", len(name))
		self.NameMaxLen = self.NameLen

		self.NameBufferOffset = struct.pack("<I", NUL)
		if len(name):
			self.NameBufferOffset = struct.pack("<I", offset)

	def pack(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)