from ntlm.constants import NUL, NtLmNegotiate, NtLmChallenge, NtLmAuthenticate
from ntlm.STRUCTURES import NEGOTIATE_FLAGS, VERSION
import struct

class MESSAGE(object):
	"""docstring for Base MESSAGE"""
	def __init__(self, message_type):
		self.Signature = b'NTLMSSP\0'
		self.MessageType = message_type

		if self.MessageType == NtLmNegotiate:
			self.NegotiateFlags		= None
			self.DomainNameFields	= None
			self.WorkstationFields	= None
		elif self.MessageType == NtLmChallenge:
			self.TargetNameFields	= None
			self.NegotiateFlags		= None
			self.ServerChallenge	= None
			self.Reserved			= None
			self.TargetInfoFields	= None
		elif self.MessageType == NtLmAuthenticate:
			self.LmChallengeResponseFields			= None
			self.NtChallengeResponseFields			= None
			self.DomainNameFields					= None
			self.UserNameFields						= None
			self.WorkstationFields					= None
			self.EncryptedRandomSessionKeyFields	= None
			self.NegotiateFlags						= None

		self.Version = None

		if self.MessageType == NtLmAuthenticate:
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
		message_type = self.MessageType

		self.Signature = struct.pack("8s", self.Signature)
		self.MessageType = struct.pack("<I", self.MessageType)

		if message_type == NtLmNegotiate:
			self.NegotiateFlags		= self.NegotiateFlags.to_bytes()
			self.DomainNameFields	= self.DomainNameFields.to_bytes()
			self.WorkstationFields	= self.WorkstationFields.to_bytes()
		elif message_type == NtLmChallenge:
			self.TargetNameFields	= self.TargetNameFields.to_bytes()
			self.NegotiateFlags		= self.NegotiateFlags.to_bytes()
			self.ServerChallenge	= struct.pack("<Q", self.ServerChallenge)
			self.TargetInfoFields	= self.TargetInfoFields.to_bytes()
		elif message_type == NtLmAuthenticate:
			self.LmChallengeResponseFields			= self.LmChallengeResponseFields.to_bytes()
			self.NtChallengeResponseFields			= self.NtChallengeResponseFields.to_bytes()
			self.DomainNameFields					= self.DomainNameFields.to_bytes()
			self.UserNameFields						= self.UserNameFields.to_bytes()
			self.WorkstationFields					= self.WorkstationFields.to_bytes()
			self.EncryptedRandomSessionKeyFields	= self.EncryptedRandomSessionKeyFields.to_bytes()
			self.NegotiateFlags						= self.NegotiateFlags.to_bytes()

		self.Version = self.Version.to_bytes()
		self.Payload = struct.pack(f"{len(self.Payload)}s", len(self.Payload))

		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)

	def from_bytes(self, message_bytes):
		self.Signature = struct.unpack("8s", message_bytes[:8])
		self.MessageType = struct.unpack("<I", message_bytes[8:12])

		if self.MessageType == NtLmNegotiate:
			self.NegotiateFlags		= struct.unpack("<I", message_bytes[12:16])
			self.DomainNameFields	= FIELDS.from_bytes(message_bytes[16:24])
			self.WorkstationFields	= FIELDS.from_bytes(message_bytes[24:32])
			offset = 32
		elif self.MessageType == NtLmChallenge:
			self.TargetNameFields	= FIELDS.from_bytes(message_bytes[12:20])
			self.NegotiateFlags		= NEGOTIATE_FLAGS.from_bytes(message_bytes[20:24])
			self.ServerChallenge	= FIELDS.from_bytes(message_bytes[24:32])
			self.Reserved			= message_bytes[32:40]
			self.TargetInfoFields	= FIELDS.from_bytes(message_bytes[40:48])
			offset = 48
		elif self.MessageType == NtLmAuthenticate:
			self.LmChallengeResponseFields			= FIELDS.from_bytes(message_bytes[12:20])
			self.NtChallengeResponseFields			= FIELDS.from_bytes(message_bytes[20:28])
			self.DomainNameFields					= FIELDS.from_bytes(message_bytes[28:36])
			self.UserNameFields						= FIELDS.from_bytes(message_bytes[36:44])
			self.WorkstationFields					= FIELDS.from_bytes(message_bytes[44:52])
			self.EncryptedRandomSessionKeyFields	= FIELDS.from_bytes(message_bytes[52:60])
			self.NegotiateFlags						= NEGOTIATE_FLAGS.from_bytes(message_bytes[60:64])
			offset = 64

		self.Version = VERSION.from_bytes(message_bytes[offset:offset+8])
		offset += 8

		if self.MessageType == NtLmAuthenticate:
			self.MIC = message_bytes[offset:offset+16]
			offset += 16

		self.Payload = struct.unpack(f"{len(message_bytes)-offset}s", message_bytes[offset:])

		return self

class FIELDS(object):
	"""docstring for Base MESSAGE"""
	def __init__(self, name, offset):
		self.NameLen = len(name)
		self.NameMaxLen = self.NameLen

		self.NameBufferOffset = NUL
		if len(name):
			self.NameBufferOffset = offset

	def to_bytes(self):
		self.NameLen 			= struct.pack("<H", self.NameLen)
		self.NameMaxLen 		= struct.pack("<H", self.NameMaxLen)
		self.NameBufferOffset 	= struct.pack("<I", self.NameBufferOffset)

		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)

	def from_bytes(self, message_bytes):
		self.NameLen 			= struct.unpack("<H", message_bytes[:2])
		self.NameMaxLen 		= struct.unpack("<H", message_bytes[2:4])
		self.NameBufferOffset 	= struct.unpack("<I", message_bytes[4:])

		return self