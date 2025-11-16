from ntlm.utils import Z
from ntlm.constants import NUL, NtLmNegotiate, NtLmChallenge, NtLmAuthenticate, MsvAvFlags
from ntlm.STRUCTURES import NEGOTIATE_FLAGS, NTLMv2_CLIENT_CHALLENGE, VERSION
import struct

class MESSAGE(object):
	"""docstring for Base MESSAGE"""
	def __init__(self, message_type=NUL):
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

	def display_info(self, obj=None, indent=0):
		class_objects = [
			"NegotiateFlags", "DomainNameFields", "WorkstationFields", 
			"TargetNameFields", "TargetInfoFields", "LmChallengeResponseFields", 
			"NtChallengeResponseFields", "UserNameFields", "EncryptedRandomSessionKeyFields",
			"Version"
		]

		if obj is None:
			obj = self

		prefix = "\t" * indent

		for attr in vars(obj):
			value = getattr(obj, attr)
			if not value:
				continue

			print(f"{prefix}{attr}:", end=" ")
			if attr in class_objects:
				print()
				self.display_info(value, indent + 1)
			else:
				print(value)

	def to_bytes(self):
		bytes_chunks = []

		bytes_chunks.append(struct.pack("8s", self.Signature))
		bytes_chunks.append(struct.pack("<I", self.MessageType))

		if self.MessageType == NtLmNegotiate:
			bytes_chunks.append(self.NegotiateFlags.to_bytes())
			bytes_chunks.append(self.DomainNameFields.to_bytes())
			bytes_chunks.append(self.WorkstationFields.to_bytes())
		elif self.MessageType == NtLmChallenge:
			bytes_chunks.append(self.TargetNameFields.to_bytes())
			bytes_chunks.append(self.NegotiateFlags.to_bytes())
			bytes_chunks.append(self.ServerChallenge)
			bytes_chunks.append(self.Reserved)
			bytes_chunks.append(self.TargetInfoFields.to_bytes())
		elif self.MessageType == NtLmAuthenticate:
			bytes_chunks.append(self.LmChallengeResponseFields.to_bytes())
			bytes_chunks.append(self.NtChallengeResponseFields.to_bytes())
			bytes_chunks.append(self.DomainNameFields.to_bytes())
			bytes_chunks.append(self.UserNameFields.to_bytes())
			bytes_chunks.append(self.WorkstationFields.to_bytes())
			bytes_chunks.append(self.EncryptedRandomSessionKeyFields.to_bytes())
			bytes_chunks.append(self.NegotiateFlags.to_bytes())

		if self.NegotiateFlags & NEGOTIATE_FLAGS.NEGOTIATE_VERSION:
			bytes_chunks.append(self.Version.to_bytes())

		if self.MessageType == NtLmAuthenticate:
			bytes_chunks.append(self.MIC)

		bytes_chunks.append(struct.pack(f"{len(self.Payload)}s", self.Payload))
		return b"".join(bytes_chunks)

	@classmethod
	def from_bytes(cls, message_bytes):
		message = cls()

		message.Signature = struct.unpack("8s", message_bytes[:8])[0]
		message.MessageType = struct.unpack("<I", message_bytes[8:12])[0]

		if message.MessageType == NtLmNegotiate:
			message.NegotiateFlags		= NEGOTIATE_FLAGS.from_bytes(message_bytes[12:16])
			message.DomainNameFields	= FIELDS.from_bytes(message_bytes[16:24])
			message.WorkstationFields	= FIELDS.from_bytes(message_bytes[24:32])
			offset = 32
		elif message.MessageType == NtLmChallenge:
			message.TargetNameFields	= FIELDS.from_bytes(message_bytes[12:20])
			message.NegotiateFlags		= NEGOTIATE_FLAGS.from_bytes(message_bytes[20:24])
			message.ServerChallenge		= message_bytes[24:32]
			message.Reserved			= message_bytes[32:40]
			message.TargetInfoFields	= FIELDS.from_bytes(message_bytes[40:48])
			offset = 48
		elif message.MessageType == NtLmAuthenticate:
			message.LmChallengeResponseFields			= FIELDS.from_bytes(message_bytes[12:20])
			message.NtChallengeResponseFields			= FIELDS.from_bytes(message_bytes[20:28])
			message.DomainNameFields					= FIELDS.from_bytes(message_bytes[28:36])
			message.UserNameFields						= FIELDS.from_bytes(message_bytes[36:44])
			message.WorkstationFields					= FIELDS.from_bytes(message_bytes[44:52])
			message.EncryptedRandomSessionKeyFields		= FIELDS.from_bytes(message_bytes[52:60])
			message.NegotiateFlags						= NEGOTIATE_FLAGS.from_bytes(message_bytes[60:64])
			offset = 64

		if message.NegotiateFlags & NEGOTIATE_FLAGS.NEGOTIATE_VERSION:
			message.Version = VERSION.from_bytes(message_bytes[offset:offset+8])
			offset += 8

		if message.MessageType == NtLmAuthenticate:
			if message.NtChallengeResponseFields.NameLen > 24:
				client_challenge = NTLMv2_CLIENT_CHALLENGE.from_bytes(message_bytes[message.NtChallengeResponseFields.NameBufferOffset+24:])
				av_pairs = client_challenge.AvPairs.av_pairs

				for av_pair in av_pairs:
					if av_pair.av_id == MsvAvFlags and av_pair.value & 0x00000002 and message.NegotiateFlags & NEGOTIATE_FLAGS.NEGOTIATE_EXTENDED_SESSIONSECURITY:
						message.MIC = message_bytes[offset:offset+16]
						offset += 16
						break

		message.Payload = struct.unpack(f"{len(message_bytes)-offset}s", message_bytes[offset:])[0]

		return message

class FIELDS(object):
	"""docstring for Base MESSAGE"""
	def __init__(self, name=Z(0), offset=NUL):
		self.NameLen = len(name)
		self.NameMaxLen = self.NameLen

		self.NameBufferOffset = NUL
		if len(name):
			self.NameBufferOffset = offset

	def to_bytes(self):
		bytes_chunks = []

		bytes_chunks.append(struct.pack("<H", self.NameLen))
		bytes_chunks.append(struct.pack("<H", self.NameMaxLen))
		bytes_chunks.append(struct.pack("<I", self.NameBufferOffset))

		return b"".join(bytes_chunks)

	@classmethod
	def from_bytes(cls, message_bytes):
		field = cls()

		field.NameLen 			= struct.unpack("<H", message_bytes[:2])[0]
		field.NameMaxLen 		= struct.unpack("<H", message_bytes[2:4])[0]
		field.NameBufferOffset 	= struct.unpack("<I", message_bytes[4:])[0]

		return field