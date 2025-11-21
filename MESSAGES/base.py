import struct

from ntlm.utils import Z
from ntlm.constants import NUL, NTLM_NEGOTIATE, NTLM_CHALLENGE, NTLM_AUTHENTICATE, MSV_AV_FLAGS
from ntlm.STRUCTURES import NEGOTIATE_FLAGS, NTLMv2_CLIENT_CHALLENGE, VERSION

class MESSAGE(object):
	"""
	Represents an NTLM message structure capable of serializing and
	deserializing NTLM NEGOTIATE, CHALLENGE, and AUTHENTICATE messages.

	This class handles:
	  - Common NTLM header fields (`Signature`, `MessageType`)
	  - Message-specific field structures (e.g., domain/workstation fields,
		response fields, target info, negotiate flags)
	  - Optional fields such as the NTLM version and MIC
	  - The raw payload stored after the fixed header region

	The internal layout and encoding follow the Microsoft NTLM protocol
	specification, with different fields depending on the message type.

	Parameters
	----------
	message_type : int, optional
		The NTLM message type (`NTLM_NEGOTIATE`, `NTLM_CHALLENGE`,
		`NTLM_AUTHENTICATE`). Determines which fields are initialized.
		Defaults to `NUL`.

	Attributes
	----------
	Signature : bytes
		The fixed NTLM signature: b'NTLMSSP\0'.
	MessageType : int
		Message type identifier.
	Payload : bytes
		Additional raw data appended after the structured header.

	Methods
	-------
	charset(flags, oem_encoding):
		Determines the character encoding (Unicode or OEM) based on the
		negotiate flags.

	display_info(obj=None, indent=0):
		Recursively prints a structured, human-readable representation of
		the message fields and their values.

	to_bytes():
		Serializes the message to its binary form, assembling all required
		fields in the correct order as defined by the NTLM protocol.

	from_bytes(message_bytes):
		Class method that parses a binary NTLM message and reconstructs
		a fully populated `MESSAGE` instance, including optional fields
		such as Version and MIC when present.

	Notes
	-----
	- The field layout depends heavily on the message type and on negotiated
	  flags such as `NEGOTIATE_VERSION` and `NEGOTIATE_EXTENDED_SESSIONSECURITY`.
	- This class relies on helper structures such as `FIELDS`,
	  `NEGOTIATE_FLAGS`, and `VERSION` to parse or serialize each section.
	- MIC extraction for NTLMv2 is performed conditionally based on the
	  values of the AV pairs and security flags.
	"""
	def __init__(self, message_type=NUL):
		self.Signature = b'NTLMSSP\0'
		self.MessageType = message_type

		if self.MessageType == NTLM_NEGOTIATE:
			self.NegotiateFlags		= None
			self.DomainNameFields	= None
			self.WorkstationFields	= None
		elif self.MessageType == NTLM_CHALLENGE:
			self.TargetNameFields	= None
			self.NegotiateFlags		= None
			self.ServerChallenge	= None
			self.Reserved			= None
			self.TargetInfoFields	= None
		elif self.MessageType == NTLM_AUTHENTICATE:
			self.LmChallengeResponseFields			= None
			self.NtChallengeResponseFields			= None
			self.DomainNameFields					= None
			self.UserNameFields						= None
			self.WorkstationFields					= None
			self.EncryptedRandomSessionKeyFields	= None
			self.NegotiateFlags						= None

		self.Version = None

		if self.MessageType == NTLM_AUTHENTICATE:
			self.MIC = None

		self.Payload = b""

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

		if self.MessageType == NTLM_NEGOTIATE:
			bytes_chunks.append(self.NegotiateFlags.to_bytes())
			bytes_chunks.append(self.DomainNameFields.to_bytes())
			bytes_chunks.append(self.WorkstationFields.to_bytes())
		elif self.MessageType == NTLM_CHALLENGE:
			bytes_chunks.append(self.TargetNameFields.to_bytes())
			bytes_chunks.append(self.NegotiateFlags.to_bytes())
			bytes_chunks.append(self.ServerChallenge)
			bytes_chunks.append(self.Reserved)
			bytes_chunks.append(self.TargetInfoFields.to_bytes())
		elif self.MessageType == NTLM_AUTHENTICATE:
			bytes_chunks.append(self.LmChallengeResponseFields.to_bytes())
			bytes_chunks.append(self.NtChallengeResponseFields.to_bytes())
			bytes_chunks.append(self.DomainNameFields.to_bytes())
			bytes_chunks.append(self.UserNameFields.to_bytes())
			bytes_chunks.append(self.WorkstationFields.to_bytes())
			bytes_chunks.append(self.EncryptedRandomSessionKeyFields.to_bytes())
			bytes_chunks.append(self.NegotiateFlags.to_bytes())

		if self.NegotiateFlags & NEGOTIATE_FLAGS.NEGOTIATE_VERSION:
			bytes_chunks.append(self.Version.to_bytes())

		if self.MessageType == NTLM_AUTHENTICATE:
			bytes_chunks.append(self.MIC)

		bytes_chunks.append(struct.pack(f"{len(self.Payload)}s", self.Payload))
		return b"".join(bytes_chunks)

	@classmethod
	def from_bytes(cls, message_bytes):
		message = cls()

		message.Signature = struct.unpack("8s", message_bytes[:8])[0]
		message.MessageType = struct.unpack("<I", message_bytes[8:12])[0]

		if message.MessageType == NTLM_NEGOTIATE:
			message.NegotiateFlags		= NEGOTIATE_FLAGS.from_bytes(message_bytes[12:16])
			message.DomainNameFields	= FIELDS.from_bytes(message_bytes[16:24])
			message.WorkstationFields	= FIELDS.from_bytes(message_bytes[24:32])
			offset = 32
		elif message.MessageType == NTLM_CHALLENGE:
			message.TargetNameFields	= FIELDS.from_bytes(message_bytes[12:20])
			message.NegotiateFlags		= NEGOTIATE_FLAGS.from_bytes(message_bytes[20:24])
			message.ServerChallenge		= message_bytes[24:32]
			message.Reserved			= message_bytes[32:40]
			message.TargetInfoFields	= FIELDS.from_bytes(message_bytes[40:48])
			offset = 48
		elif message.MessageType == NTLM_AUTHENTICATE:
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

		if message.MessageType == NTLM_AUTHENTICATE:
			if message.NtChallengeResponseFields.Len > 24:
				print(message_bytes[message.NtChallengeResponseFields.BufferOffset+16:message.NtChallengeResponseFields.Len])
				client_challenge = NTLMv2_CLIENT_CHALLENGE.from_bytes(message_bytes[message.NtChallengeResponseFields.BufferOffset+16:message.NtChallengeResponseFields.BufferOffset+message.NtChallengeResponseFields.Len])
				av_pairs = client_challenge.AvPairs.av_pairs

				for av_pair in av_pairs:
					if av_pair.av_id == MSV_AV_FLAGS and av_pair.value & 0x00000002 and message.NegotiateFlags & NEGOTIATE_FLAGS.NEGOTIATE_EXTENDED_SESSIONSECURITY:
						message.MIC = message_bytes[offset:offset+16]
						offset += 16
						break

		message.Payload = struct.unpack(f"{len(message_bytes)-offset}s", message_bytes[offset:])[0]

		return message

class FIELDS(object):
	"""
	Represents a serializable field descriptor containing length and offset
	metadata, intended to be converted to and from a binary format.

	This class models a simple header composed of three values:
	- `Len`: the current length of the field (in bytes)
	- `MaxLen`: the maximum allowed length
	- `BufferOffset`: the position in an external buffer where the actual data
	  is stored

	Parameters
	----------
	name : sequence, optional
		Value used to determine the field's length. Its length initializes
		`Len` and `MaxLen`. Defaults to `Z(0)`.
	offset : int, optional
		Offset that initializes `BufferOffset`. Defaults to `NUL`.

	Methods
	-------
	to_bytes():
		Serializes the instance to binary format using the structure:
			<H Len> <H MaxLen> <I BufferOffset>
		and returns a `bytes` object.

	from_bytes(message_bytes):
		Class method that reconstructs an instance from a binary block following
		the same serialization structure.

	Notes
	-----
	This class does not store the actual data, but only metadata pointing to
	where the field is stored in an external buffer.
	"""
	def __init__(self, name=Z(0), offset=NUL):
		self.Len = len(name)
		self.MaxLen = self.Len

		self.BufferOffset = NUL
		if len(name):
			self.BufferOffset = offset

	def to_bytes(self):
		bytes_chunks = []

		bytes_chunks.append(struct.pack("<H", self.Len))
		bytes_chunks.append(struct.pack("<H", self.MaxLen))
		bytes_chunks.append(struct.pack("<I", self.BufferOffset))

		return b"".join(bytes_chunks)

	@classmethod
	def from_bytes(cls, message_bytes):
		field = cls()

		field.Len 			= struct.unpack("<H", message_bytes[:2])[0]
		field.MaxLen 		= struct.unpack("<H", message_bytes[2:4])[0]
		field.BufferOffset 	= struct.unpack("<I", message_bytes[4:])[0]

		return field