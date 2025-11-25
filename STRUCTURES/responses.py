import struct

from ntlm.utils import nonce, Z
from ntlm.constants import MSV_AV_TIMESTAMP

from .av_pair import AV_PAIR_LIST

class RESPONSE(object):
	"""
	Represents an NTLM response structure such as LM, NT, or NTLMv2 responses.

	This class encapsulates the variable-length authentication response data
	that appears in NTLM AUTHENTICATE messages. A response typically consists of
	a fixed-size portion (e.g., LM/NT hash or NTLMv2 HMAC) followed by optional
	additional data such as the NTLMv2 client challenge structure.

	Parameters
	----------
	response : bytes, optional
		Initial response value. Defaults to 24 zero bytes (`Z(24)`), which
		matches the size of an LM/NT challenge response in legacy NTLM.

	Attributes
	----------
	Response : bytes
		The main response block (usually 24 bytes).
	ChallengeFromClient : bytes, optional
		Additional data appended after the initial response (e.g., NTLMv2
		client challenge fields), populated by `from_bytes()`.

	Methods
	-------
	__len__():
		Returns the total number of bytes contained in the response object.
	to_bytes():
		Serializes the response fields into a contiguous byte string.
	from_bytes(message_bytes):
		Class method that parses a raw response from bytes, separating the
		fixed 24-byte portion from any remaining client challenge data.

	Notes
	-----
	- This class does not interpret the internal structure of NTLMv2
	  client challenge data; it simply stores and concatenates it.
	- The length of the initial `Response` field (24 bytes) follows the
	  NTLM specification for LM and NT responses.
	"""
	def __init__(self, response=Z(24), challenge=Z(0)):
		self.Response = response
		self.ChallengeFromClient = challenge

	def __len__(self):
		values = [getattr(self, attr) for attr in vars(self)]

		length = 0
		for value in values:
			length += len(value)

		return length

	def to_bytes(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)

	@classmethod
	def from_bytes(cls, message_bytes):
		response = cls()

		response.Response = message_bytes[:24]
		response.ChallengeFromClient = message_bytes[24:]

		return response

class NTLMv2_CLIENT_CHALLENGE(object):
	"""
	Represents an NTLMv2 Client Challenge structure (a component of the
	NTLMv2 authentication response).

	This structure appears inside the NT challenge response of an NTLMv2
	AUTHENTICATE message and contains metadata used in the NTLMv2 proof-of-
	possession calculation, including the timestamp, an 8-byte client
	challenge, and a list of AV pairs (attribute–value pairs).

	Parameters
	----------
	av_list : AV_PAIR_LIST, optional
		The list of AV pairs to embed inside the challenge structure.
		Defaults to an empty `AV_PAIR_LIST()`.
	challenge : bytes, optional
		The 8-byte client challenge (nonce). Defaults to `nonce(64)`,
		which produces a 64-bit random value.

	Attributes
	----------
	RespType : bytes
		The response type, always set to ``b"\\x01"``.
	HiRespType : bytes
		The high-order response type, also ``b"\\x01"``.
	Reserved1 : bytes
		Two reserved bytes (zero).
	Reserved2 : bytes
		Four reserved bytes (zero).
	TimeStamp : int
		The 64-bit Windows FILETIME timestamp extracted from the AV pair list,
		if present.
	ChallengeFromClient : bytes
		The 8-byte client nonce used in NTLMv2 authentication.
	Reserved3 : bytes
		Four reserved bytes (zero).
	AvPairs : AV_PAIR_LIST
		The attribute–value pair list encoding metadata such as domain,
		workstation, timestamps, flags, etc.

	Methods
	-------
	to_bytes():
		Serializes the NTLMv2 client challenge structure into its binary
		representation following the NTLMv2 specification.
	from_bytes(message_bytes):
		Parses raw bytes into a new `NTLMv2_CLIENT_CHALLENGE` instance.

	Notes
	-----
	- The timestamp (`TimeStamp`) is extracted dynamically from the AV pair
	  list, specifically from the `MSV_AV_TIMESTAMP` AV pair if present.
	- The order and layout of fields strictly follow Microsoft's NTLMv2
	  specification.
	- This class does not compute the HMAC or proof string; it only models
	  the internal client challenge block used in the NTLMv2 response.
	"""
	def __init__(self, target_info=AV_PAIR_LIST(), challenge=nonce(64)):
		self.RespType = b"\x01"
		self.HiRespType = b"\x01"
		self.Reserved1 = Z(2)
		self.Reserved2 = Z(4)
		self.TimeStamp = target_info.MsvAvTimestamp.value
		self.ChallengeFromClient = challenge
		self.Reserved3 = Z(4)
		self.AvPairs = target_info

	def to_bytes(self):
		bytes_chunks = []

		bytes_chunks.append(self.RespType)
		bytes_chunks.append(self.HiRespType)
		bytes_chunks.append(self.Reserved1)
		bytes_chunks.append(self.Reserved2)
		bytes_chunks.append(struct.pack("<Q", self.TimeStamp))
		bytes_chunks.append(self.ChallengeFromClient)
		bytes_chunks.append(self.Reserved3)
		bytes_chunks.append(self.AvPairs.to_bytes())

		return b"".join(bytes_chunks)

	@classmethod
	def from_bytes(cls, message_bytes):
		ntlmv2_client_challenge = cls()

		ntlmv2_client_challenge.RespType = message_bytes[:1]
		ntlmv2_client_challenge.HiRespType = message_bytes[1:2]
		ntlmv2_client_challenge.Reserved1 = message_bytes[2:4]
		ntlmv2_client_challenge.Reserved2 = message_bytes[4:8]
		ntlmv2_client_challenge.TimeStamp = struct.unpack("<Q", message_bytes[8:16])[0]
		ntlmv2_client_challenge.ChallengeFromClient = message_bytes[16:24]
		ntlmv2_client_challenge.Reserved3 = message_bytes[24:28]
		ntlmv2_client_challenge.AvPairs = AV_PAIR_LIST.from_bytes(message_bytes[28:])

		return ntlmv2_client_challenge