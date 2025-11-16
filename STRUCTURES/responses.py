from ntlm.utils import nonce, Z
from ntlm.constants import MsvAvTimestamp
from ntlm.STRUCTURES import AV_PAIR_LIST
import struct

class RESPONSE(object):
	def __init__(self, response=Z(24)):
		self.Response = response

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
	"""docstring for NTLMv2_CLIENT_CHALLENGE"""
	def __init__(self, av_list=AV_PAIR_LIST(), challenge=nonce(64)):
		self.RespType = b"\x01"
		self.HiRespType = b"\x01"
		self.Reserved1 = Z(2)
		self.Reserved2 = Z(4)

		for av_pair in av_list.av_pairs:
			if av_pair and av_pair.av_id == MsvAvTimestamp:
				self.TimeStamp = av_pair.value

		self.ChallengeFromClient = challenge
		self.Reserved3 = Z(4)
		self.AvPairs = av_list

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
		ntlmv2_client_challenge.TimeStamp = struct.unpack("<Q", message_bytes[8:16])
		ntlmv2_client_challenge.ChallengeFromClient = message_bytes[16:24]
		ntlmv2_client_challenge.Reserved3 = message_bytes[24:28]
		ntlmv2_client_challenge.AvPairs = AV_PAIR_LIST.from_bytes(message_bytes[28:])

		return ntlmv2_client_challenge