import struct

from ntlm.constants import NUL, NTLM_NEGOTIATE, NTLM_CHALLENGE, NTLM_AUTHENTICATE

from .av_pair import AvPairList
from .responses import Response

class Payload(object):
	def __init__(self, message_type):
		if message_type == NTLM_NEGOTIATE:
			self.Domain			= None
			self.Workstation	= None
		elif message_type == NTLM_CHALLENGE:
			self.Target			= None
			self.TargetInfo		= None
		elif message_type == NTLM_AUTHENTICATE:
			self.LmChallenge 				= None
			self.NtChallenge 				= None
			self.Domain						= None
			self.UserName					= None
			self.Workstation				= None
			self.EncryptedRandomSessionKey	= None

	def to_bytes(self, message_type):
		bytes_chunks = []

		if message_type == NTLM_NEGOTIATE:
			bytes_chunks.append(self.Domain)
			bytes_chunks.append(self.Workstation)
		elif message_type == NTLM_CHALLENGE:
			bytes_chunks.append(self.Target)
			bytes_chunks.append(self.TargetInfo.to_bytes())
		elif message_type == NTLM_AUTHENTICATE:
			bytes_chunks.append(self.LmChallenge.to_bytes())
			bytes_chunks.append(self.NtChallenge.to_bytes())
			bytes_chunks.append(self.Domain)
			bytes_chunks.append(self.UserName)
			bytes_chunks.append(self.Workstation)
			bytes_chunks.append(self.EncryptedRandomSessionKey)

		return b"".join(bytes_chunks)

	@classmethod
	def from_bytes(cls, message_type, message_bytes, fields):
		payload = cls(message_type)

		if message_type == NTLM_NEGOTIATE:
			payload.Domain		= message_bytes[fields[0].BufferOffset:fields[0].BufferOffset + fields[0].Len]
			payload.Workstation	= message_bytes[fields[1].BufferOffset:fields[1].BufferOffset + fields[1].Len]
		elif message_type == NTLM_CHALLENGE:
			payload.Target = message_bytes[fields[0].BufferOffset:fields[0].BufferOffset + fields[0].Len]
			payload.TargetInfo = AvPairList.from_bytes(message_bytes[fields[1].BufferOffset:fields[1].BufferOffset + fields[1].Len])
		elif message_type == NTLM_AUTHENTICATE:
			payload.LmChallenge	= Response.from_bytes(message_bytes[fields[0].BufferOffset:fields[0].BufferOffset + fields[0].Len])
			payload.NtChallenge	= Response.from_bytes(message_bytes[fields[1].BufferOffset:fields[1].BufferOffset + fields[1].Len])
			payload.Domain		= message_bytes[fields[2].BufferOffset:fields[2].BufferOffset + fields[2].Len]
			payload.UserName	= message_bytes[fields[3].BufferOffset:fields[3].BufferOffset + fields[3].Len]
			payload.Workstation	= message_bytes[fields[4].BufferOffset:fields[4].BufferOffset + fields[4].Len]
			payload.EncryptedRandomSessionKey = message_bytes[fields[5].BufferOffset:fields[5].BufferOffset + fields[5].Len]

		return payload