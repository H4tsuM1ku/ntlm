from ntlm.CRYPTO import Z, nonce
import struct

class LM_RESPONSE(object):
	"""docstring for LM_RESPONSE"""
	def __init__(self, response):
		self.Response = response

	def pack(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)

class LMv2_RESPONSE(object):
	"""docstring for LM_RESPONSE"""
	def __init__(self, response, challenge):
		self.Response = response
		self.ChallengeFromClient = challenge

	def pack(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)

class NT_RESPONSE(object):
	"""docstring for LM_RESPONSE"""
	def __init__(self, response):
		self.Response = response

	def pack(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)

class NTv2_RESPONSE(object):
	"""docstring for LM_RESPONSE"""
	def __init__(self, response, challenge):
		self.Response = response
		self.ClientChallenge = challenge 

	def pack(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)

class NTLMv2_CLIENT_CHALLENGE(object):
	"""docstring for NTLMv2_CLIENT_CHALLENGE"""
	def __init__(self, av_pairs, time, challenge):
		self.RespType = b"\x01"
		self.HiRespType = b"\x01"
		self.Reserved1 = Z(2)
		self.Reserved2 = Z(4)
		self.TimeStamp = time
		self.ChallengeFromClient = struct.pack("<Q", challenge)
		self.Reserved3 = Z(4)
		self.AvPairs = av_pairs.pack()

	def pack(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)