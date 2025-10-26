from ntlm.CRYPTO import Z, nonce
import struct

class LM_RESPONSE(object):
	"""docstring for LM_RESPONSE"""
	def __init__(self, response, server_challenge):
		self.Response = 

class LMv2_RESPONSE(object):
	"""docstring for LM_RESPONSE"""
	def __init__(self, response, server_challenge):
		self.Response = 
		self.ChallengeFromClient = 

class NT_RESPONSE(object):
	"""docstring for LM_RESPONSE"""
	def __init__(self, response, server_challenge):
		self.Response = 

class NTv2_RESPONSE(object):
	"""docstring for LM_RESPONSE"""
	def __init__(self, response, server_challenge):
		self.Response = 
		self. = 

class NTLMv2_CLIENT_CHALLENGE(object):
	"""docstring for NTLMv2_CLIENT_CHALLENGE"""
	def __init__(self):
		self.RespType = b"\x01"
		self.HiRespType = b"\x01"
		self.Reserved1 = Z(2)
		self.Reserved2 = Z(4)
		self.TimeStamp = 
		self.ChallengeFromClient = struct.pack("<Q", nonce(64))
		self.Reserved3 = Z(4)
