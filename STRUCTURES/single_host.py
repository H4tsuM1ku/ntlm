from ntlm.constants import NUL
from ntlm.CRYPTO import Z, nonce
import struct

class SINGLE_HOST(object):
	def __init__(self):
		self.Size = struct.pack("<I", 48)
		self.Z4 = Z(4)
		self.CustomData = Z(8)
		self.MachineID = nonce(256).to_bytes(32, 'little')

	def __len__(self):
		return struct.unpack("<I", self.Size)[0]

	def pack(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)