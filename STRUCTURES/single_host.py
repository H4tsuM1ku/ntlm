from ntlm.constants import NUL
from ntlm.utils import Z, nonce
import struct

class SINGLE_HOST(object):
	def __init__(self):
		self.Size = 48
		self.Z4 = Z(4)
		self.CustomData = Z(8)
		self.MachineID = nonce(256)

	def __len__(self):
		return struct.unpack("<I", self.Size)[0]

	def to_bytes(self):
		self.Size = struct.pack("<I", self.Size)
		self.MachineID = self.MachineID.to_bytes(32, 'little')

		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)

	def from_bytes(self, message_bytes):
		self.Size 		= struct.unpack("<I", message_bytes[:4])
		self.Z4 		= struct.unpack("<I", message_bytes[4:8])
		self.CustomData = struct.unpack("<I", message_bytes[8:16])
		self.MachineID 	= message_bytes[16:]

		return self