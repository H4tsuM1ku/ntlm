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

		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)

	@classmethod
	def from_bytes(cls, message_bytes):
		single_host = cls()

		single_host.Size 		= struct.unpack("<I", message_bytes[:4])[0]
		single_host.Z4 			= struct.unpack("<I", message_bytes[4:8])[0]
		single_host.CustomData 	= struct.unpack("<I", message_bytes[8:16])[0]
		single_host.MachineID 	= message_bytes[16:]

		return single_host