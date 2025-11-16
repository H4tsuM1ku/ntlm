from ntlm.constants import NUL
from ntlm.utils import Z, nonce
import struct

class SINGLE_HOST(object):
	def __init__(self, custom_data=Z(8)):
		self.Size = 48
		self.Z4 = Z(4)
		self.CustomData = custom_data
		self.MachineID = nonce(256)

	def __len__(self):
		return struct.unpack("<I", self.Size)[0]

	def to_bytes(self):
		bytes_chunks = []

		bytes_chunks.append(struct.unpack("<I", self.Size))
		bytes_chunks.append(self.Z4)
		bytes_chunks.append(self.CustomData)
		bytes_chunks.append(self.MachineID)
		
		return b"".join(bytes_chunks)

	@classmethod
	def from_bytes(cls, message_bytes):
		single_host = cls()

		single_host.Size 		= struct.unpack("<I", message_bytes[:4])[0]
		single_host.Z4 			= struct.unpack("<I", message_bytes[4:8])[0]
		single_host.CustomData 	= struct.unpack("<I", message_bytes[8:16])[0]
		single_host.MachineID 	= message_bytes[16:]

		return single_host