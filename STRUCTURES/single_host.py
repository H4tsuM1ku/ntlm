import struct

from ntlm.constants import NUL
from ntlm.utils import Z, nonce


class SingleHost(object):
	"""
	Represents a single host structure containing machine-specific data.

	This class models a fixed-size header with a custom data field and a
	unique machine identifier. It can serialize to and from a binary
	representation.

	Parameters
	----------
	custom_data : bytes, optional
		Optional custom data associated with the host. Defaults to
		`Z(8)` (8 zero bytes).

	Attributes
	----------
	Size : int
		Size of the structure in bytes. Defaults to 48.
	Z4 : bytes
		Four reserved zero bytes.
	CustomData : bytes
		Custom data associated with the host.
	MachineID : bytes
		Unique 256-bit identifier for the machine (nonce).

	Methods
	-------
	__len__():
		Returns the total size of the structure in bytes.
	to_bytes():
		Serializes the structure into a contiguous byte string.
	from_bytes(message_bytes):
		Class method that parses a binary representation and returns
		a `SingleHost` instance.

	Notes
	-----
	- The structure layout is:
		<Size (4 bytes)> <Z4 (4 bytes)> <CustomData (8 bytes)> <MachineID (256 bits)>
	- `MachineID` is generated as a random nonce by default.
	- Reserved fields (`Z4`) and default custom data (`Z(8)`) are typically
	  zero-filled and may be ignored depending on context.
	"""
	def __init__(self, custom_data=Z(8)):
		self.Size = 48
		self.Z4 = Z(4)
		self.CustomData = custom_data
		self.MachineID = nonce(256)

	def __len__(self):
		return self.Size

	def to_bytes(self):
		bytes_chunks = []

		bytes_chunks.append(struct.pack("<I", self.Size))
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