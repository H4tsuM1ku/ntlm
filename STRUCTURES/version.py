from ntlm.utils import Z
from ntlm.constants import NUL
import struct

class VERSION(object):
	"""
	Represents the NTLM version structure, included optionally in NTLM messages
	when the `NEGOTIATE_VERSION` flag is set.

	This structure provides product version information and a revision number,
	allowing clients and servers to negotiate capabilities based on version.

	Parameters
	----------
	major_version : int, optional
		The major version number of the product. Defaults to `NUL` (0).
	minor_version : int, optional
		The minor version number of the product. Defaults to `NUL` (0).
	build : int, optional
		The build number of the product. Defaults to `NUL` (0).
	revision : int, optional
		NTLM revision level. Defaults to `NUL` (0).

	Attributes
	----------
	ProductMajorVersion : int
		Major version of the NTLM implementation.
	ProductMinorVersion : int
		Minor version of the NTLM implementation.
	ProductBuild : int
		Build number of the NTLM implementation.
	Reserved : bytes
		Three reserved bytes (always zero).
	NTLMRevisionCurrent : int
		Revision number of the NTLM implementation.

	Methods
	-------
	to_bytes():
		Serializes the version information into an 8-byte NTLM structure.
	from_bytes(message_bytes):
		Class method that parses an 8-byte version structure from raw bytes.

	Notes
	-----
	- The byte layout is as follows:
		<MajorVersion (1 byte)> <MinorVersion (1 byte)> <Build (2 bytes little-endian)>
		<Reserved (3 bytes)> <Revision (1 byte)>
	- This structure is used to indicate client or server capabilities and
	  does not affect cryptographic operations directly.
	- The reserved bytes are typically zero and must be preserved in
	  serialization and deserialization.
	"""
	def __init__(self, major_version=NUL, minor_version=NUL, build=NUL, revision=NUL):
		self.ProductMajorVersion = major_version
		self.ProductMinorVersion = minor_version
		self.ProductBuild = build
		self.Reserved = Z(3)
		self.NTLMRevisionCurrent = revision

	def to_bytes(self):
		bytes_chunks = []

		bytes_chunks.append(struct.pack("B", self.ProductMajorVersion))
		bytes_chunks.append(struct.pack("B", self.ProductMinorVersion))
		bytes_chunks.append(struct.pack("<H", self.ProductBuild))
		bytes_chunks.append(self.Reserved)
		bytes_chunks.append(struct.pack("B", self.NTLMRevisionCurrent))

		return b"".join(bytes_chunks)

	@classmethod
	def from_bytes(cls, message_bytes):
		version = cls()
		
		version.ProductMajorVersion 	= message_bytes[0]
		version.ProductMinorVersion		= message_bytes[1]
		version.ProductBuild 			= struct.unpack("<H", message_bytes[2:4])[0]
		version.Reserved 				= message_bytes[4:7]
		version.NTLMRevisionCurrent 	= message_bytes[7]

		return version