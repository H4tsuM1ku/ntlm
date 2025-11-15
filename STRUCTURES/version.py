from ntlm.utils import Z
from ntlm.constants import NUL
import struct

class VERSION(object):
	"""
	NTLM VERSION structure.

	This structure identifies the operating system version and NTLMSSP revision
	used in the NTLM protocol exchanges. It consists of versioning fields
	describing the OS and a revision field that specifies the NTLMSSP version.

	Fields
	-------
	ProductMajorVersion (1 byte):
		An 8-bit unsigned integer that SHOULD contain the major version number
		of the operating system in use.

	ProductMinorVersion (1 byte):
		An 8-bit unsigned integer that SHOULD contain the minor version number
		of the operating system in use.

	ProductBuild (2 bytes):
		A 16-bit unsigned integer that contains the build number of the
		operating system in use. This field SHOULD identify the OS build number.

	Reserved (3 bytes):
		A 24-bit field that SHOULD be set to zero and MUST be ignored by the
		recipient.

	NTLMRevisionCurrent (1 byte):
		An 8-bit unsigned integer that indicates the current revision of the
		NTLMSSP in use. This field SHOULD contain the following value 0x0F.
	"""
	def __init__(self, major_version=NUL, minor_version=NUL, build=NUL, revision=NUL):
		self.ProductMajorVersion = major_version
		self.ProductMinorVersion = minor_version
		self.ProductBuild = build
		self.Reserved = Z(3)
		self.NTLMRevisionCurrent = revision

	def to_bytes(self):
		self.ProductMajorVersion 	= struct.pack("B", self.ProductMajorVersion)
		self.ProductMinorVersion	= struct.pack("B", self.ProductMinorVersion)
		self.ProductBuild 			= struct.pack("<H", self.ProductBuild)
		self.Reserved				= struct.pack("3B", (self.Reserved >> 16) & 0xff,
										(self.Reserved >> 8) & 0xff,
										self.Reserved & 0xff)
		self.NTLMRevisionCurrent 	= struct.pack("B", self.NTLMRevisionCurrent)

		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)

	@classmethod
	def from_bytes(cls, message_bytes):
		version = cls()
		
		version.ProductMajorVersion 	= message_bytes[0]
		version.ProductMinorVersion		= message_bytes[1]
		version.ProductBuild 			= struct.unpack("<H", message_bytes[2:4])[0]
		version.Reserved 				= struct.unpack("3B", message_bytes[4:7])[0]
		version.NTLMRevisionCurrent 	= message_bytes[7]

		return version