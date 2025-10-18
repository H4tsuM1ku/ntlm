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
	def __init__(self, major_version, minor_version, build):
		self.ProductMajorVersion = struct.pack('B', major_version)
		self.ProductMinorVersion = struct.pack('B', minor_version)
		self.ProductBuild = struct.pack('<H', build)
		self.Reserved = struct.pack('3B', 0x0, 0x0, 0x0)
		self.NTLMRevisionCurrent = struct.pack('B', 0xF)

	def pack(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)