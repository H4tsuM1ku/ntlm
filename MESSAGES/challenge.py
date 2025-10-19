from .base import MESSAGE, FIELDS
from ntlm.constants import NtLmChallenge, MsvAvEOL
from ntlm.CRYPTO import nonce
from ntlm.STRUCTURES import VERSION, AV_PAIR
import struct

class CHALLENGE(MESSAGE):
	"""docstring for CHALLENGE"""
	def __init__(self, flags, target_name="", av_list={}, major_version=0x0, minor_version=0x0, build=0x0, oem_encoding="cp850"):
		super(CHALLENGE, self).__init__(NtLmChallenge)

		offset = 56 if flags.dict["NEGOTIATE_VERSION"] else 48
		encoding = super(CHALLENGE, self).charset(flags, oem_encoding)
		version = VERSION()

		target_name = target_name.encode(encoding) if flags.dict["REQUEST_TARGET"] and len(target_name) else b""
		target_info = b""
		#target_info = AV_PAIR(av_list) if flags.dict["NEGOTIATE_TARGET_INFO"] and len(target_info) else AV_PAIR({})

		self.TargetNameFields = FIELDS(target_name, offset).pack()
		self.TargetInfoFields = FIELDS(target_info, offset, len(target_name)).pack()

		self.NegotiateFlags = flags.pack
		self.ServerChallenge = struct.pack("<Q", nonce(64))
		self.Reserved = struct.pack("<Q", 0)

		self.Version = version.get_version()
		if flags.dict["NEGOTIATE_VERSION"]:
			self.Version = version.get_version(major_version, minor_version, build)

		self.Payload += struct.pack(f"<{len(target_name)}s", target_name)
		#self.Payload += target_info.pack()