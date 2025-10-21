from .base import MESSAGE, FIELDS
from ntlm.constants import NUL, NTLMSSP_REVISION_W2K3, NtLmChallenge, MsvAvEOL
from ntlm.CRYPTO import nonce
from ntlm.STRUCTURES import VERSION, AV_PAIR_LIST
import struct

class CHALLENGE(MESSAGE):
	"""docstring for CHALLENGE"""
	def __init__(self, flags, target_name="", av_list={}, major_version=NUL, minor_version=NUL, build=NUL, oem_encoding="cp850"):
		super(CHALLENGE, self).__init__(NtLmChallenge)

		offset = 56
		encoding = super(CHALLENGE, self).charset(flags, oem_encoding)
		version = VERSION()

		target_name = target_name.encode(encoding) if flags.dict["REQUEST_TARGET"] and len(target_name) else b""
		target_info = AV_PAIR_LIST(av_list) if flags.dict["NEGOTIATE_TARGET_INFO"] else AV_PAIR_LIST()

		self.TargetNameFields, offset = FIELDS(target_name, offset).pack(), offset + len(target_name)
		self.TargetInfoFields, offset = FIELDS(target_info, offset).pack(), offset + len(target_info)

		self.NegotiateFlags = flags.pack
		self.ServerChallenge = struct.pack("<Q", nonce(64))
		self.Reserved = struct.pack("<Q", NUL)

		self.Version = version.get_version()
		if flags.dict["NEGOTIATE_VERSION"]:
			self.Version = version.get_version(major_version, minor_version, build, NTLMSSP_REVISION_W2K3)

		self.Payload += struct.pack(f"<{len(target_name)}s", target_name)
		self.Payload += target_info.pack()