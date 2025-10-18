from .base import MESSAGE, FIELDS
from ntlm.constants import NtLmChallenge, MsvAvEOL
from ntlm.STRUCTURES import VERSION, AV_PAIR
import struct

class CHALLENGE(MESSAGE):
	"""docstring for CHALLENGE"""
	def __init__(self, flags, target_name="", av_list="", major_version=0x0, minor_version=0x0, build=0x0, oem_encoding="cp850"):
		super(CHALLENGE, self).__init__(NtLmNegotiate)

		offset = 56 if flags.dict["NEGOTIATE_VERSION"] else 48
		encoding = super(CHALLENGE, self).charset(flags, oem_encoding)

		target_name = target_name.encode(encoding) if flags.dict["REQUEST_TARGET"] and len(target_name) else b""
		target_info = AV_PAIR(av_list) if flags.dict["NEGOTIATE_TARGET_INFO"] and len(target_info) else AV_PAIR(MsvAvEOL)

		self.TargetNameFields = FIELDS(target_name).pack()
		self.message.TargetInfoFields = FIELDS(target_info, len(target_name)).pack()

		self.NegotiateFlags = flags.pack
		self.ServerChallenge = struct.pack("<Q", 0)
		self.Reserved = struct.pack("<Q", 0)

		self.Version = VERSION(major_version, minor_version, build).pack() if flags.dict["NEGOTIATE_VERSION"] else VERSION(0, 0, 0).pack()

		self.Payload += struct.pack(f"<{target_name_length}s", target_name)
		self.Payload += target_info.pack()