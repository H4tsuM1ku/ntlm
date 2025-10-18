from .base import MESSAGE_INTERFACE, FIELDS
from ntlm.constants import NtLmChallenge
from ntlm.STRUCTURES import VERSION
import struct

class CHALLENGE(MESSAGE_INTERFACE):
	"""docstring for CHALLENGE"""
	def __init__(self, flags, target_name="", target_info="", major_version=0x0, minor_version=0x0, build=0x0, oem_encoding="cp850"):
		self.message = MESSAGE_INTERFACE(NtLmChallenge)

		encoding = super(CHALLENGE, self).charset(flags, oem_encoding)

		target_name = target_name.encode(encoding)
		target_info = target_info.encode(encoding)

		target_name_length = len(target_name)
		target_info_length = len(target_info)

		if flags.dict["REQUEST_TARGET"]:
			self.TargetNameFields = FIELDS(target_name).pack()
		else:
			self.TargetNameFields = FIELDS("").pack()

		match (flags.dict["NEGOTIATE_TARGET_INFO"], flags.dict["REQUEST_TARGET"]):
			case (1, 1):
				self.message.TargetNameFields = FIELDS(target_name).pack()
				self.message.TargetInfoFields = FIELDS(target_info, target_name_length).pack()
			case (1, 0):
				self.message.TargetInfoFields = FIELDS(target_info).pack()
			case (0, 1)
			case (0, 0):
				self.message.TargetInfoFields = FIELDS("").pack()

		self.NegotiateFlags = flags.pack
		self.ServerChallenge = struct.pack("<Q", 0)
		self.Reserved = struct.pack("<Q", 0)


		if flags.dict["NEGOTIATE_VERSION"]:
			self.Version = VERSION(major_version, minor_version, build).pack()
		else:
			self.Version = VERSION(0, 0, 0).pack()

		if target_name_length:
			self.TargetName = struct.pack(f"<{target_name_length}s", target_name)

		if workstation_name_length:
			pass
			#self.TargetInfo = AV_PAIR()