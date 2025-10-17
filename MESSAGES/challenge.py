from .base import MESSAGE, TARGET_NAME_FIELDS, TARGET_INFO_FIELDS
from ntlm.constants import NtLmChallenge
from ntlm.STRUCTURES import NEGOTIATE_FLAGS, VERSION, AV_PAIR

class CHALLENGE(MESSAGE):
	"""docstring for CHALLENGE"""
	def __init__(self, flags, target_name="", target_info="", major_version=0x0, minor_version=0x0, build=0x0, oem_encoding="cp850"):
		super(CHALLENGE, self).__init__(NtLmChallenge)
		encoding = super(CHALLENGE, self).encoding(flags, oem_encoding)

		target_name = target_name.encode(encoding)
		workstation_name = workstation_name.encode(encoding)

		domain_name_length = len(target_name)
		workstation_name_length = len(workstation_name)

		if flags.dict["REQUEST_TARGET"]:
			self.TargetNameFields = TARGET_NAME_FIELDS(target_name).pack()
		else:
			self.TargetNameFields = TARGET_NAME_FIELDS("").pack()

		self.NegotiateFlags = flags.pack
		self.ServerChallenge = struct.pack("<Q", 0)
		self.Reserved = struct.pack("<Q", 0)


		match (flags.dict["NEGOTIATE_TARGET_INFO"], flags.dict["REQUEST_TARGET"]):
			case (1, 1):
				self.TargetInfoFields = TARGET_INFO_FIELDS(target_info, len(target_name)).pack()
			case (1, 0):
				self.TargetInfoFields = TARGET_INFO_FIELDS(target_info).pack()
			case (0, 1) | (0, 0):
				self.WorkstationFields = TARGET_INFO_FIELDS("").pack()

		if flags.dict["NEGOTIATE_VERSION"]:
			self.Version = VERSION(major_version, minor_version, build).pack()
		else:
			self.Version = VERSION(0, 0, 0).pack()

		if domain_name_length:
			self.TargetName = struct.pack(f"<{domain_name_length}s", target_name)

		if workstation_name_length:
			self.TargetInfo = AV_PAIR()