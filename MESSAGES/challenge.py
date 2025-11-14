from .base import MESSAGE, FIELDS
from ntlm.utils import nonce, Z
from ntlm.constants import NUL, NTLMSSP_REVISION_W2K3, NtLmChallenge, MsvAvEOL
from ntlm.STRUCTURES import NEGOTIATE_FLAGS, VERSION, AV_PAIR_LIST
import struct

class CHALLENGE(MESSAGE):
	"""docstring for CHALLENGE"""
	def __init__(self, flags=NEGOTIATE_FLAGS(1), infos={}, av_list={}, version_infos=(NUL, NUL, NUL), oem_encoding="cp850"):
		super(CHALLENGE, self).__init__(NtLmChallenge)

		encoding = super(CHALLENGE, self).charset(flags, oem_encoding)

		target_name = Z(0)
		if (flags.dict["REQUEST_TARGET"] or flags.dict["TARGET_TYPE_SERVER"] or flags.dict["TARGET_TYPE_DOMAIN"]) and len(infos["target"]):
			target_name = infos["target"].encode(encoding)
		
		target_info = AV_PAIR_LIST(av_list) if flags.dict["NEGOTIATE_TARGET_INFO"] else AV_PAIR_LIST()

		offset = 48
		self.Version = Z(0)
		if flags.dict["NEGOTIATE_VERSION"]:
			self.Version = VERSION(*version_infos, NTLMSSP_REVISION_W2K3)
			offset += 8

		self.TargetNameFields, offset = FIELDS(target_name, offset), offset + len(target_name)
		self.TargetInfoFields, offset = FIELDS(target_info, offset), offset + len(target_info)

		self.NegotiateFlags = flags
		self.ServerChallenge = nonce(64)
		self.Reserved = Z(8)

		self.Payload += target_name
		self.Payload += target_info.to_bytes()