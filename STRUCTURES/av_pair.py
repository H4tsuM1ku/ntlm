from .single_host import SINGLE_HOST
from ntlm.constants import NUL, MsvAvEOL, MsvAvNbComputerName, MsvAvNbDomainName,\
							MsvAvDnsComputerName, MsvAvDnsDomainName, MsvAvDnsTreeName,\
							MsvAvFlags, MsvAvTimestamp, MsvAvSingleHost, MsvAvTargetName,\
							MsvAvChannelBindings
import struct

class AV_PAIR_LIST(object):
	def __init__(self, av_list={}):
		self.av_pairs = []

		for av_id in av_list:
			if av_id == MsvAvEOL:
				continue

			self.add(av_id, av_list[av_id])

		self.add(MsvAvEOL, NUL)

	def __len__(self):
		length = 0
		for packed_av in self.av_pairs:
			length += len(packed_av)

		return length

	def add(self, av_id: int, value: bytes):
		self.av_pairs.append(AV_PAIR(av_id, value).pack())

	def pack(self):
		return b"".join(self.av_pairs)

class AV_PAIR(object):
	def __init__(self, av_id, value=""):
		self.av_id = struct.pack("<H", av_id)

		if av_id in {MsvAvNbComputerName, MsvAvNbDomainName, MsvAvDnsComputerName, MsvAvDnsDomainName, MsvAvDnsTreeName, MsvAvTargetName}:
			value = value.encode("utf-16-le")
			self.len = struct.pack("<H", len(value))
			self.value = struct.pack(f"<{len(value)}s", value)
		if av_id == MsvAvFlags:
			value = struct.pack(f"<I", value)
			self.len = struct.pack("<H", len(value))
			self.value = value
		if av_id == MsvAvTimestamp:
			timestamp = TIMESTAMP()
			self.len = struct.pack("<H", len(timestamp))
			self.value = timestamp.pack()
		if av_id == MsvAvSingleHost:
			single_host = SINGLE_HOST()
			self.len = struct.pack("<H", len(single_host))
			self.value = single_host.pack()
		if av_id == MsvAvEOL:
			self.len = struct.pack("<H", NUL)

	def __len__(self):
		return struct.unpack("<H", self.len)[0]

	def pack(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)