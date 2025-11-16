from .single_host import SINGLE_HOST
from ntlm.utils import Z
from ntlm.constants import NUL, MsvAvEOL, MsvAvNbComputerName, MsvAvNbDomainName,\
							MsvAvDnsComputerName, MsvAvDnsDomainName, MsvAvDnsTreeName,\
							MsvAvFlags, MsvAvTimestamp, MsvAvSingleHost, MsvAvTargetName,\
							MsvAvChannelBindings
from datetime import datetime, timezone
import struct

class AV_PAIR_LIST(object):
	def __init__(self, av_list={}):
		self.av_pairs = []
		EOL = False

		for av_id in av_list:
			if av_id == MsvAvEOL:
				EOL = True
				continue

			self.add(AV_PAIR().set_av_pair(av_id, av_list[av_id]))

		if EOL:
			self.add(AV_PAIR())

	def __len__(self):
		length = 0
		for packed_av in self.av_pairs:
			length += len(packed_av)

		return length

	def add(self, av_pair):
		self.av_pairs.append(av_pair)

	def to_bytes(self):
		for av_pair, i in enumerate(self.av_pairs):
			self.av_pairs[i] = av_pair.to_bytes()

		return b"".join(self.av_pairs)

	@classmethod
	def from_bytes(cls, message_bytes):
		av_pairs = cls()

		while message_bytes:
			av_pair, message_bytes = AV_PAIR.from_bytes(message_bytes)
			av_pairs.add(av_pair)

		return av_pairs


class AV_PAIR(object):
	def __init__(self):
		self.av_id = MsvAvEOL
		self.len = NUL
		self.value = Z(0)

	def __len__(self):
		return self.len

	def set_av_pair(self, av_id, value):
		self.av_id = av_id

		if self.av_id in {MsvAvNbComputerName, MsvAvNbDomainName, MsvAvDnsComputerName, MsvAvDnsDomainName, MsvAvDnsTreeName, MsvAvTargetName}:
			self.value = value.encode("utf-16-le")
			self.len = len(value)
		if self.av_id == MsvAvFlags:
			self.value = value
			self.len = 4
		if self.av_id == MsvAvTimestamp:
			self.value = int((datetime.now().timestamp() - datetime(1601, 1, 1, tzinfo=timezone.utc).timestamp()) * 10**7)
			self.len = 8
		if self.av_id == MsvAvSingleHost:
			self.value = SINGLE_HOST()
			self.len = self.value.len()
		if self.av_id == MsvAvChannelBindings:
			pass

	def to_bytes(self):
		if self.av_id in {MsvAvNbComputerName, MsvAvNbDomainName, MsvAvDnsComputerName, MsvAvDnsDomainName, MsvAvDnsTreeName, MsvAvTargetName}:
			self.value = struct.pack(f"{self.len}s", self.value)
		if self.av_id == MsvAvFlags:
			self.value = struct.pack(f"<I", self.value)
		if self.av_id == MsvAvTimestamp:
			self.value = struct.pack("<Q", self.value)
		if self.av_id == MsvAvSingleHost:
			self.value = self.value.to_bytes()
		if self.av_id == MsvAvChannelBindings:
			pass

		self.av_id = struct.pack("<H", self.av_id)
		self.len = struct.pack("<H", self.len)
		
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)

	@classmethod
	def from_bytes(cls, message_bytes):
		av_pair = cls()

		av_pair.av_id = struct.unpack("<H", message_bytes[:2])[0]
		av_pair.len = struct.unpack("<H", message_bytes[2:4])[0]

		value = message_bytes[4:4+av_pair.len]
		if av_pair.av_id in {MsvAvNbComputerName, MsvAvNbDomainName, MsvAvDnsComputerName, MsvAvDnsDomainName, MsvAvDnsTreeName, MsvAvTargetName}:
			av_pair.value = struct.unpack(f"{av_pair.len}s", value)[0]
		if av_pair.av_id == MsvAvFlags:
			av_pair.value = struct.unpack(f"<I", value)[0]
		if av_pair.av_id == MsvAvTimestamp:
			av_pair.value = struct.unpack("<Q", value)[0]
		if av_pair.av_id == MsvAvSingleHost:
			av_pair.value = av_pair.value.from_bytes(value)
		if av_pair.av_id == MsvAvChannelBindings:
			pass

		return av_pair, message_bytes[4+av_pair.len:]