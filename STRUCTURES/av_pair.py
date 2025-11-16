from .single_host import SINGLE_HOST
from ntlm.utils import Z
from ntlm.constants import NUL, MsvAvEOL, MsvAvNbComputerName, MsvAvNbDomainName,\
							MsvAvDnsComputerName, MsvAvDnsDomainName, MsvAvDnsTreeName,\
							MsvAvFlags, MsvAvTimestamp, MsvAvSingleHost, MsvAvTargetName,\
							MsvAvChannelBindings
from datetime import datetime, timezone
import struct

class AV_PAIR_LIST(object):
	def __init__(self, infos={}):
		self.av_pairs = []
		EOL = False

		av_list = {
			MsvAvNbComputerName:	infos["workstation"] if "workstation" in infos else Z(0),
			MsvAvNbDomainName:		infos["domain"].split('.')[0] if "domain" in infos  else Z(0),
			MsvAvDnsComputerName:	infos["workstation"] + '.' + infos["domain"] if "domain" in infos and "workstation" in infos  else Z(0),
			MsvAvDnsDomainName:		infos["domain"] if "domain" in infos else Z(0),
			MsvAvDnsTreeName:		infos["domain"] if "domain" in infos else Z(0),
			MsvAvFlags:				0,
			MsvAvTimestamp:			int((datetime.now().timestamp() - datetime(1601, 1, 1, tzinfo=timezone.utc).timestamp()) * 10**7),
			MsvAvSingleHost:		infos["custom_data"] if "custom_data" in infos else Z(0),
			MsvAvTargetName:		infos["target"] if "target" in infos else Z(0),
			#MsvAvChannelBindings:	infos["domain"] if "domain" in infos,
			MsvAvEOL:				1
		}

		for av_id in av_list:
			if av_id == MsvAvEOL:
				EOL = True
				continue

			self.add(AV_PAIR().set_av_pair(av_id, av_list[av_id]))

		if EOL:
			self.add(AV_PAIR())

		self.av_pairs = list(filter(lambda x: x is not None, self.av_pairs))

	def __len__(self):
		length = 0
		for packed_av in self.av_pairs:
			length += len(packed_av)

		return length

	def add(self, av_pair):
		self.av_pairs.append(av_pair)

	def to_bytes(self):
		bytes_chunks = []

		for i, av_pair in enumerate(self.av_pairs):
			bytes_chunks.append(av_pair.to_bytes())

		return b"".join(bytes_chunks)

	@classmethod
	def from_bytes(cls, message_bytes):
		av_list = cls()
		av_list.av_pairs = []

		while message_bytes:
			av_pair, message_bytes = AV_PAIR.from_bytes(message_bytes)
			av_list.add(av_pair)

		return av_list


class AV_PAIR(object):
	def __init__(self):
		self.av_id = MsvAvEOL
		self.av_len = NUL
		self.value = Z(0)

	def __len__(self):
		return self.av_len

	def set_av_pair(self, av_id, value):
		if not value:
			return None

		self.av_id = av_id

		if self.av_id in {MsvAvNbComputerName, MsvAvNbDomainName, MsvAvDnsComputerName, MsvAvDnsDomainName, MsvAvDnsTreeName, MsvAvTargetName}:
			self.value = value.encode("utf-16-le")
			self.av_len = len(self.value)
		if self.av_id == MsvAvFlags:
			self.value = value
			self.av_len = 4
		if self.av_id == MsvAvTimestamp:
			self.value = value
			self.av_len = 8
		if self.av_id == MsvAvSingleHost:
			self.value = SINGLE_HOST(value)
			self.av_len = self.value.len()
		if self.av_id == MsvAvChannelBindings:
			pass

		return self

	def to_bytes(self):
		bytes_chunks = []

		bytes_chunks.append(struct.pack("<H", self.av_id))
		bytes_chunks.append(struct.pack("<H", self.av_len))

		if self.av_id in {MsvAvNbComputerName, MsvAvNbDomainName, MsvAvDnsComputerName, MsvAvDnsDomainName, MsvAvDnsTreeName, MsvAvTargetName}:
			bytes_chunks.append(struct.pack(f"{self.av_len}s", self.value))
		if self.av_id == MsvAvFlags:
			bytes_chunks.append(struct.pack(f"<I", self.value))
		if self.av_id == MsvAvTimestamp:
			bytes_chunks.append(struct.pack("<Q", self.value))
		if self.av_id == MsvAvSingleHost:
			bytes_chunks.append(self.value.to_bytes())
		if self.av_id == MsvAvChannelBindings:
			pass

		return b"".join(bytes_chunks)

	@classmethod
	def from_bytes(cls, message_bytes):
		av_pair = cls()

		av_pair.av_id = struct.unpack("<H", message_bytes[:2])[0]
		av_pair.av_len = struct.unpack("<H", message_bytes[2:4])[0]

		value = message_bytes[4:4+av_pair.av_len]
		if av_pair.av_id in {MsvAvNbComputerName, MsvAvNbDomainName, MsvAvDnsComputerName, MsvAvDnsDomainName, MsvAvDnsTreeName, MsvAvTargetName}:
			av_pair.value = struct.unpack(f"{av_pair.av_len}s", value)[0]
		if av_pair.av_id == MsvAvFlags:
			av_pair.value = struct.unpack(f"<I", value)[0]
		if av_pair.av_id == MsvAvTimestamp:
			av_pair.value = struct.unpack("<Q", value)[0]
		if av_pair.av_id == MsvAvSingleHost:
			av_pair.value = av_pair.value.from_bytes(value)
		if av_pair.av_id == MsvAvChannelBindings:
			pass

		return av_pair, message_bytes[4+av_pair.av_len:]