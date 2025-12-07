from datetime import datetime, timezone
import struct

from ntlm.utils import Z
from ntlm.constants import NUL, MSV_AV_NB_COMPUTER_NAME, MSV_AV_NB_DOMAIN_NAME, MSV_AV_DNS_COMPUTER_NAME,\
							MSV_AV_DNS_DOMAIN_NAME, MSV_AV_DNS_TREE_NAME, MSV_AV_FLAGS,\
							MSV_AV_TIMESTAMP, MSV_AV_SINGLE_HOST, MSV_AV_TARGET_NAME, MSV_AV_CHANNEL_BINDINGS,\
							MSV_AV_EOL
from ntlm.CRYPTO import md5

from .single_host import SingleHost

class AvPairList(object):
	"""
	Represents a list of NTLM AV (Attribute–Value) pairs used in the
	NTLMv2 Client Challenge and target information structures.

	AV pairs convey optional metadata such as workstation name, domain
	name, DNS names, flags, timestamps, and other context-specific data.

	Parameters
	----------
	infos : dict, optional
		Dictionary of information used to populate common AV pairs. Possible
		keys include:
		- "workstation": NetBIOS name of the client workstation
		- "domain": NetBIOS or DNS domain name
		- "custom_data": Optional custom field (e.g., SingleHost)
		- "target": Optional target server name
		Defaults to empty dictionary, which creates an empty AV pair list.

	Attributes
	----------
	av_pairs : list of AvPair
		List of AvPair instances representing each attribute–value entry.

	Methods
	-------
	__len__():
		Returns the total number of bytes when the AV pair list is serialized.
	add(av_pair):
		Appends a new `AvPair` instance to the list.
	to_bytes():
		Serializes the AV pair list into a contiguous byte string.
	from_bytes(message_bytes):
		Class method that parses a raw byte string and reconstructs an
		`AvPairList` instance, extracting individual `AvPair` objects.

	Notes
	-----
	- An AV pair list always ends with an "End-of-List" (`MSV_AV_EOL`) entry,
	  which is automatically added during initialization.
	- Common AV pairs include:
		- `MSV_AV_NB_COMPUTER_NAME`
		- `MSV_AV_NB_DOMAIN_NAME`
		- `MSV_AV_DNS_COMPUTER_NAME`
		- `MSV_AV_DNS_DOMAIN_NAME`
		- `MSV_AV_DNS_TREE_NAME`
		- `MSV_AV_FLAGS`
		- `MSV_AV_TIMESTAMP`
		- `MSV_AV_SINGLE_HOST`
		- `MSV_AV_TARGET_NAME`
		- `MSV_AV_CHANNEL_BINDINGS`
	- The `infos` dictionary values are encoded appropriately when constructing
	  the AV pairs.
	- The `to_bytes` method concatenates all AvPair serializations into a
	  single byte string suitable for inclusion in NTLM messages.
	"""
	def __init__(self, domain_name=Z(0), workstation_name=Z(0), target_name=Z(0), custom_data=Z(0), flags=Z(0), channel_bindings=Z(0)):
		self.MsvAvNbComputerName 	= None
		self.MsvAvNbDomainName		= None
		self.MsvAvDnsComputerName	= None
		self.MsvAvDnsDomainName		= None
		self.MsvAvDnsTreeName		= None
		self.MsvAvFlags				= None
		self.MsvAvTimestamp			= AvPair(MSV_AV_TIMESTAMP, int((datetime.now().timestamp() - datetime(1601, 1, 1, tzinfo=timezone.utc).timestamp()) * 10**7))
		self.MsvAvSingleHost		= None
		self.MsvAvTargetName		= None
		self.MsvAvChannelBindings	= None
		self.MsvAvEOL				= AvPair()

		if workstation_name:
			self.MsvAvNbComputerName 	= AvPair(MSV_AV_NB_COMPUTER_NAME, workstation_name)

		if domain_name:
			self.MsvAvNbDomainName		= AvPair(MSV_AV_NB_DOMAIN_NAME, domain_name.split(b'.')[0])
			self.MsvAvDnsComputerName	= AvPair(MSV_AV_DNS_COMPUTER_NAME, workstation_name + b'.' + domain_name)
			self.MsvAvDnsDomainName		= AvPair(MSV_AV_DNS_DOMAIN_NAME, domain_name)
			self.MsvAvDnsTreeName		= AvPair(MSV_AV_DNS_TREE_NAME, domain_name)

		if flags:
			self.MsvAvFlags			= AvPair(MSV_AV_FLAGS, flags)

		if custom_data:
			self.MsvAvSingleHost	= AvPair(MSV_AV_SINGLE_HOST, custom_data)
		
		if target_name:
			self.MsvAvTargetName	= AvPair(MSV_AV_TARGET_NAME, target_name)
		
		if channel_bindings:
			self.MsvAvChannelBindings	= AvPair(MSV_AV_CHANNEL_BINDINGS, channel_bindings)


	def __len__(self):
		length = 0

		values = [getattr(self, attr) for attr in vars(self)]
		av_pairs = list(filter(lambda x: x is not None, values))

		for av_pair in av_pairs:
			length += len(av_pair)

		return length

	def to_bytes(self):
		bytes_chunks = []

		values = [getattr(self, attr) for attr in vars(self)]
		av_pairs = list(filter(lambda x: x is not None, values))

		for av_pair in av_pairs:
			bytes_chunks.append(av_pair.to_bytes())

		return b"".join(bytes_chunks)

	@classmethod
	def from_bytes(cls, message_bytes):
		av_pair_list = cls()

		while message_bytes:
			av_pair, message_bytes = AvPair.from_bytes(message_bytes)

			if av_pair.av_id == MSV_AV_NB_COMPUTER_NAME:
				av_pair_list.MsvAvNbCompterName = av_pair
			elif av_pair.av_id == MSV_AV_NB_DOMAIN_NAME:
				av_pair_list.MsvAvNbDomainName = av_pair
			elif av_pair.av_id == MSV_AV_DNS_COMPUTER_NAME:
				av_pair_list.MsvAvDnsComputerName = av_pair
			elif av_pair.av_id == MSV_AV_DNS_DOMAIN_NAME:
				av_pair_list.MsvAvDnsDomainName = av_pair
			elif av_pair.av_id == MSV_AV_DNS_TREE_NAME:
				av_pair_list.MsvAvDnsTreeName = av_pair
			elif av_pair.av_id == MSV_AV_FLAGS:
				av_pair_list.MsvAvFlags = av_pair
			elif av_pair.av_id == MSV_AV_TIMESTAMP:
				av_pair_list.MsvAvTimestamp = av_pair
			elif av_pair.av_id == MSV_AV_SINGLE_HOST:
				av_pair_list.MsvAvSingleHost = av_pair
			elif av_pair.av_id == MSV_AV_TARGET_NAME:
				av_pair_list.MsvAvTargetName = av_pair
			elif av_pair.av_id == MSV_AV_CHANNEL_BINDINGS:
				av_pair_list.MsvAvChannelBindings = av_pair
			elif av_pair.av_id == MSV_AV_EOL:
				av_pair_list.MsvAvEOL = av_pair

		return av_pair_list


class AvPair(object):
	"""
	Represents a single NTLM Attribute–Value (AV) pair used in NTLMv2
	Client Challenge and target information structures.

	Each AvPair encodes an attribute type (`av_id`), its length
	(`av_len`), and the corresponding value. AV pairs are the building
	blocks of the `AvPairList` used in NTLMv2 authentication.

	Parameters
	----------
	None
		Instances are initialized with `av_id` set to `MSV_AV_EOL` (End-of-List)
		and an empty value.

	Attributes
	----------
	av_id : int
		Identifier of the AV pair, e.g., `MSV_AV_NB_COMPUTER_NAME`, `MSV_AV_FLAGS`,
		`MSV_AV_TIMESTAMP`, etc.
	av_len : int
		Length of the value in bytes.
	value : bytes or SingleHost
		Value associated with the AV pair. Can be UTF-16LE encoded bytes,
		integers, or a `SingleHost` object depending on `av_id`.

	Methods
	-------
	set_av_pair(av_id, value):
		Initializes the AV pair with a given identifier and value. Returns
		`self` or `None` if the value is empty.
	to_bytes():
		Serializes the AV pair into a binary structure suitable for inclusion
		in NTLMv2 messages:
			<av_id (2 bytes)> <av_len (2 bytes)> <value (variable length)>
	from_bytes(message_bytes):
		Class method that parses a binary AV pair from raw bytes and returns
		a tuple `(AvPair instance, remaining_bytes)`.

	Notes
	-----
	- AV pair types determine the serialization format:
		- Strings (computer/domain/DNS names) are UTF-16LE encoded.
		- Flags are 4-byte integers.
		- Timestamps are 8-byte integers.
		- SingleHost is serialized using its `to_bytes()` method.
		- Channel bindings are currently not implemented.
	- `MSV_AV_EOL` marks the end of an AV pair list and typically has
	  zero-length value.
	- The `from_bytes` method correctly slices the input to allow sequential
	  parsing of multiple AV pairs in a list.
	"""
	def __init__(self, av_id=MSV_AV_EOL, value=Z(0)):
		self.av_id = av_id
		self.av_len = NUL
		self.value = value

		if self.av_id in {MSV_AV_NB_COMPUTER_NAME, MSV_AV_NB_DOMAIN_NAME, MSV_AV_DNS_COMPUTER_NAME, MSV_AV_DNS_DOMAIN_NAME, MSV_AV_DNS_TREE_NAME, MSV_AV_TARGET_NAME}:
			self.value = value
			self.av_len = len(value)
		if self.av_id == MSV_AV_FLAGS:
			self.value = value
			self.av_len = 4
		if self.av_id == MSV_AV_TIMESTAMP:
			self.value = value
			self.av_len = 8
		if self.av_id == MSV_AV_SINGLE_HOST:
			self.value = SingleHost(value)
			self.av_len = len(self.value)
		if self.av_id == MSV_AV_CHANNEL_BINDINGS:
			self.value = md5(value)
			self.av_len = 0 # UNKNOWN LENGTH

	def __len__(self):
		return self.av_len

	def to_bytes(self):
		bytes_chunks = []

		bytes_chunks.append(struct.pack("<H", self.av_id))
		bytes_chunks.append(struct.pack("<H", self.av_len))

		if self.av_id in {MSV_AV_NB_COMPUTER_NAME, MSV_AV_NB_DOMAIN_NAME, MSV_AV_DNS_COMPUTER_NAME, MSV_AV_DNS_DOMAIN_NAME, MSV_AV_DNS_TREE_NAME, MSV_AV_TARGET_NAME}:
			bytes_chunks.append(struct.pack(f"{self.av_len}s", self.value))
		if self.av_id == MSV_AV_FLAGS:
			bytes_chunks.append(struct.pack(f"<I", self.value))
		if self.av_id == MSV_AV_TIMESTAMP:
			bytes_chunks.append(struct.pack("<Q", self.value))
		if self.av_id == MSV_AV_SINGLE_HOST:
			bytes_chunks.append(self.value.to_bytes())
		if self.av_id == MSV_AV_CHANNEL_BINDINGS:
			pass

		return b"".join(bytes_chunks)

	@classmethod
	def from_bytes(cls, message_bytes):
		av_pair = cls()

		av_pair.av_id = struct.unpack("<H", message_bytes[:2])[0]
		av_pair.av_len = struct.unpack("<H", message_bytes[2:4])[0]

		value = message_bytes[4:4+av_pair.av_len]
		if av_pair.av_id in {MSV_AV_NB_COMPUTER_NAME, MSV_AV_NB_DOMAIN_NAME, MSV_AV_DNS_COMPUTER_NAME, MSV_AV_DNS_DOMAIN_NAME, MSV_AV_DNS_TREE_NAME, MSV_AV_TARGET_NAME}:
			av_pair.value = struct.unpack(f"{av_pair.av_len}s", value)[0]
		if av_pair.av_id == MSV_AV_FLAGS:
			av_pair.value = struct.unpack(f"<I", value)[0]
		if av_pair.av_id == MSV_AV_TIMESTAMP:
			av_pair.value = struct.unpack("<Q", value)[0]
		if av_pair.av_id == MSV_AV_SINGLE_HOST:
			av_pair.value = av_pair.value.from_bytes(value)
		if av_pair.av_id == MSV_AV_CHANNEL_BINDINGS:
			pass

		return av_pair, message_bytes[4+av_pair.av_len:]