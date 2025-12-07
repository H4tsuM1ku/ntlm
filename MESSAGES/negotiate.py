from ntlm.utils import charset, resolve_infos, Z
from ntlm.constants import DEFAULT_INFOS, NUL, NTLMSSP_REVISION_W2K3, NTLM_NEGOTIATE
from ntlm.STRUCTURES import NegotiateFlags, Version, Payload

from .base import Message, Fields

class Negotiate(Message):
	"""
	Represents an NTLM Negotiate message (Type 1), the first message sent
	by a client during NTLM authentication.

	This message advertises the client capabilities (negotiate flags),
	optionally provides the domain and workstation names, and may include
	NTLM version information depending on the negotiate flags.

	Parameters
	----------
	flags : NegotiateFlags, optional
		The set of negotiate flags indicating the client's capabilities.
		Defaults to `NegotiateFlags(1)`.
	infos : dict, optional
		A dictionary containing `"domain"` and `"workstation"` strings that
		may be encoded and embedded into the message depending on the flags.
		Defaults to `DEFAULT_INFOS`.
	version_infos : tuple, optional
		Tuple containing (major_version, minor_version, build_number) used when
		the `NEGOTIATE_VERSION` flag is set. Defaults to `(NUL, NUL, NUL)`.
	oem_encoding : str, optional
		Encoding used for OEM-encoded fields when Unicode is not negotiated.
		Defaults to `"cp850"`.

	Attributes
	----------
	NegotiateFlags : NegotiateFlags
		The client's advertised capabilities.
	DomainNameFields : Fields
		Descriptor for the optional domain name.
	WorkstationFields : Fields
		Descriptor for the optional workstation name.
	Version : Version or bytes
		NTLM version structure if negotiated, otherwise zero-filled bytes.
	Payload : bytes
		Concatenation of all variable-length fields (domain and workstation).

	Notes
	-----
	- Domain and workstation names are only included when their corresponding
	  `NEGOTIATE_OEM_*_SUPPLIED` flags are set and the values are non-empty.
	- The NTLM version block is included only when the `NEGOTIATE_VERSION`
	  flag is set.
	- Offsets within field descriptors are computed dynamically based on
	  whether version information is included.
	- This class automatically selects the correct character encoding for
	  the names based on negotiate flags.
	"""
	def __init__(self, flags=NegotiateFlags(1), infos=DEFAULT_INFOS, version_infos=(NUL, NUL, NUL), oem_encoding="cp850"):
		super(Negotiate, self).__init__(NTLM_NEGOTIATE)

		encoding = charset(flags, oem_encoding)

		data = resolve_infos(flags, infos, encoding)
		domain_name 		= data["domain"]
		workstation_name	= data["workstation"]

		self.NegotiateFlags = flags

		offset = 32
		self.Version = Z(0)
		if flags.dict["NEGOTIATE_VERSION"]:
			self.Version = Version(*version_infos, NTLMSSP_REVISION_W2K3)
			offset += 8

		self.DomainNameFields, offset = Fields(domain_name, offset), offset + len(domain_name)
		self.WorkstationFields, offset = Fields(workstation_name, offset), offset + len(workstation_name)

		self.Payload = Payload(NTLM_NEGOTIATE)
		self.Payload.Domain = domain_name
		self.Payload.Workstation = workstation_name