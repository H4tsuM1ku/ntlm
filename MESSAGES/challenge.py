from ntlm.utils import nonce, charset, resolve_infos, Z
from ntlm.constants import DEFAULT_INFOS, NUL, NTLMSSP_REVISION_W2K3, NTLM_CHALLENGE
from ntlm.STRUCTURES import NEGOTIATE_FLAGS, VERSION, AV_PAIR_LIST, PAYLOAD

from .base import MESSAGE, FIELDS

class CHALLENGE(MESSAGE):
	"""
	Represents an NTLM CHALLENGE message (Type 2), sent by the server
	after receiving a NEGOTIATE message from the client.

	This message communicates the server challenge, target information,
	and the server’s supported security features. It may also include
	a target name and NTLM version structure depending on the negotiate flags.

	Parameters
	----------
	flags : NEGOTIATE_FLAGS, optional
		The negotiate flags chosen by the server for this authentication
		exchange. These determine whether fields such as target name,
		target info, and version information will be included.
		Defaults to `NEGOTIATE_FLAGS(1)`.
	infos : dict, optional
		Dictionary containing optional `"target"` metadata used to build
		the AV pair list and target name fields. Defaults to `DEFAULT_INFOS`.
	version_infos : tuple, optional
		Tuple containing (major_version, minor_version, build_number) used
		when the `NEGOTIATE_VERSION` flag is set. Defaults to `(NUL, NUL, NUL)`.
	oem_encoding : str, optional
		Encoding used for OEM-encoded fields when Unicode is not negotiated.
		Defaults to `"cp850"`.

	Attributes
	----------
	NegotiateFlags : NEGOTIATE_FLAGS
		Security and capability flags selected by the server.
	ServerChallenge : bytes
		An 8-byte random challenge used in NTLM authentication.
	Reserved : bytes
		Eight reserved bytes required by the NTLM specification.
	TargetNameFields : FIELDS
		Descriptor for the server target name (domain, computer, or share),
		if supplied.
	TargetInfoFields : FIELDS
		Descriptor for the AV pair list containing additional server metadata.
	Version : VERSION or bytes
		NTLM version block if negotiated, otherwise zero-filled bytes.
	Payload : bytes
		Payload containing the target name and target information structures.

	Notes
	-----
	- The target name is included only when certain flags are set, such as
	  `REQUEST_TARGET`, `TARGET_TYPE_SERVER`, `TARGET_TYPE_DOMAIN`,
	  or `TARGET_TYPE_SHARE`.
	- The AV pair list (`TargetInfoFields`) is included only when the
	  `NEGOTIATE_TARGET_INFO` flag is set.
	- NTLM version information is appended only when `NEGOTIATE_VERSION`
	  is set.
	- Field offsets are computed dynamically based on the optional data
	  included in the message.
	- The server challenge is generated using a 64-bit nonce.
	"""
	def __init__(self, flags=NEGOTIATE_FLAGS(1), infos=DEFAULT_INFOS, version_infos=(NUL, NUL, NUL), oem_encoding="cp850"):
		super(CHALLENGE, self).__init__(NTLM_CHALLENGE)

		encoding = charset(flags, oem_encoding)

		data = resolve_infos(flags, infos, encoding)
		domain_name 		= data["domain"]
		workstation_name	= data["workstation"]
		target_name 		= data["target"]
		custom_data			= data["custom_data"]

		target_info = AV_PAIR_LIST()
		if flags.dict["NEGOTIATE_TARGET_INFO"]:
			target_info = AV_PAIR_LIST(domain_name, workstation_name, target_name, custom_data)

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

		self.Payload = PAYLOAD(NTLM_CHALLENGE)
		self.Payload.Target = target_name
		self.Payload.TargetInfo = target_info