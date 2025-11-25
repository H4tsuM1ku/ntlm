from ntlm.utils import nonce, charset, resolve_infos, Z
from ntlm.constants import DEFAULT_INFOS, NUL, NTLMSSP_REVISION_W2K3, NTLM_AUTHENTICATE, MSV_AV_FLAGS
from ntlm.STRUCTURES import NEGOTIATE_FLAGS, VERSION, RESPONSE, AV_PAIR_LIST, PAYLOAD
from ntlm.CRYPTO import rc4k, compute_response, compute_MIC, KXKEY, SIGNKEY, SEALKEY

from .base import MESSAGE, FIELDS

class AUTHENTICATE(MESSAGE):
	"""
	Represents an NTLM AUTHENTICATE message (Type 3), the final message
	sent by the client during the NTLM authentication handshake.

	This message contains the client's authentication material, including
	LM/NT challenge responses, user and domain names, workstation name,
	and optionally an encrypted session key and MIC value depending on
	the negotiated security features.

	Parameters
	----------
	flags : NEGOTIATE_FLAGS, optional
		The negotiate flags negotiated during the NTLM handshake.
		These flags determine which cryptographic operations are performed
		and which fields are included in the message.
		Defaults to `NEGOTIATE_FLAGS(0x40000201)`.
	infos : dict, optional
		A dictionary of user, domain, workstation, and server details
		required for response computation. Expected keys include:
		`"user"`, `"domain"`, `"workstation"`, `"password"`,
		`"server_challenge"`, `"negotiate_message"`, and optionally
		`"target_info"`. Defaults to `DEFAULT_INFOS`.
	version_infos : tuple, optional
		Tuple containing (major_version, minor_version, build_number).
		Used only when the `NEGOTIATE_VERSION` flag is set.
		Defaults to `(NUL, NUL, NUL)`.
	oem_encoding : str, optional
		OEM codepage used when Unicode is not negotiated.
		Defaults to `"cp850"`.

	Attributes
	----------
	LmChallengeResponseFields : FIELDS
		Descriptor for the LM challenge response structure.
	NtChallengeResponseFields : FIELDS
		Descriptor for the NT challenge response (often NTLMv2).
	DomainNameFields : FIELDS
		Descriptor for the domain name.
	UserNameFields : FIELDS
		Descriptor for the username.
	WorkstationFields : FIELDS
		Descriptor for the workstation name.
	EncryptedRandomSessionKeyFields : FIELDS
		Descriptor for the encrypted session key, included only when
		key exchange and signing/sealing are negotiated.
	Version : VERSION or bytes
		NTLM version structure when negotiated; zero-filled otherwise.
	MIC : bytes
		The Message Integrity Code computed in NTLMv2 when required by
		negotiate flags and AV pair flags.
	Payload : bytes
		Concatenation of all variable-length data (responses, names,
		session key) appended after the header.

	Notes
	-----
	- LM and NT responses are computed using `compute_response`, which
	  includes support for NTLMv2 client challenge structures.
	- If `NEGOTIATE_KEY_EXCH` and signing or sealing are enabled, the final
	  session key is encrypted using RC4 and included in the message.
	- MIC computation is performed only when the AV pair `"MSV_AV_FLAGS"` and
	  `NEGOTIATE_EXTENDED_SESSIONSECURITY` both indicate that it is required.
	- Offsets for each variable-length structure follow the NTLM specification
	  and depend on which optional fields (e.g., version) are present.
	- If the MIC remains uninitialized (all zeros), it is replaced with a
	  zero-length block (`Z(0)`), matching expected NTLM behavior.
	"""
	def __init__(self, flags=NEGOTIATE_FLAGS(0x40000201), infos=DEFAULT_INFOS, version_infos=(NUL, NUL, NUL), oem_encoding="cp850"):
		super(AUTHENTICATE, self).__init__(NTLM_AUTHENTICATE)

		encoding = charset(flags, oem_encoding)

		data = resolve_infos(flags, infos, encoding)
		domain_name			= data["domain"]
		workstation_name	= data["workstation"]
		username			= data["user"]
		password			= data["password"]
		server_challenge	= data["server_challenge"]
		negotiate_message	= data["negotiate_message"]
		target_info			= data["target_info"]

		client_challenge = nonce(64)

		if flags.dict["NEGOTIATE_KEY_EXCH"]:
			LmChallengeResponse, NtChallengeResponse, SessionKey, temp = compute_response(flags, username, password, domain_name, target_info, server_challenge, client_challenge)
			KeyExchangeKey = KXKEY(flags, SessionKey, password, server_challenge, LmChallengeResponse)
			
			if flags.dict["NEGOTIATE_SIGN"] or flags.dict["NEGOTIATE_SEAL"]:
				ExportedSessionKey = nonce(128)
				EncryptedRandomSessionKey = rc4k(KeyExchangeKey, ExportedSessionKey)
			else:
				ExportedSessionKey = KeyExchangeKey
				EncryptedRandomSessionKey = Z(0)

		lm_response, nt_response = RESPONSE(LmChallengeResponse, client_challenge), RESPONSE(NtChallengeResponse, temp)

		offset = 80
		self.Version = Z(0)
		if flags.dict["NEGOTIATE_VERSION"]:
			self.Version = VERSION(*version_infos, NTLMSSP_REVISION_W2K3)
			offset += 8
	
		self.LmChallengeResponseFields, offset = FIELDS(lm_response, offset), offset + len(lm_response)
		self.NtChallengeResponseFields, offset = FIELDS(nt_response, offset), offset + len(nt_response)

		self.DomainNameFields, offset = FIELDS(domain_name, offset), offset + len(domain_name)
		self.UserNameFields, offset = FIELDS(username, offset), offset + len(username)
		self.WorkstationFields, offset = FIELDS(workstation_name, offset), offset + len(workstation_name)

		self.EncryptedRandomSessionKeyFields = FIELDS(EncryptedRandomSessionKey, offset)

		self.NegotiateFlags = flags

		self.MIC = Z(16)

		self.Payload = PAYLOAD(NTLM_AUTHENTICATE)
		self.Payload.LmChallenge = lm_response
		self.Payload.NtChallenge = nt_response
		self.Payload.Domain = domain_name
		self.Payload.UserName = username
		self.Payload.Workstation = workstation_name
		self.Payload.EncryptedRandomSessionKey = EncryptedRandomSessionKey

		if target_info and target_info.MsvAvFlags and target_info.MsvAvFlags.value & 0x00000002 and flags.dict["NEGOTIATE_EXTENDED_SESSIONSECURITY"]:
			self.MIC = compute_MIC(KeyExchangeKey, EncryptedRandomSessionKey, negotiate_message, server_challenge, self)
		else:
			self.MIC = Z(0)