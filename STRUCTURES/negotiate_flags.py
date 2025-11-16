from ntlm.constants import *
from enum import IntFlag
from functools import cached_property
import struct

class NEGOTIATE_FLAGS(IntFlag):
	"""
	NTLM NEGOTIATE FLAGS structure.

	This class represents the NTLMSSP NEGOTIATE_FLAGS field, where each bit corresponds to a specific negotiation capability.

	Fields
	-------
	W (1 bit):
		If set, requests 56-bit encryption.
		- If the client sends NTLMSSP_NEGOTIATE_SEAL or NTLMSSP_NEGOTIATE_SIGN with NTLMSSP_NEGOTIATE_56,
		  the server MUST return NTLMSSP_NEGOTIATE_56 in the CHALLENGE_MESSAGE. Otherwise ignored.
		- If both NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 are supported, both are returned.
		- Clients/servers that set NTLMSSP_NEGOTIATE_SEAL SHOULD set this if supported.
		Alternate name: NTLMSSP_NEGOTIATE_56

	V (1 bit):
		Requests explicit key exchange. SHOULD be used for improved integrity/confidentiality.
		See sections 3.2.5.1.2, 3.2.5.2.1, 3.2.5.2.2.
		Alternate name: NTLMSSP_NEGOTIATE_KEY_EXCH

	U (1 bit):
		Requests 128-bit session key negotiation.
		- If the client sets NTLMSSP_NEGOTIATE_128 and NTLMSSP_NEGOTIATE_SEAL/SIGN, the server MUST return it.
		- Otherwise ignored.
		- If both 56 and 128 are requested and supported, both are returned.
		Alternate name: NTLMSSP_NEGOTIATE_128

	r1–r3 (1 bit each):
		Unused. MUST be zero.

	T (1 bit):
		Requests protocol version number (in Version field of messages).
		Alternate name: NTLMSSP_NEGOTIATE_VERSION

	r4 (1 bit):
		Unused. MUST be zero.

	S (1 bit):
		Indicates TargetInfo fields in CHALLENGE_MESSAGE are populated.
		Alternate name: NTLMSSP_NEGOTIATE_TARGET_INFO

	R (1 bit):
		Requests usage of LMOWF.
		Alternate name: NTLMSSP_REQUEST_NON_NT_SESSION_KEY

	r5 (1 bit):
		Unused. MUST be zero.

	Q (1 bit):
		Requests identify-level token.
		Alternate name: NTLMSSP_NEGOTIATE_IDENTIFY

	P (1 bit):
		Requests NTLM v2 session security (extended session security).
		- Mutually exclusive with NTLMSSP_NEGOTIATE_LM_KEY.
		- If both are requested, only EXTENDED_SESSIONSECURITY is returned.
		Alternate name: NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY

	r6 (1 bit):
		Unused. MUST be zero.

	O (1 bit):
		TargetName MUST be a server name
		- If set, NTLMSSP_TARGET_TYPE_DOMAIN MUST NOT be set.
		- Ignored in NEGOTIATE/AUTHENTICATE messages.
		Alternate name: NTLMSSP_TARGET_TYPE_SERVER

	N (1 bit):
		TargetName MUST be a domain name
		- If set, NTLMSSP_TARGET_TYPE_SERVER MUST NOT be set.
		- Ignored in NEGOTIATE/AUTHENTICATE messages.
		Alternate name: NTLMSSP_TARGET_TYPE_DOMAIN

	M (1 bit):
		Always generates a session key regardless of SIGN/SEAL flags.
		- Required for MIC in AUTHENTICATE_MESSAGE.
		- Overridden by SIGN/SEAL if supported.
		Alternate name: NTLMSSP_NEGOTIATE_ALWAYS_SIGN

	r7 (1 bit):
		Unused. MUST be zero.

	L (1 bit):
		Indicates whether Workstation field is present.
		- If not set → field ignored.
		- If set → length determines if workstation name is nonempty.
		Alternate name: NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED

	K (1 bit):
		Indicates the domain name is provided.
		Alternate name: NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED

	J (1 bit):
		Indicates anonymous connection.
		Alternate name: NTLMSSP_ANONYMOUS (nowhere in the documentation)

	r8 (1 bit):
		Unused. SHOULD be zero.

	H (1 bit):
		Requests usage of NTLM v1 session security.
		Alternate name: NTLMSSP_NEGOTIATE_NTLM

	r9 (1 bit):
		Unused. MUST be zero.

	G (1 bit):
		Requests LAN Manager (LM) session key computation.
		- Mutually exclusive with EXTENDED_SESSIONSECURITY.
		Alternate name: NTLMSSP_NEGOTIATE_LM_KEY

	F (1 bit):
		Requests connectionless authentication.
		- If set, NTLMSSP_NEGOTIATE_KEY_EXCH MUST also be set.
		Alternate name: NTLMSSP_NEGOTIATE_DATAGRAM

	E (1 bit):
		Requests session key negotiation for message confidentiality.
		- If client sends SEAL, server MUST return SEAL.
		Alternate name: NTLMSSP_NEGOTIATE_SEAL

	D (1 bit):
		Requests session key negotiation for message signatures.
		- If client sends SIGN, server MUST return SIGN.
		Alternate name: NTLMSSP_NEGOTIATE_SIGN

	r10 (1 bit):
		Unused. MUST be zero.

	C (1 bit):
		Requires TargetName field in CHALLENGE_MESSAGE.
		Alternate name: NTLMSSP_REQUEST_TARGET

	B (1 bit):
		Requests OEM character set encoding.
		Alternate name: NTLMSSP_NEGOTIATE_OEM

	A (1 bit):
		Requests Unicode character set encoding.
		Alternate name: NTLMSSP_NEGOTIATE_UNICODE

	Character Encoding Logic:
		- A == 1 → Unicode
		- A == 0 and B == 1 → OEM
		- A == 0 and B == 0 → SEC_E_INVALID_TOKEN
	"""

	NEGOTIATE_56						= NTLMSSP_NEGOTIATE_56
	NEGOTIATE_KEY_EXCH					= NTLMSSP_NEGOTIATE_KEY_EXCH
	NEGOTIATE_128						= NTLMSSP_NEGOTIATE_128
	NEGOTIATE_VERSION					= NTLMSSP_NEGOTIATE_VERSION
	NEGOTIATE_TARGET_INFO				= NTLMSSP_NEGOTIATE_TARGET_INFO
	REQUEST_NON_NT_SESSION_KEY			= NTLMSSP_REQUEST_NON_NT_SESSION_KEY
	NEGOTIATE_IDENTIFY					= NTLMSSP_NEGOTIATE_IDENTIFY
	NEGOTIATE_EXTENDED_SESSIONSECURITY	= NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
	TARGET_TYPE_SHARE					= NTLMSSP_TARGET_TYPE_SHARE
	TARGET_TYPE_SERVER					= NTLMSSP_TARGET_TYPE_SERVER
	TARGET_TYPE_DOMAIN					= NTLMSSP_TARGET_TYPE_DOMAIN
	NEGOTIATE_ALWAYS_SIGN				= NTLMSSP_NEGOTIATE_ALWAYS_SIGN
	NEGOTIATE_OEM_WORKSTATION_SUPPLIED	= NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
	NEGOTIATE_OEM_DOMAIN_SUPPLIED		= NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
	ANONYMOUS							= NTLMSSP_ANONYMOUS
	NEGOTIATE_NTLM						= NTLMSSP_NEGOTIATE_NTLM
	NEGOTIATE_LM_KEY					= NTLMSSP_NEGOTIATE_LM_KEY
	NEGOTIATE_DATAGRAM					= NTLMSSP_NEGOTIATE_DATAGRAM
	NEGOTIATE_SEAL						= NTLMSSP_NEGOTIATE_SEAL
	NEGOTIATE_SIGN						= NTLMSSP_NEGOTIATE_SIGN
	REQUEST_TARGET						= NTLMSSP_REQUEST_TARGET
	NEGOTIATE_OEM						= NTLMSSP_NEGOTIATE_OEM
	NEGOTIATE_UNICODE					= NTLMSSP_NEGOTIATE_UNICODE

	@cached_property
	def dict(self):
		return {flag.name: (1 if flag & self else 0) for flag in NEGOTIATE_FLAGS}

	def clear(self):
		return NEGOTIATE_FLAGS(NUL)

	def to_bytes(self):
		return struct.pack("<I", self)

	@classmethod
	def from_bytes(cls, message_bytes):
		flags = struct.unpack("<I", message_bytes)[0]

		return cls(flags)