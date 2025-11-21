import secrets

from ntlm.constants import DEFAULT_INFOS

def nonce(N):
	return secrets.randbits(N).to_bytes((N + 7) // 8, "little")

def Z(N):
	return bytes(N)

def charset(flags, oem_encoding):
	match (flags.dict["NEGOTIATE_UNICODE"], flags.dict["NEGOTIATE_OEM"]):
		case (1, 1) | (1, 0):
			encoding = "utf-16-le"
		case (0, 1):
			encoding = oem_encoding
		case (0, 0):
			raise Exception("SEC_E_INVALID_TOKEN: You need to choose a character set encoding")
	return encoding

def resolve_infos(flags, infos, encoding):
	values = DEFAULT_INFOS.copy()

	for key in infos:
		value = Z(0)

		match key:
			case "domain":
				if flags.dict["NEGOTIATE_OEM_DOMAIN_SUPPLIED"]:
					value = infos["domain"].encode(encoding)
			case "workstation":
				if flags.dict["NEGOTIATE_OEM_WORKSTATION_SUPPLIED"]:
					value = infos["workstation"].encode(encoding)
			case "user":
				value = infos["user"].encode(encoding)
			case "password":
				value = infos["password"]
			case "target":
				if (flags.dict["REQUEST_TARGET"] or flags.dict["TARGET_TYPE_SERVER"] or flags.dict["TARGET_TYPE_DOMAIN"] or flags.dict["TARGET_TYPE_SHARE"]):
					value = infos["target"].encode(encoding)
			case "server_challenge":
				value = infos["server_challenge"]
			case "negotiate_message":
				value = infos["negotiate_message"]
			case "target_info":
				value = infos["target_info"]
			case "custom_data":
				value = infos["custom_data"]
		
		values[key] = value

	return values