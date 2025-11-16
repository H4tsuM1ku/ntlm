def __getattr__(name):
	match name:
		case "NEGOTIATE_FLAGS":
			from .negotiate_flags import NEGOTIATE_FLAGS
			return NEGOTIATE_FLAGS
		case "VERSION":
			from .version import VERSION
			return VERSION
		case "AV_PAIR_LIST":
			from .av_pair import AV_PAIR_LIST
			return AV_PAIR_LIST
		case "SINGLE_HOST":
			from .single_host import SINGLE_HOST
			return SINGLE_HOST
		case "RESPONSE":
			from .responses import RESPONSE
			return RESPONSE
		case "NTLMv2_CLIENT_CHALLENGE":
			from .responses import NTLMv2_CLIENT_CHALLENGE	
			return NTLMv2_CLIENT_CHALLENGE

	raise AttributeError(f"module {__name__} has no attribute {name}")