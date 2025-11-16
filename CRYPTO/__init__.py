def __getattr__(name):
	match name:
		case "rc4k":
			from .utils import rc4k
			return rc4k
		case "LMOWFv1":
			from .hashing import LMOWFv1
			return LMOWFv1
		case "NTOWFv1":
			from .hashing import NTOWFv1
			return NTOWFv1
		case "LMOWFv2":
			from .hashing import LMOWFv2
			return LMOWFv2
		case "NTOWFv2":
			from .hashing import NTOWFv2
			return NTOWFv2
		case "KXKEY":
			from .keys import KXKEY
			return KXKEY
		case "SIGNKEY":
			from .keys import SIGNKEY
			return SIGNKEY
		case "SEALKEY":
			from .keys import SEALKEY
			return SEALKEY
		case "compute_response":
			from .compute import compute_response
			return compute_response
		case "compute_MIC":
			from .compute import compute_MIC
			return compute_MIC

	raise AttributeError(f"module {__name__} has no attribute {name}")