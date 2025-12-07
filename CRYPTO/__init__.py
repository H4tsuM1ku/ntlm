def __getattr__(name):
	match name:
		case "rc4k":
			from .utils import rc4k
			return rc4k
		case "lmowfv1":
			from .hashing import lmowfv1
			return lmowfv1
		case "ntowfv1":
			from .hashing import ntowfv1
			return ntowfv1
		case "lmowfv2":
			from .hashing import lmowfv2
			return lmowfv2
		case "ntowfv2":
			from .hashing import ntowfv2
			return ntowfv2
		case "kxkey":
			from .keys import kxkey
			return kxkey
		case "sign_key":
			from .keys import sign_key
			return sign_key
		case "seal_key":
			from .keys import seal_key
			return seal_key
		case "compute_response":
			from .compute import compute_response
			return compute_response
		case "compute_MIC":
			from .compute import compute_MIC
			return compute_MIC

	raise AttributeError(f"module {__name__} has no attribute {name}")