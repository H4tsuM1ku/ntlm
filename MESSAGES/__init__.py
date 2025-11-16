def __getattr__(name):
	match name:
		case "NEGOTIATE":
			from .negotiate import NEGOTIATE
			return NEGOTIATE
		case "CHALLENGE":
			from .challenge import CHALLENGE
			return CHALLENGE
		case "AUTHENTICATE":
			from .authenticate import AUTHENTICATE
			return AUTHENTICATE

	raise AttributeError(f"module {__name__} has no attribute {name}")