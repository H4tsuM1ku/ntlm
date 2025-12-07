def __getattr__(name):
	match name:
		case "Negotiate":
			from .negotiate import Negotiate
			return Negotiate
		case "Challenge":
			from .challenge import Challenge
			return Challenge
		case "Authenticate":
			from .authenticate import Authenticate
			return Authenticate

	raise AttributeError(f"module {__name__} has no attribute {name}")