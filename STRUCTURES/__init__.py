def __getattr__(name):
	match name:
		case "NegotiateFlags":
			from .negotiate_flags import NegotiateFlags
			return NegotiateFlags
		case "Version":
			from .version import Version
			return Version
		case "AvPairList":
			from .av_pair import AvPairList
			return AvPairList
		case "SingleHost":
			from .single_host import SingleHost
			return SingleHost
		case "Response":
			from .responses import Response
			return Response
		case "Ntlmv2ClientChallenge":
			from .responses import Ntlmv2ClientChallenge	
			return Ntlmv2ClientChallenge
		case "Payload":
			from .payload import Payload
			return Payload

	raise AttributeError(f"module {__name__} has no attribute {name}")