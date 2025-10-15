from base import MESSAGE, NEGOTIATEFLAGS

class NEGOTIATE(MESSAGE):
	"""docstring for NEGOTIATE"""
	def __init__(self, flags):
		super(NEGOTIATE, self).__init__(0x000000001)
		self.NegotiateFlags = NEGOTIATEFLAGS(*flags).to_bytes()

	def to_bytes(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)