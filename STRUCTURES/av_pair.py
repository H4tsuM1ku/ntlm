from ntlm.constants import *

class AV_PAIR(object):
	def __init__(self):
		self.av_pairs = b""

		for av_data in av_list:
			pass

	def pack(self):
		values = [getattr(self, attr) for attr in vars(self)]
		return b"".join(values)