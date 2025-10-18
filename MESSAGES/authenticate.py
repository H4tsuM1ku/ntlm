from .base import MESSAGE, FIELDS
from ntlm.constants import NtLmAuthenticate
from ntlm.STRUCTURES import VERSION
import struct

class AUTHENTICATE(MESSAGE):
	"""docstring for AUTHENTICATE"""
	def __init__(self):
		super(AUTHENTICATE, self).__init__(NtLmAuthenticate)
