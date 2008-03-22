# Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
# Author: John Millikin <jmillikin@gmail.com>

class ReadError (ValueError):
	pass
	
class UnterminatedStringError (ReadError):
	def __init__ (self, string_start):
		msg = 'Unterminated string started at %r'
		super (UnterminatedStringError, self).__init__ (msg % string_start)
		
class LeadingZeroError (ReadError):
	pass
	
class UnknownAtomError (ReadError):
	pass
	
class BadObjectKeyError (ReadError):
	pass
	
class MissingSurrogateError (ReadError):
	def __init__ (self, first_half):
		if isinstance (first_half, (str, unicode)):
			msg = first_half
		else:
			msg = 'Surrogate pair half is required after \\u%04x' % first_half
		super (MissingSurrogateError, self).__init__ (msg)
		
class InvalidEscapeCodeError (ReadError):
	def __init__ (self, code):
		msg = 'Invalid escape code: "\\%s"'
		super (InvalidEscapeCodeError, self).__init__ (msg % (code,))
		
class WriteError (ValueError):
	pass
	
class UnknownSerializerError (WriteError):
	def __init__ (self, value):
		msg = 'No known serializer for object: %r'
		super (UnknownSerializerError, self).__init__ (msg % (value,))
		
