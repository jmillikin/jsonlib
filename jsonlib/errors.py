# Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
# Author: John Millikin <jmillikin@gmail.com>

class ReadError (ValueError):
	pass
	
class WriteError (ValueError):
	pass
	
class UnknownSerializerError (WriteError):
	def __init__ (self, value):
		msg = 'No known serializer for object: %r'
		if isinstance (UnknownSerializerError, type):
			parent = super (UnknownSerializerError, self)
			parent.__init__ (msg % (value,))
		else:
			WriteError.__init__ (self, msg % (value,))
		
