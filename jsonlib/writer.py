# Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
# Author: John Millikin <jmillikin@gmail.com>

"""Implements jsonlib.write"""

from jsonlib._writer import _write

__all__ = ['write']

def write (value, sort_keys = False, indent = None, ascii_only = True,
           coerce_keys = False, encoding = 'utf-8'):
	"""Serialize a Python value to a JSON-formatted byte string.
	
	value
		The Python object to serialize.
		
	sort_keys
		Whether object keys should be kept sorted. Useful
		for tests, or other cases that check against a
		constant string value.
		
	indent
		A string to be used for indenting arrays and objects.
		If this is non-None, pretty-printing mode is activated.
		
	ascii_only
		Whether the output should consist of only ASCII
		characters. If this is True, any non-ASCII code points
		are escaped even if their inclusion would be legal.
	
	coerce_keys
		Whether to coerce invalid object keys to strings. If
		this is False, an exception will be raised when an
		invalid key is specified.
	
	encoding
		The output encoding to use. This must be the name of an
		encoding supported by Python's codec mechanism. If
		None, a Unicode string will be returned rather than an
		encoded bytestring.
		
		If a non-UTF encoding is specified, the resulting
		bytestring might not be readable by many JSON libraries,
		including jsonlib.
		
		The default encoding is UTF-8.
	
	"""
	u_string = u''.join (_write (value, sort_keys, indent, ascii_only,
	                             coerce_keys, (), 0))
	if encoding is None:
		return u_string
	return u_string.encode (encoding)
	
