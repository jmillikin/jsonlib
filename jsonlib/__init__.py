# Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
# Author: John Millikin <jmillikin@gmail.com>

import codecs
from decimal import Decimal
from UserString import UserString
import struct
import sys

from jsonlib.errors import ReadError, WriteError, UnknownSerializerError
from jsonlib._reader import _read
from jsonlib._writer import _write

__all__ = ('read', 'write', 'ReadError', 'WriteError',
           'UnknownSerializerError')

def safe_unichr (codepoint):
	"""Similar to unichr(), except handles narrow builds.
	
	If a codepoint above 0x10000 is passed to this function, and the
	system cannot handle wide characters, the return value will be a
	string of length 2 containing the surrogate pair.
	
	"""
	if codepoint >= 0x10000 > sys.maxunicode:
		# No wide character support
		upper = (codepoint & 0xFFC00 - 0x10000) >> 10
		lower = codepoint & 0x3FF
		
		upper += 0xD800
		lower += 0xDC00
		
		return unichr (upper) + unichr (lower)
	else:
		return unichr (codepoint)
		
def unicode_autodetect_encoding (bytes):
	"""Intelligently convert a byte string to Unicode.
	
	Assumes the encoding used is one of the UTF-* variants. If the
	input is already in unicode, this is a noop.
	
	"""
	if isinstance (bytes, unicode):
		return bytes
		
	def struct_decode (format, offset = 0):
		"""Helper for decoding UTF-32."""
		_bytes = bytes[offset:]
		codes = struct.unpack (format % (len (_bytes) / 4), _bytes)
		return u''.join (safe_unichr (code) for code in codes)
		
	boms = ((codecs.BOM_UTF32_BE, lambda: struct_decode ('>%dl', 4)),
	        (codecs.BOM_UTF32_LE, lambda: struct_decode ('<%dl', 4)),
	        (codecs.BOM_UTF16_BE, lambda: bytes[2:].decode ('utf-16-be')),
	        (codecs.BOM_UTF16_LE, lambda: bytes[2:].decode ('utf-16-le')),
	        (codecs.BOM_UTF8, lambda: bytes[3:].decode ('utf-8')))
	
	utf_headers = (((0, 0, 0, 1), lambda: struct_decode ('>%dl')),
	              ((1, 0, 0, 0), lambda: struct_decode ('<%dl')),
	              ((0, 1, 0, 1), lambda: bytes.decode ('utf-16-be')),
	              ((1, 0, 1, 0), lambda: bytes.decode ('utf-16-le')))
	
	# Check for Byte Order Mark
	for bom, func in boms:
		if bytes.startswith (bom):
			return func ()
			
	# First two characters are always ASCII
	header = tuple (((ord (b) and 1) or 0) for b in bytes[:4])
	for utf_header, func in utf_headers:
		if header == utf_header:
			return func ()
			
	# Default to UTF-8
	return bytes.decode ('utf-8')
	
def read (string):
	"""Parse a JSON expression into a Python value.
	
	If string is a byte string, it will be converted to Unicode
	before parsing (see unicode_autodetect_encoding).
	
	"""
	u_string = unicode_autodetect_encoding (string)
	value = _read (u_string, Decimal, ReadError)
	if not isinstance (value, (dict, list)):
		raise ReadError ("Tried to deserialize a basic value.")
	return value
	
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
	pieces = _write (value, sort_keys, indent, ascii_only, coerce_keys,
	                 Decimal, UserString, WriteError,
	                 UnknownSerializerError)
	u_string = u''.join (pieces)
	if encoding is None:
		return u_string
	return u_string.encode (encoding)
	
