# Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
# Author: John Millikin <jmillikin@gmail.com>

import codecs
import struct
import sys

from _jsonlib import _read, write, ReadError, WriteError, UnknownSerializerError

__all__ = ('read', 'write', 'ReadError', 'WriteError',
           'UnknownSerializerError')

__version__ = (1, 3, 3)

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
	return _read (u_string)
	
