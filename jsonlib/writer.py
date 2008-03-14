# Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
# Author: John Millikin <jmillikin@gmail.com>

"""Implements jsonlib.write"""

from decimal import Decimal
from .util import memoized, KEYWORDS
from . import errors

__all__ = ['write']

ESCAPES = {
	'"': '\\"',
	'\t': '\\t',
	'\b': '\\b',
	'\n': '\\n',
	'\r': '\\r',
	'\f': '\\f',
	'\\': '\\\\'
}

def get_indent (indent_string, indent_level):
	if indent_string is None:
		return '', '', ''
	return '\n', indent_string * (indent_level + 1), indent_string * indent_level
	
def write_array (value, sort_keys, indent_string, ascii_only, indent_level):
	"""Serialize an iterable to a list of strings in JSON array format."""
	newline, indent, next_indent = get_indent (indent_string, indent_level)
	retval = ['[', newline]
	
	for index, item in enumerate (value):
		if item is value:
			raise errors.WriteError ("Can't write self-referential values")
		if indent:
			retval.append (indent)
		retval.extend (_write (item, sort_keys, indent_string, ascii_only, indent_level + 1))
		if (index + 1) < len (value):
			if newline:
				retval.append (',' + newline)
			else:
				retval.append (', ')
	retval.append (newline + next_indent)
	retval.append (']')
	return retval
	
def write_object (value, sort_keys, indent_string, ascii_only, indent_level):
	"""Serialize a mapping to a list of strings in JSON object format."""
	newline, indent, next_indent = get_indent (indent_string, indent_level)
	retval = ['{', newline]
	
	if sort_keys:
		items = sorted (value.items ())
	else:
		items = value.items ()
	
	for index, (key, sub_value) in enumerate (items):
		if not isinstance (key, (str, unicode)):
			raise errors.WriteError ("Only strings may be used as object keys")
			
		if sub_value is value:
			raise errors.WriteError ("Can't write self-referential values")
			
		if indent:
			retval.append (indent)
		retval.extend (_write (key, sort_keys, indent_string, ascii_only, indent_level + 1))
		retval.append (': ')
		retval.extend (_write (sub_value, sort_keys, indent_string, ascii_only, indent_level + 1))
		if (index + 1) < len (value):
			if newline:
				retval.append (',' + newline)
			else:
				retval.append (', ')
	retval.append (newline + next_indent)
	retval.append ('}')
	return retval
	
@memoized
def write_char (char, ascii_only):
	"""Serialize a single unicode character to its JSON representation."""
	if char in ESCAPES:
		return ESCAPES[char]
		
	# Control character
	if ord (char) in range (0x0, 0x1F + 1):
		return '\\u%04x' % ord (char)
		
	# Unicode
	if ord (char) > 0x7E and ascii_only:
		# Split into surrogate pairs
		if ord (char) > 0xFFFF:
			unicode_value = ord (char)
			reduced = unicode_value - 0x10000
			second_half = (reduced & 0x3FF) # Lower 10 bits
			first_half = (reduced >> 10)
			
			first_half += 0xD800
			second_half += 0xDC00
			
			return '\\u%04x\\u%04x'% (first_half, second_half)
		else:
			return '\\u%04x' % ord (char)
			
	return char
	
@memoized
def write_string (value, ascii_only):
	"""Serialize a string to its JSON representation.
	
	This function will use the default codec for decoding the input
	to Unicode. This might raise an exception and halt the entire
	serialization, so you should always use unicode strings instead.
	
	"""
	return write_unicode (unicode (value), ascii_only)
	
@memoized
def write_unicode (value, ascii_only):
	"""Serialize a unicode string to its JSON representation."""
	return ['"'] + [write_char (char, ascii_only) for char in value] + ['"']
	
@memoized
def write_float (value):
	disallowed = ('inf', '-inf', 'nan', 'Infinity', '-Infinity', 'NaN')
	s_value = unicode (value)
	if s_value in disallowed:
		raise errors.WriteError ("Cannot write floating-point value %r" % value)
	return s_value
	
# Fundamental types
_m_str = memoized (unicode)
CONTAINER_TYPES = {
	dict: write_object,
	list: write_array,
	tuple: write_array,
}

STR_TYPE_MAPPERS = {
	unicode: write_unicode,
	str: write_string,
}

TYPE_MAPPERS = {
	int: _m_str,
	long: _m_str,
	float: write_float,
	Decimal: write_float,
	type (True): (lambda val: 'true' if val else 'false'),
	type (None): lambda _: 'null',
}

def _write (value, sort_keys, indent_string, ascii_only, indent_level):
	"""Serialize a Python value into a list of byte strings.
	
	When joined together, result in the value's JSON representation.
	
	"""
	v_type = type (value)
	if v_type in CONTAINER_TYPES:
		w_func = CONTAINER_TYPES[v_type]
		return w_func (value, sort_keys, indent_string, ascii_only,
		               indent_level)
	elif v_type in STR_TYPE_MAPPERS:
		return STR_TYPE_MAPPERS[v_type] (value, ascii_only)
	elif v_type in TYPE_MAPPERS:
		return TYPE_MAPPERS[v_type] (value)
	else:
		# Might be a subclass
		for mapper_type, mapper in STR_TYPE_MAPPERS.items ():
			if isinstance (value, mapper_type):
				return mapper (value, ascii_only)
		for mapper_type, mapper in TYPE_MAPPERS.items ():
			if isinstance (value, mapper_type):
				return mapper (value)
				
		raise errors.UnknownSerializerError (value)
		
def write (value, sort_keys = False, indent = None, ascii_only = True):
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
	
	"""
	return u''.join (_write (value, sort_keys, indent, ascii_only, 0))
	
