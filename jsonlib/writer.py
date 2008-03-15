# Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
# Author: John Millikin <jmillikin@gmail.com>

"""Implements jsonlib.write"""

from decimal import Decimal
from .util import memoized, INFINITY
from . import errors

__all__ = ['write']

ESCAPES = {
	# Escaping the solidus is a security measure intended for
	# protecting users from broken browser parsing, if the consumer
	# is stupid enough to parse JSON by including it directly into
	# a <script> tag.
	# 
	# See: http://t3.dotgnu.info/blog/insecurity/quotes-dont-help.html
	'/': '\\/',
	'"': '\\"',
	'\t': '\\t',
	'\b': '\\b',
	'\n': '\\n',
	'\r': '\\r',
	'\f': '\\f',
	'\\': '\\\\'
}

for char_ord in range (0, 0x20):
	ESCAPES.setdefault (chr (char_ord), '\\u%04x' % char_ord)
	
def get_indent (indent_string, indent_level):
	if indent_string is None:
		return '', '', ''
	return '\n', indent_string * (indent_level + 1), indent_string * indent_level
	
def write_array (value, sort_keys, indent_string, ascii_only, coerce_keys,
                 parent_objects, indent_level):
	"""Serialize an iterable to a list of strings in JSON array format."""
	
	if value in parent_objects:
		raise errors.WriteError ("Can't write self-referential values.")
		
	newline, indent, next_indent = get_indent (indent_string, indent_level)
	retval = ['[', newline]
	
	for index, item in enumerate (value):
		if indent:
			retval.append (indent)
		retval.extend (_write (item, sort_keys, indent_string,
		                       ascii_only, coerce_keys,
		                       parent_objects + (value,),
		                       indent_level + 1))
		if (index + 1) < len (value):
			if newline:
				retval.append (',' + newline)
			else:
				retval.append (', ')
	retval.append (newline + next_indent)
	retval.append (']')
	return retval
	
def write_object (value, sort_keys, indent_string, ascii_only, coerce_keys,
                  parent_objects, indent_level):
	"""Serialize a mapping to a list of strings in JSON object format."""
	
	if value in parent_objects:
		raise errors.WriteError ("Can't write self-referential values.")
		
	newline, indent, next_indent = get_indent (indent_string, indent_level)
	retval = ['{', newline]
	
	if sort_keys:
		items = sorted (value.items ())
	else:
		items = value.items ()
		
	if newline:
		separator = ',' + newline
	else:
		separator = ', '
	for index, (key, sub_value) in enumerate (items):
		is_string = isinstance (key, str)
		is_unicode = isinstance (key, unicode)
		if indent:
			retval.append (indent)
		if is_string:
			retval.extend (write_string (key, ascii_only))
		elif is_unicode:
			retval.extend (write_unicode (key, ascii_only))
		elif coerce_keys:
			try:
				new_key = write_basic (key, ascii_only)
			except errors.UnknownSerializerError:
				new_key = unicode (key)
			retval.extend (write_unicode (new_key, ascii_only))
		else:
			raise errors.WriteError ("Only strings may "
			                         "be used as object "
			                         "keys.")
		retval.append (': ')
		retval.extend (_write (sub_value, sort_keys, indent_string,
		                       ascii_only, coerce_keys,
		                       parent_objects + (value,),
		                       indent_level + 1))
		if (index + 1) < len (value):
			retval.append (separator)
	retval.append (newline + next_indent)
	retval.append ('}')
	return retval
	
@memoized
def write_char (char, ascii_only):
	"""Serialize a single unicode character to its JSON representation."""
	if char in ESCAPES:
		return ESCAPES[char]
		
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
	if value != value:
		raise errors.WriteError ("Cannot serialize NaN.")
	if value == INFINITY:
		raise errors.WriteError ("Cannot serialize Infinity.")
	if value == -INFINITY:
		raise errors.WriteError ("Cannot serialize -Infinity.")
	return unicode (value)
	
@memoized
def write_decimal (value):
	if value != value:
		raise errors.WriteError ("Cannot serialize NaN.")
	s_value = unicode (value)
	if s_value in ('Infinity', '-Infinity'):
		raise errors.WriteError ("Cannot serialize %r." % value)
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
	Decimal: write_decimal,
	bool: (lambda val: 'true' if val else 'false'),
	type (None): lambda _: 'null',
}

def write_basic (value, ascii_only):
	v_type = type (value)
	if v_type in STR_TYPE_MAPPERS:
		return STR_TYPE_MAPPERS[v_type] (value, ascii_only)
	if v_type in TYPE_MAPPERS:
		return TYPE_MAPPERS[v_type] (value)
		
	# Might be a subclass
	for mapper_type, mapper in STR_TYPE_MAPPERS.items ():
		if isinstance (value, mapper_type):
			return mapper (value, ascii_only)
	for mapper_type, mapper in TYPE_MAPPERS.items ():
		if isinstance (value, mapper_type):
			return mapper (value)
			
	raise errors.UnknownSerializerError (value)
	
def _write (value, sort_keys, indent_string, ascii_only, coerce_keys,
            parent_objects, indent_level):
	"""Serialize a Python value into a list of byte strings.
	
	When joined together, result in the value's JSON representation.
	
	"""
	v_type = type (value)
	if v_type in CONTAINER_TYPES:
		w_func = CONTAINER_TYPES[v_type]
		return w_func (value, sort_keys, indent_string, ascii_only,
		               coerce_keys, parent_objects, indent_level)
	return write_basic (value, ascii_only)
	
def write (value, sort_keys = False, indent = None, ascii_only = True,
           coerce_keys = False):
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
	
	"""
	return u''.join (_write (value, sort_keys, indent, ascii_only,
	                         coerce_keys, (), 0))
	
