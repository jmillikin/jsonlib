# Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
# Author: John Millikin <jmillikin@gmail.com>

"""Implements jsonlib.write"""

from decimal import Decimal
import UserString
from jsonlib.util import memoized, INFINITY
from jsonlib import errors

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
	
def get_separators (start, end, indent_string, indent_level):
	if indent_string is None:
		return start, end, '', ','
	else:
		indent = indent_string * (indent_level + 1)
		next_indent = indent_string * indent_level
		return start + '\n', '\n' + next_indent + end, indent, ',\n'
		
def write_array (value, sort_keys, indent_string, ascii_only, coerce_keys,
                 parent_objects, indent_level):
	"""Serialize an iterable to a list of strings in JSON array format."""
	
	v_id = id (value)
	if v_id in parent_objects:
		raise errors.WriteError ("Cannot serialize self-referential values.")
		
	separators = get_separators ('[', ']', indent_string, indent_level)
	start, end, pre_value, post_value = separators
	
	retval = [start]
	
	for index, item in enumerate (value):
		retval.append (pre_value)
		retval.extend (_py_write (item, sort_keys, indent_string,
		                          ascii_only, coerce_keys,
		                          parent_objects + (v_id,),
		                          indent_level + 1))
		if (index + 1) < len (value):
			retval.append (post_value)
	retval.append (end)
	return retval
	
def write_iterable (value, *args, **kwargs):
	return write_array (tuple (value), *args, **kwargs)
	
def write_object (value, sort_keys, indent_string, ascii_only, coerce_keys,
                  parent_objects, indent_level):
	"""Serialize a mapping to a list of strings in JSON object format."""
	
	v_id = id (value)
	if v_id in parent_objects:
		raise errors.WriteError ("Cannot serialize self-referential values.")
		
	separators = get_separators ('{', '}', indent_string, indent_level)
	start, end, pre_value, post_value = separators
	
	retval = [start]
	
	if sort_keys:
		items = sorted (value.items ())
	else:
		items = value.items ()
		
	for index, (key, sub_value) in enumerate (items):
		is_string = isinstance (key, str)
		is_unicode = isinstance (key, unicode)
		retval.append (pre_value)
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
		if indent_string is not None:
			retval.append (': ')
		else:
			retval.append (':')
		retval.extend (_py_write (sub_value, sort_keys, indent_string,
		                          ascii_only, coerce_keys,
		                          parent_objects + (v_id,),
		                          indent_level + 1))
		if (index + 1) < len (value):
			retval.append (post_value)
	retval.append (end)
	return retval
	
def write_string (value, ascii_only):
	"""Serialize a string to its JSON representation.
	
	This function will use the default codec for decoding the input
	to Unicode. This might raise an exception and halt the entire
	serialization, so you should always use unicode strings instead.
	
	"""
	return write_unicode (unicode (value), ascii_only)
	
def write_unicode (value, ascii_only):
	"""Serialize a unicode string to its JSON representation."""
	stream = iter (value)
	yield '"'
	for char in stream:
		ochar = ord (char)
		if char in ESCAPES:
			yield ESCAPES[char]
		elif ochar > 0x7E:
			# Prevent invalid surrogate pairs from being
			# serialized.
			if 0xD800 <= ochar <= 0xDBFF:
				try:
					next = stream.next ()
				except StopIteration:
					raise errors.WriteError ("Cannot serialize incomplete surrogate pair.")
				onext = ord (next)
				if not (0xDC00 <= onext <= 0xDFFF):
					raise errors.WriteError ("Cannot serialize invalid surrogate pair.")
				if ascii_only:
					yield '\\u%04x' % ochar
					yield '\\u%04x' % onext
				else:
					yield char
					yield next
			elif 0xDC00 <= ochar <= 0xDFFF:
				raise errors.WriteError ("Cannot serialize reserved code point U+%04X." % ochar)
			elif ascii_only:
				if ochar > 0xFFFF:
					unicode_value = ord (char)
					reduced = unicode_value - 0x10000
					second_half = (reduced & 0x3FF) # Lower 10 bits
					first_half = (reduced >> 10)
				
					first_half += 0xD800
					second_half += 0xDC00
				
					yield '\\u%04x\\u%04x'% (first_half, second_half)
				else:
					yield '\\u%04x' % ochar
			else:
				yield char
		else:
			yield char
			
	yield '"'
	
@memoized
def write_float (value):
	if value != value:
		raise errors.WriteError ("Cannot serialize NaN.")
	if value == INFINITY:
		raise errors.WriteError ("Cannot serialize Infinity.")
	if value == -INFINITY:
		raise errors.WriteError ("Cannot serialize -Infinity.")
	return repr (value)
	
def write_decimal (value):
	if value != value:
		raise errors.WriteError ("Cannot serialize NaN.")
	s_value = unicode (value)
	if s_value in ('Infinity', '-Infinity'):
		raise errors.WriteError ("Cannot serialize %s." % s_value)
	return s_value
	
def write_complex (value):
	if value.imag == 0.0:
		return repr (value.real)
	raise errors.WriteError ("Cannot serialize complex numbers with"
	                         " imaginary components.")
	
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
	UserString.UserString: write_string,
}

TYPE_MAPPERS = {
	int: _m_str,
	long: _m_str,
	float: write_float,
	complex: write_complex,
	Decimal: write_decimal,
	bool: (lambda val: val and 'true' or 'false'),
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
	
def _py_write (value, sort_keys, indent_string, ascii_only, coerce_keys,
            parent_objects, indent_level):
	"""Serialize a Python value into a list of byte strings.
	
	When joined together, result in the value's JSON representation.
	
	"""
	w_func = CONTAINER_TYPES.get (type (value))
	
	# Might be a subclass
	if w_func is None:
		for mapper_type, mapper in CONTAINER_TYPES.items ():
			if isinstance (value, mapper_type):
				w_func = mapper
				
	# Check for user-defined mapping types
	if w_func is None:
		if hasattr (value, 'items'):
			w_func = write_object
			
	if w_func:
		return w_func (value, sort_keys, indent_string, ascii_only,
		               coerce_keys, parent_objects, indent_level)
		
	if parent_objects:
		return write_basic (value, ascii_only)
		
	# Check for user-defined iterables. Run this check after
	# write_basic to avoid iterating over strings.
	try:
		iter (value)
	except TypeError:
		pass
	else:
		return write_iterable (value, sort_keys, indent_string, ascii_only,
		                       coerce_keys, parent_objects, indent_level)
		
	raise errors.WriteError ("The outermost container must be an array or object.")
	
def write (value, sort_keys = False, indent = None, ascii_only = True,
           coerce_keys = False, encoding = 'utf-8', **kwargs):
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
	
	_write = _py_write
	if kwargs.get ('__speedboost', True):
		try:
			from _writer import _write
		except ImportError:
			pass
	u_string = u''.join (_write (value, sort_keys, indent, ascii_only,
	                             coerce_keys, (), 0))
	if encoding is None:
		return u_string
	return u_string.encode (encoding)
	
