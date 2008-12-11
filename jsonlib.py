"""JSON serializer/deserializer for Python.

The main implementation of this module is accessed through calls to
``read()`` and ``write()``. See their documentation for details.

"""
__author__ = "John Millikin <jmillikin@gmail.com>"
__version__ = (1, 3, 8)
__license__ = """Copyright (c) 2008 John Millikin

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
"""

__all__ = [
	'loads', 'dumps', 'read', 'write',
	'ReadError', 'WriteError', 'UnknownSerializerError',
]

import codecs
from decimal import Decimal
import re
import sys
from UserString import UserString

# Exception classes {{{
class ReadError (ValueError):
	"""Exception raised if there is an error parsing a JSON expression."""
	def __init__ (self, string, offset, description):
		line = string.count ('\n', 0, offset) + 1
		if line == 1:
			column = offset + 1
		else:
			column = offset - string.rindex ('\n', 0, offset)
			
		template = ("JSON parsing error at line %d, column %d"
		            " (position %d): %s")
		error = template % (line, column, offset, description)
		ValueError.__init__ (self, error)
		
class WriteError (ValueError):
	"""Exception raised if there is an error generating a JSON expression."""
	pass
	
class UnknownSerializerError (WriteError):
	"""Exception raised if there is no known way to convert a
	value to a JSON expression.
	
	"""
	
	def __init__ (self, value):
		error = "No known serializer for object: %r" % (value,)
		WriteError.__init__ (self, error)
		
class UnknownAtomError (ValueError):
	"""For internal use, not raised by any external functions."""
	pass
	
# }}}

# Constants {{{
KEYWORDS = (('null', None), ('true', True), ('false', False))
try:
	INFINITY = float ('inf')
except ValueError:
	INFINITY = 1e300000
try:
	NAN = float ('nan')
except ValueError:
	NAN = INFINITY/INFINITY
	
UNICODE_BOMS = [
	(codecs.BOM_UTF32_BE, 'utf-32-be'),
	(codecs.BOM_UTF32_LE, 'utf-32-le'),
	(codecs.BOM_UTF16_BE, 'utf-16-be'),
	(codecs.BOM_UTF16_LE, 'utf-16-le'),
	(codecs.BOM_UTF8, 'utf-8'),
]
UTF_HEADERS = [
	((0, 0, 0, 1), 'utf-32-be'),
	((1, 0, 0, 0), 'utf-32-le'),
	((0, 1, 0, 1), 'utf-16-be'),
	((1, 0, 1, 0), 'utf-16-le'),
]

NUMBER_SPLITTER = re.compile (
	'^(?P<minus>-)?(?P<int>0|[1-9][0-9]*)' # Basic integer portion
	'(?:\\.(?P<frac>[0-9]+))?'             # Fractional portion
	'(?P<exp>[eE][-+]?[0-9]+)?$',          # Exponent
)

READ_ESCAPES = {
	'\\': '\\',
	'"': '"',
	'/': '/',
	'b': '\b',
	'f': '\f',
	'n': '\n',
	'r': '\r',
	't': '\t',
}

WRITE_ESCAPES = {
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

for __char_ord in range (0, 0x20):
	WRITE_ESCAPES.setdefault (chr (__char_ord), '\\u%04x' % __char_ord)
	
# }}}

# Parser {{{
def next_char_ord (string, index):
	value = ord (string[index])
	if (0xD800 <= value <= 0xDBFF) and len (string) >= 2:
		upper = value
		lower = ord (string[index + 1])
		upper -= 0xD800
		lower -= 0xDC00
		value = ((upper << 10) + lower) + 0x10000
		
	if value > 0xffff:
		return "U+%08X" % value
	return "U+%04X" % value
	
def error_unexpected (s, idx, looking_for = None):
	char_ord = next_char_ord (s, idx)
	if looking_for is None:
		desc = "Unexpected %s." % (char_ord,)
	else:
		desc = "Unexpected %s while looking for %s." % (char_ord, looking_for)
	raise ReadError (s, idx, desc)
	
def _w (s, idx, start = None, err = None):
	s_len = len (s)
	ws = '\x09\x20\x0a\x0d'
	while idx < s_len and s[idx] in ws:
		idx += 1
	if idx >= s_len and (start is not None) and (err is not None):
		raise ReadError (s, start, err)
	return idx
	
def read_object (s, idx):
	retval = {}
	start = idx
	idx = _w (s, idx + 1, start, "Unterminated object.")
	if s[idx] == '}':
		return retval, idx + 1
	while True:
		idx = _w (s, idx, start, "Unterminated object.")
		if s[idx] != '"':
			error_unexpected (s, idx, "property name")
		key, idx = read_raw (s, idx)
		idx = _w (s, idx, start, "Unterminated object.")
		if s[idx] != ':':
			error_unexpected (s, idx, "colon")
		idx += 1
		if idx >= len (s):
			raise ReadError (s, start, "Unterminated object.")
			
		value, idx = read_raw (s, idx)
		retval[key] = value
		idx = _w (s, idx, start, "Unterminated object.")
		if s[idx] == '}':
			return retval, idx + 1
		if s[idx] != ',':
			error_unexpected (s, idx, "comma")
		idx += 1
		
def read_array (s, idx):
	retval = []
	start = idx
	idx = _w (s, idx + 1, start, "Unterminated array.")
	if s[idx] == ']':
		return retval, idx + 1
	while True:
		if idx >= len (s):
			raise ReadError (s, start, "Unterminated array.")
		value, idx = read_raw (s, idx)
		retval.append (value)
		idx = _w (s, idx, start, "Unterminated array.")
		if s[idx] == ']':
			return retval, idx + 1
		if s[idx] != ',':
			error_unexpected (s, idx, "comma")
		idx += 1
		
def read_unicode_escape (s, index):
	"""Read a JSON-style Unicode escape.
	
	Unicode escapes may take one of two forms:
	
	* \\uUUUU, where UUUU is a series of four hexadecimal digits that
	indicate a code point in the Basic Multi-lingual Plane.
	
	* \\uUUUU\\uUUUU, where the two points encode a UTF-16 surrogate pair.
	  In builds of Python without wide character support, these are
	  returned as a surrogate pair.
	
	"""
	first_hex_str = s[index+1:index+5]
	if len (first_hex_str) < 4 or '"' in first_hex_str:
		raise ReadError (s, index - 1, "Unterminated unicode escape.")
	first_hex = int (first_hex_str, 16)
	
	# Some code points are reserved for indicating surrogate pairs
	if 0xDC00 <= first_hex <= 0xDFFF:
		raise ReadError (s, index - 1,
			"U+%04X is a reserved code point." % first_hex)
		
	# Check if it's a UTF-16 surrogate pair
	if not (0xD800 <= first_hex <= 0xDBFF):
		return unichr (first_hex), index + 4
		
	second_hex_str = s[index+5:index+11]
	if (not (len (second_hex_str) >= 6
	        and second_hex_str.startswith ('\\u'))
	    or '"' in second_hex_str):
		raise ReadError (s, index + 5, "Missing surrogate pair half.")
		
	second_hex = int (second_hex_str[2:], 16)
	if sys.maxunicode <= 65535:
		retval = unichr (first_hex) + unichr (second_hex)
	else:
		# Convert to 10-bit halves of the 20-bit character
		first_hex -= 0xD800
		second_hex -= 0xDC00
		
		# Merge into 20-bit character
		retval = unichr ((first_hex << 10) + second_hex + 0x10000)
	return retval, index + 10
	
def read_string (s, idx):
	idx += 1
	start = idx
	escaped = False
	chunks = []
	
	while True:
		while not escaped:
			c = s[idx]
			if c == '\\':
				escaped = True
			elif c == '"':
				return u''.join (chunks), idx + 1
			elif ord (c) < 0x20:
				error_unexpected (s, idx)
			else:
				chunks.append (c)
			idx += 1
			
		while escaped:
			c = s[idx]
			if c == 'u':
				unescaped, idx = read_unicode_escape (s, idx)
				chunks.append (unescaped)
			elif c in READ_ESCAPES:
				chunks.append (READ_ESCAPES[c])
			else:
				raise ReadError (s, idx - 1,
					"Unknown escape code: \\%s." % c)
			idx += 1
			escaped = False
			
def read_keyword (s, idx):
	for text, value in KEYWORDS:
		end = idx + len (text)
		if s[idx:end] == text:
			return value, end
	error_unexpected (s, idx)
	
def read_number (s, idx):
	allowed = '0123456789-+.eE'
	end = idx
	try:
		while s[end] in allowed:
			end += 1
	except IndexError:
		pass
	match = NUMBER_SPLITTER.match (s[idx:end])
	if not match:
		raise ReadError (s, idx, "Invalid number.")
		
	int_part = int (match.group ('int'), 10)
	if match.group ('frac') or match.group ('exp'):
		return Decimal (match.group (0)), end
	if match.group ('minus'):
		return -int_part, end
	return int_part, end
	
def read_raw (s, idx, root = False):
	idx = _w (s, idx)
	c = s[idx]
	if c == '{':
		return read_object (s, idx)
	if c == '[':
		return read_array (s, idx)
	if root:
		error_unexpected (s, idx)
	if c == '"':
		return read_string (s, idx)
	if c in 'tfn':
		return read_keyword (s, idx)
	if c in '-0123456789':
		return read_number (s, idx)
	error_unexpected (s, idx)
	
def read (string):
	"""Parse a JSON expression into a Python value.
	
	If string is a byte string, it will be converted to Unicode
	before parsing (see unicode_autodetect_encoding).
	
	"""
	string = unicode_autodetect_encoding (string)
	start = _w (string, 0)
	if not string or start == len (string):
		raise ReadError (string, 0, "No expression found.")
	value, end = read_raw (string, 0, True)
	end = _w (string, end)
	if end != len (string):
		raise ReadError (string, end,
			"Extra data after JSON expression.")
		raise ValueError ()
	return value
	
loads = read

def unicode_autodetect_encoding (bytestring):
	"""Intelligently convert a byte string to Unicode.
	
	Assumes the encoding used is one of the UTF-* variants. If the
	input is already in unicode, this is a noop.
	
	"""
	if isinstance (bytestring, unicode):
		return bytestring
		
	# Check for UTF byte order marks in the bytestring
	for bom, encoding in UNICODE_BOMS:
		if bytestring.startswith (bom):
			return bytestring[len(bom):].decode (encoding)
			
	# Autodetect UTF-* encodings using the algorithm in the RFC
	# Don't use inline if..else for Python 2.4
	header = tuple ((ord (b) and 1) or 0 for b in bytestring[:4])
	for utf_header, encoding in UTF_HEADERS:
		if header == utf_header:
			return bytestring.decode (encoding)
			
	# Default to UTF-8
	return bytestring.decode ('utf-8')
	
# }}}

# Serializer {{{
def get_separators (start, end, indent_string, indent_level):
	if indent_string is None:
		return start, end, '', ','
	else:
		indent = indent_string * (indent_level + 1)
		next_indent = indent_string * indent_level
		return start + '\n', '\n' + next_indent + end, indent, ',\n'
		
def write_array (value, _write, sort_keys, indent_string, ascii_only,
                 coerce_keys, on_unknown, parent_objects, indent_level):
	"""Serialize an iterable to a list of strings in JSON array format."""
	
	v_id = id (value)
	if v_id in parent_objects:
		raise WriteError ("Cannot serialize self-referential values.")
		
	if len (value) == 0:
		return _write ('[]')
		
	separators = get_separators ('[', ']', indent_string, indent_level)
	start, end, pre_value, post_value = separators
	
	_write (start)
	for index, item in enumerate (value):
		_write (pre_value)
		_py_write (item, _write, sort_keys, indent_string,
		           ascii_only, coerce_keys, on_unknown,
		           parent_objects + (v_id,),
		           indent_level + 1)
		if (index + 1) < len (value):
			_write (post_value)
	_write (end)
	
def write_iterable (value, *args, **kwargs):
	write_array (tuple (value), *args, **kwargs)
	
def write_object (value, _write, sort_keys, indent_string, ascii_only,
                  coerce_keys, on_unknown, parent_objects, indent_level):
	"""Serialize a mapping to a list of strings in JSON object format."""
	
	v_id = id (value)
	if v_id in parent_objects:
		raise WriteError ("Cannot serialize self-referential values.")
		
	if len (value) == 0:
		return _write ('{}')
		
	separators = get_separators ('{', '}', indent_string, indent_level)
	start, end, pre_value, post_value = separators
	
	_write (start)
	if sort_keys:
		items = sorted (value.items ())
	else:
		items = value.items ()
		
	for index, (key, sub_value) in enumerate (items):
		is_string = isinstance (key, (str, UserString))
		is_unicode = isinstance (key, unicode)
		_write (pre_value)
		if is_string:
			_write (write_string (key, ascii_only))
		elif is_unicode:
			_write (write_unicode (key, ascii_only))
		elif coerce_keys:
			try:
				new_key = write_basic (key, ascii_only)
			except UnknownSerializerError:
				new_key = unicode (key)
			_write (write_unicode (new_key, ascii_only))
		else:
			raise WriteError ("Only strings may be used as object "
			                  "keys.")
		if indent_string is not None:
			_write (': ')
		else:
			_write (':')
		_py_write (sub_value, _write, sort_keys, indent_string,
		           ascii_only, coerce_keys, on_unknown,
		           parent_objects + (v_id,),
		           indent_level + 1)
		if (index + 1) < len (value):
			_write (post_value)
	_write (end)
	
def write_string (value, ascii_only):
	"""Serialize a string to its JSON representation.
	
	This function will use the default codec for decoding the input
	to Unicode. This might raise an exception and halt the entire
	serialization, so you should always use unicode strings instead.
	
	"""
	return write_unicode (unicode (value), ascii_only)
	
def write_unicode (value, ascii_only):
	return u''.join (_write_unicode (value, ascii_only))
	
def _write_unicode (value, ascii_only):
	"""Serialize a unicode string to its JSON representation."""
	stream = iter (value)
	yield '"'
	for char in stream:
		ochar = ord (char)
		if char in WRITE_ESCAPES:
			yield WRITE_ESCAPES[char]
		elif ochar > 0x7E:
			# Prevent invalid surrogate pairs from being
			# serialized.
			if 0xD800 <= ochar <= 0xDBFF:
				try:
					next = stream.next ()
				except StopIteration:
					raise WriteError ("Cannot serialize incomplete surrogate pair.")
				onext = ord (next)
				if not (0xDC00 <= onext <= 0xDFFF):
					raise WriteError ("Cannot serialize invalid surrogate pair.")
				if ascii_only:
					yield '\\u%04x' % ochar
					yield '\\u%04x' % onext
				else:
					yield char
					yield next
			elif 0xDC00 <= ochar <= 0xDFFF:
				raise WriteError ("Cannot serialize reserved code point U+%04X." % ochar)
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
	
def write_float (value):
	if value != value:
		raise WriteError ("Cannot serialize NaN.")
	if value == INFINITY:
		raise WriteError ("Cannot serialize Infinity.")
	if value == -INFINITY:
		raise WriteError ("Cannot serialize -Infinity.")
	return repr (value)
	
def write_decimal (value):
	if value != value:
		raise WriteError ("Cannot serialize NaN.")
	s_value = unicode (value)
	if s_value in ('Infinity', '-Infinity'):
		raise WriteError ("Cannot serialize %s." % s_value)
	return s_value
	
def write_complex (value):
	if value.imag == 0.0:
		return repr (value.real)
	raise WriteError ("Cannot serialize complex numbers with"
	                  " imaginary components.")
	
STR_TYPE_WRITERS = [
	(unicode, write_unicode),
	(str, write_string),
	(UserString, write_string),
]

BASIC_TYPE_WRITERS = [
	(int, unicode),
	(long, unicode),
	(float, write_float),
	(complex, write_complex),
	(Decimal, write_decimal),
	(bool, (lambda val: val and 'true' or 'false')),
	(type (None), lambda _: 'null'),
]

def write_basic (value, ascii_only):
	for keyword, kw_value in KEYWORDS:
		if value is kw_value:
			return keyword
			
	for type_, func in BASIC_TYPE_WRITERS:
		if isinstance (value, type_):
			return func (value)
			
	for type_, func in STR_TYPE_WRITERS:
		if isinstance (value, type_):
			return func (value, ascii_only)
			
	raise UnknownSerializerError (value)
	
def _py_write (value, _write, sort_keys, indent_string, ascii_only,
               coerce_keys, on_unknown, parent_objects, indent_level,
               in_on_unknown = False):
	"""Serialize a Python value into a list of byte strings.
	
	When joined together, result in the value's JSON representation.
	
	"""
	# Check basic types first
	for keyword, kw_value in KEYWORDS:
		if value is kw_value:
			return _write (keyword)
			
	for type_, func in BASIC_TYPE_WRITERS:
		if isinstance (value, type_):
			if not parent_objects:
				err = "The outermost container must be an array or object."
				raise WriteError (err)
			return _write (func (value))
			
	for type_, func in STR_TYPE_WRITERS:
		if isinstance (value, type_):
			if not parent_objects:
				err = "The outermost container must be an array or object."
				raise WriteError (err)
			return _write (func (value, ascii_only))
			
	# Container types
	if hasattr (value, 'items'):
		func = write_object
	elif isinstance (value,(list, tuple)):
		func = write_array
	else:
		try:
			iter (value)
			func = write_iterable
		except TypeError:
			if on_unknown and not in_on_unknown:
				new_value = on_unknown (value)
				_py_write (new_value, _write, sort_keys,
				           indent_string, ascii_only,
				           coerce_keys,
				           on_unknown, parent_objects,
				           indent_level, True)
				return
			raise UnknownSerializerError (value)
			
	func (value, _write, sort_keys, indent_string, ascii_only,
	      coerce_keys, on_unknown, parent_objects, indent_level)
	
def dump (value, fp, sort_keys = False, indent = None, ascii_only = True,
          coerce_keys = False, encoding = 'utf-8', on_unknown = None):
	"""Serialize a Python value to a JSON-formatted byte string.
	
	Rather than being returned as a string, the output is written to
	a file-like object.
	
	"""
	if not (indent is None or len (indent) == 0):
		if len (indent.strip (u'\u0020\u0009\u000A\u000D')) > 0:
			raise TypeError ("Only whitespace may be used for indentation.")
			
	if on_unknown is not None and not callable (on_unknown):
		raise TypeError ("The on_unknown object must be callable.")
	
	def _write (text):
		if not isinstance (text, unicode):
			text = unicode (text, 'ascii')
		if encoding is not None:
			text = text.encode (encoding)
		fp.write (text)
		
	_py_write (value, _write, sort_keys, indent, ascii_only, coerce_keys,
	           on_unknown, (), 0)
	
def write (value, sort_keys = False, indent = None, ascii_only = True,
           coerce_keys = False, encoding = 'utf-8', on_unknown = None):
	"""Serialize a Python value to a JSON-formatted byte string.
	
	.. describe:: value
		
		The Python object to serialize.
		
	.. describe:: sort_keys
		
		Whether object keys should be kept sorted. Useful
		for tests, or other cases that check against a
		constant string value.
		
	.. describe:: indent
		
		A string to be used for indenting arrays and objects.
		If this is non-None, pretty-printing mode is activated.
		
	.. describe:: ascii_only
		
		Whether the output should consist of only ASCII
		characters. If this is True, any non-ASCII code points
		are escaped even if their inclusion would be legal.
	
	.. describe:: coerce_keys
		
		Whether to coerce invalid object keys to strings. If
		this is False, an exception will be raised when an
		invalid key is specified.
	
	.. describe:: encoding
		
		The output encoding to use. This must be the name of an
		encoding supported by Python's codec mechanism. If
		None, a Unicode string will be returned rather than an
		encoded bytestring.
		
		If a non-UTF encoding is specified, the resulting
		bytestring might not be readable by many JSON libraries,
		including jsonlib.
		
		The default encoding is UTF-8.
	.. describe:: on_unknown
		
		A callable to be used for converting objects of an
		unrecognized type into a JSON expression. If ``None``,
		unrecognized objects will raise an ``UnknownSerializerError``.
		
	"""
	if not (indent is None or len (indent) == 0):
		if len (indent.strip (u'\u0020\u0009\u000A\u000D')) > 0:
			raise TypeError ("Only whitespace may be used for indentation.")
			
	if on_unknown is not None and not callable (on_unknown):
		raise TypeError ("The on_unknown object must be callable.")
	pieces = []
	_py_write (value, pieces.append, sort_keys, indent, ascii_only,
	           coerce_keys, on_unknown, (), 0)
	u_string = u''.join (pieces)
	if encoding is None:
		return u_string
	return u_string.encode (encoding)
	
dumps = write
# }}}
