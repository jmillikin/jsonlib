# Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
# Author: John Millikin <jmillikin@gmail.com>

"""Implements jsonlib.read"""

from decimal import Decimal
import re
import struct
import sys

from jsonlib.util import memoized, chunk, KEYWORDS
from jsonlib.StateMachine import StateMachine, PUSH, POP
from jsonlib.errors import ReadError

__all__ = ['read']

NUMBER_SPLITTER = re.compile (
	r'^(?P<minus>-)?(?P<int>[0-9]+)' # Basic integer portion
	r'(?:\.(?P<frac>[0-9]+))?'       # Fractional portion
	r'(?P<exp>[eE][-+]?[0-9]+)?$',   # Exponent
re.UNICODE)

TOKEN_SPLITTER = re.compile (
	# Basic tokens
	r'([\[\]{}:,])|'
	
	# String atom
	r'("(?:[^"\\]|\\.)*")|'
	
	# Non-string atom
	ur'([^\u0009\u0020\u000a\u000c\[\]{}:,]+)|'
	
	# Whitespace
	ur'([\u0009\u0020\u000a\u000c])|'
	
	# Anything else, will trigger an exception
	r'(.+?)',
re.UNICODE)

ESCAPES = {
	u'\\': '\\',
	u'"': '"',
	u'/': '/',
	u'b': '\b',
	u'f': '\f',
	u'n': '\n',
	u'r': '\r',
	u't': '\t',
}

class Token (object):
	"""A JSON token."""
	__slots__ = ['name']
	def __init__ (self, name):
		self.name = name
	def __repr__ (self):
		return 'Token<%r>' % self.name
	def __call__ (self, full_string, offset, value):
		return TokenInstance (self, full_string, offset, value)
		
class TokenInstance (object):
	"""Instance of a JSON token"""
	__slots__ = ['type', 'value', 'offset', 'full_string']
	def __init__ (self, token_type, full_string, offset, value):
		self.type = token_type
		self.offset = offset
		self.full_string = full_string
		self.value = value
	def __repr__ (self):
		return '%s<%r>' % (self.type.name, self.value)
		

# Inputs
ARRAY_START = Token ('ARRAY_START')
ARRAY_END = Token ('ARRAY_END')
OBJECT_START = Token ('OBJECT_START')
OBJECT_END = Token ('OBJECT_END')
COLON = Token ('COLON')
COMMA = Token ('COMMA')
ATOM = Token ('ATOM')
EOF = Token ('EOF')

def format_error (*args):
	if len (args) == 2:
		token, description = args
		string = token.full_string
		offset = token.offset
	else:
		string, offset, description = args
	line = string.count ('\n', 0, offset) + 1
	if line == 1:
		column = offset + 1
	else:
		column = offset - string.rindex ('\n', 0, offset)
		
	error = "JSON parsing error at line %d, column %d (position %d): %s"
	return error % (line, column, offset, description)
	
def tokenize (string):
	"""Split a JSON string into a stream of tokens.
	
	string
		The string to tokenize. Should be in unicode.
	
	"""
	basic_types = {u'[': ARRAY_START, u']': ARRAY_END,
	               u'{': OBJECT_START, u'}': OBJECT_END,
	               u':': COLON, u',': COMMA}
	
	position = 0
	for match in TOKEN_SPLITTER.findall (string):
		basic_string, string_atom, other_atom, whitespace, unknown_token = match
		if basic_string:
			yield basic_types[basic_string] (string, position, basic_string)
		elif string_atom:
			yield ATOM (string, position, string_atom)
		elif other_atom:
			yield ATOM (string, position, other_atom)
		elif whitespace:
			pass
		else:
			raise ReadError ("Unknown token: %r" % unknown_token)
		position += sum (map (len, match))
		
	yield EOF (string, position, 'EOF')
	
def read_unicode_escape (atom, index, stream):
	r"""Read a JSON-style Unicode escape.
	
	Unicode escapes may take one of two forms:
	
	* \uUUUU, where UUUU is a series of four hexadecimal digits that
	indicate a code point in the Basic Multi-lingual Plane.
	
	* \uUUUU\uUUUU, where the two points encode a UTF-16 surrogate pair.
	  In builds of Python without wide character support, these are
	  returned as a surrogate pair.
	
	"""
	get_n = lambda n: u''.join ([stream.next () for ii in xrange (n)])
	
	try:
		unicode_value = int (get_n (4), 16)
	except StopIteration:
		error = format_error (atom.full_string, index - 1,
		                      "Unterminated unicode escape.")
		raise ReadError (error)
		
	# Check if it's a UTF-16 surrogate pair
	if unicode_value >= 0xD800 and unicode_value <= 0xDBFF:
		first_half = unicode_value
		try:
			next_escape = get_n (2)
		except StopIteration:
			error = format_error (atom.full_string, index + 5,
			                      "Missing surrogate pair half.")
			raise ReadError (error)
		if next_escape != '\\u':
			error = format_error (atom.full_string, index + 5,
			                      "Missing surrogate pair half.")
			raise ReadError (error)
		try:
			second_half = int (get_n (4), 16)
		except StopIteration:
			error = format_error (atom.full_string, index + 5,
			                      "Missing surrogate pair half.")
			raise ReadError (error)
			
		if sys.maxunicode <= 65535:
			# No wide character support
			return unichr (first_half) + unichr (second_half)
		else:
			# Convert to 10-bit halves of the 20-bit character
			first_half -= 0xD800
			second_half -= 0xDC00
			
			# Merge into 20-bit character
			unicode_value = (first_half << 10) + second_half + 0x10000
			return unichr (unicode_value)
	else:
		return unichr (unicode_value)
	
def read_unichars (atom):
	"""Read unicode characters from an escaped string."""
	escaped = False
	stream = iter (atom.value[1:-1])
	illegal = map (unichr, range (0x20))
	for index, char in enumerate (stream):
		full_idx = atom.offset + index + 1
		if char in illegal:
			error = format_error (atom.full_string, full_idx,
			                      "Unexpected U+%04X." % ord (char))
			raise ReadError (error)
		if escaped:
			if char in ESCAPES:
				yield ESCAPES[char]
				escaped = False
			elif char == 'u':
				yield read_unicode_escape (atom, full_idx, stream)
				escaped = False
			else:
				error = format_error (atom.full_string, full_idx - 1,
				                      "Unknown escape code.")
				raise ReadError (error)
				
		elif char == u'\\':
			escaped = True
		else:
			yield char
			
def parse_long (atom, string, base = 10):
	"""Convert a string to a long, forbidding leading zeros."""
	if string[0] == '0':
		if len (string) > 1:
			error = format_error (atom, "Number with leading zero.")
			raise ReadError (error)
		return 0L
	return long (string, base)
	
def parse_number (atom, match):
	"""Parse a number from a regex match.
	
	Expects to have a match object from NUMBER_SPLITTER.
	
	"""
	if match.group ('frac'):
		int_part = parse_long (atom, match.group ('int'))
		value = Decimal ('%d.%s' % (int_part,
		                 match.group ('frac')))
	else:
		value = parse_long (atom, match.group ('int'))
		
	if match.group ('exp'):
		value = Decimal (str (value) + match.group ('exp'))
		
	if match.group ('minus'):
		return -value
	else:
		return value
		
def next_char_ord (string):
	value = ord (string[0])
	if (0xD800 <= value <= 0xDBFF) and len (string) >= 2:
		upper = value
		lower = ord (string[1])
		upper -= 0xD800
		lower -= 0xDC00
		value = ((upper << 10) + lower) + 0x10000
		
	return value
	
def parse_atom (atom):
	"""Parse a JSON atom into a Python value."""
	assert atom.type == ATOM
	
	for keyword, value in KEYWORDS:
		if atom.value == keyword:
			return value
			
	# String
	if atom.value.startswith ('"'):
		assert atom.value.endswith ('"')
		return u''.join (read_unichars (atom))
		
	if atom.value[0] in ('-1234567890'):
		number_match = NUMBER_SPLITTER.match (atom.value)
		
		if number_match:
			return parse_number (atom, number_match)
		error = format_error (atom, "Invalid number.")
		raise ReadError (error)
		
	char_ord = next_char_ord (atom.value)
	if char_ord > 0xffff:
		error = format_error (atom,
		                      "Unexpected U+%08X." % char_ord)
	else:
		error = format_error (atom,
		                      "Unexpected U+%04X." % char_ord)
	raise ReadError (error)
	
def _py_read (string):
	"""Parse a unicode string in JSON format into a Python value."""
	read_item_stack = [([], 0)]
	
	# Callbacks
	def on_atom (atom):
		"""Called when an atom token is retrieved."""
		read_item_stack[-1][0].append (parse_atom (atom))
		
	def on_container_start (token):
		"""Called when an array or object begins."""
		read_item_stack.append (([], token.offset))
		
	def on_array_end (_):
		"""Called when an array has ended."""
		array, _ = read_item_stack.pop ()
		read_item_stack[-1][0].append (array)
		
	def on_object_key (token):
		"""Called when an object key is retrieved."""
		key = parse_atom (token)
		if isinstance (key, unicode):
			read_item_stack[-1][0].append (key)
		else:
			error = format_error (token, "Expecting property name.")
			raise ReadError (error)
			
	def on_object_end (_):
		"""Called when an object has ended."""
		pairs, _ = read_item_stack.pop ()
		read_item_stack[-1][0].append (dict (chunk (pairs, 2)))
		
	def on_unterminated_object (token):
		_, start = read_item_stack[-1]
		error = format_error (token.full_string, start, "Unterminated object.")
		raise ReadError (error)
		
	def on_expected_colon (token):
		error = format_error (token, "Expected colon after object"
		                             " property name.")
		raise ReadError (error)
		
	def on_empty_expression (token):
		error = format_error (token.full_string, 0, "No expression found.")
		raise ReadError (error)
		
	def on_missing_object_key (token):
		error = format_error (token, "Expecting property name.")
		raise ReadError (error)
		
	def on_expecting_comma (token):
		error = format_error (token, "Expecting comma.")
		raise ReadError (error)
		
	def on_extra_data (token):
		error = format_error (token, "Extra data after JSON expression.")
		raise ReadError (error)
		
	machine = StateMachine ('need-value', ['root'])
	
	# Register state transitions
	machine.connect_many (
		('root', 'need-value',
			(ATOM, 'complete', on_atom),
			(ARRAY_START, 'empty', on_container_start, PUSH, 'array'),
			(OBJECT_START, 'empty', on_container_start, PUSH, 'object'),
			(EOF, 'error', on_empty_expression)),
		('root', 'got-value',
			(EOF, 'complete'),
			(ARRAY_START, 'error', on_extra_data)),
		('root', 'complete', (EOF, 'complete')),
		
		('array', 'empty',
			(ARRAY_START, 'empty', on_container_start, PUSH, 'array'),
			(ARRAY_END, 'got-value', on_array_end, POP),
			(OBJECT_START, 'empty', on_container_start, PUSH, 'object'),
			(ATOM, 'got-value', on_atom)),
		('array', 'need-value',
			(ARRAY_START, 'empty', on_container_start, PUSH, 'array'),
			(OBJECT_START, 'empty', on_container_start, PUSH, 'object'),
			(ATOM, 'got-value', on_atom)),
		('array', 'got-value',
			(ARRAY_END, 'got-value', on_array_end, POP),
			(COMMA, 'need-value'),
			(ATOM, 'error', on_expecting_comma)),
		
		('object', 'empty',
			(ARRAY_START, 'empty', on_container_start, PUSH, 'array'),
			(OBJECT_START, 'empty', on_container_start, PUSH, 'object'),
			(OBJECT_END, 'got-value', on_object_end, POP),
			(ATOM, 'with-key', on_object_key),
			(COMMA, 'error', on_missing_object_key)),
		('object', 'with-key',
			(COLON, 'need-value'),
			(OBJECT_END, 'error', on_expected_colon)),
		('object', 'need-value',
			(ARRAY_START, 'empty', on_container_start, PUSH, 'array'),
			(OBJECT_START, 'empty', on_container_start, PUSH, 'object'),
			(ATOM, 'got-value', on_atom)),
		('object', 'got-value',
			(OBJECT_END, 'got-value', on_object_end, POP),
			(COMMA, 'need-key'),
			(EOF, 'error', on_unterminated_object),
			(ATOM, 'error', on_expecting_comma)),
		('object', 'need-key',
			(ATOM, 'with-key', on_object_key),
			(OBJECT_END, 'error', on_missing_object_key)),
	)
	
	for token in tokenize (string):
		try:
			machine.transition (token.type, token)
		except ReadError:
			raise
		except ValueError, error:
			raise ReadError (error.message)
			
	return read_item_stack[0][0][0]
	
def safe_unichr (codepoint):
	"""Similar to unichr(), except handles narrow builds.
	
	If a codepoint above 0x10000 is passed to this function, and the
	system cannot handle wide characters, the return value will be a
	string of length 2 containing the surrogate pair."""
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
		
	header = [((ord (b) and 1) or 0) for b in bytes[:4]]
	def struct_decode (format, offset = 0):
		"""Helper for decoding UTF-32."""
		_bytes = bytes[offset:]
		codes = struct.unpack (format % (len (_bytes) / 4), _bytes)
		return u''.join (safe_unichr (code) for code in codes)
		
	# UTF-32 codecs are not available
	if header == [0, 0, 0, 1]:
		return struct_decode ('>%dl')
	if header == [1, 0, 0, 0]:
		return struct_decode ('<%dl')
	if header[:2] == [0, 1]:
		return bytes.decode ('utf-16-be')
	if header[:2] == [1, 0]:
		return bytes.decode ('utf-16-le')
		
	# Check for a BOM
	if bytes[:4] == '\x00\x00\xfe\xff':
		return struct_decode ('>%dl', 4)
	if bytes[:4] == '\xff\xfe\x00\x00':
		return struct_decode ('<%dl', 4)
	if bytes[:2] == '\xfe\xff':
		return bytes[2:].decode ('utf-16-be')
	if bytes[:2] == '\xff\xfe':
		return bytes[2:].decode ('utf-16-le')
		
	# Default to UTF-8
	return bytes.decode ('utf-8')
	
def read (string, **kwargs):
	"""Parse a JSON expression into a Python value.
	
	If string is a byte string, it will be converted to Unicode
	before parsing (see unicode_autodetect_encoding).
	
	"""
	_read = _py_read
	if kwargs.get ('__speedboost', True):
		try:
			from _reader import _read
		except ImportError:
			pass
	value = _read (unicode_autodetect_encoding (string))
	if not isinstance (value, (dict, list)):
		raise ReadError ("Tried to deserialize a basic value.")
	return value
	
