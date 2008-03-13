# Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
# Author: John Millikin <jmillikin@gmail.com>

"""Implements jsonlib.read"""

from decimal import Decimal
import re
import struct
import sys

from .util import memoized, chunk, KEYWORDS
from .StateMachine import StateMachine, PUSH, POP
from . import errors

__all__ = ['read']

NUMBER_SPLITTER = re.compile (
	r'^(?P<minus>-)?(?P<int>[0-9]+)' # Basic integer portion
	r'(?:\.(?P<frac>[0-9]+))?'       # Fractional portion
	r'(?P<exp>[eE][-+]?[0-9]+)?$',   # Exponent
re.UNICODE)

TOKEN_SPLITTER = re.compile (
	r'\s*([\[\]{}:,])|'         # Basic tokens
	r'\s*("(?:[^"\\]|\\.)*")|' # String atom
	r'\s*([^\s\[\]{}:,]+)|'     # Non-string atom
	r'(.+?)',                  # Anything else, will trigger an exception
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
	def __call__ (self, value):
		return TokenInstance (self, value)
		
class TokenInstance (object):
	"""Instance of a JSON token"""
	__slots__ = ['type', 'value']
	def __init__ (self, token_type, value):
		self.type = token_type
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

def tokenize (string):
	"""Split a JSON string into a stream of tokens.
	
	string -- The string to tokenize. Should be in unicode.
	
	"""
	basic_types = {u'[': ARRAY_START, u']': ARRAY_END,
	               u'{': OBJECT_START, u'}': OBJECT_END,
	               u':': COLON, u',': COMMA}
	
	for match in TOKEN_SPLITTER.findall (string):
		basic_string, string_atom, other_atom, unknown_token = match
		if basic_string:
			yield basic_types[basic_string] (basic_string)
		elif string_atom:
			yield ATOM (string_atom)
		elif other_atom:
			yield ATOM (other_atom)
		else:
			raise errors.ReadError ("Unknown token: %r" % unknown_token)
			
	yield EOF ('EOF')
	
def read_unicode_escape (stream):
	r"""Read a JSON-style Unicode escape.
	
	Unicode escapes may take one of two forms:
	
	* \uUUUU, where UUUU is a series of four hexadecimal digits that
	indicate a code point in the Basic Multi-lingual Plane.
	
	* \uUUUU\uUUUU, where the two points encode a UTF-16 surrogate pair.
	  In builds of Python without wide character support, these are
	  returned as a surrogate pair.
	
	"""
	get_n = lambda n: u''.join ([stream.next () for ii in xrange (n)])
	
	unicode_value = int (get_n (4), 16)
	
	# Check if it's a UTF-16 surrogate pair
	if unicode_value >= 0xD800 and unicode_value <= 0xDBFF:
		first_half = unicode_value
		try:
			next_escape = get_n (2)
			if next_escape != '\\u':
				raise errors.MissingSurrogateError (first_half)
			second_half = int (get_n (4), 16)
		except StopIteration:
			raise errors.MissingSurrogateError (first_half)
			
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
	
def read_unichars (string):
	"""Read unicode characters from an escaped string."""
	escaped = False
	stream = iter (string)
	for char in stream:
		if escaped:
			if char in ESCAPES:
				yield ESCAPES[char]
				escaped = False
			elif char == 'u':
				yield read_unicode_escape (stream)
				escaped = False
			else:
				raise errors.InvalidEscapeCodeError (char)
				
		elif char == u'\\':
			escaped = True
		else:
			yield char
			
def parse_long (string, base = 10):
	"""Convert a string to a long, forbidding leading zeros."""
	if string[0] == '0':
		if len (string) > 1:
			raise errors.LeadingZeroError (string)
		return 0L
	return long (string, base)
	
def parse_number (match):
	"""Parse a number from a regex match.
	
	Expects to have a match object from NUMBER_SPLITTER.
	
	"""
	if match.group ('frac'):
		value = Decimal ('%s.%s' % (match.group ('int'),
		                 match.group ('frac')))
	else:
		value = parse_long (match.group ('int'))
		
	if match.group ('exp'):
		value = Decimal (str (value) + match.group ('exp'))
		
	if match.group ('minus'):
		return -value
	else:
		return value
		
@memoized
def _parse_atom_string (string):
	"""Parse a JSON atom into a Python value.
	
	This function is used to implement parse_atom, so the result
	can be memoized.
	
	"""
	for keyword, value in KEYWORDS:
		if string == keyword:
			return value
			
	# String
	if string.startswith ('"'):
		assert string.endswith ('"')
		return u''.join (read_unichars (string[1:-1]))
		
	number_match = NUMBER_SPLITTER.match (string)
	
	if number_match:
		return parse_number (number_match)
		
	raise errors.UnknownAtomError ()
	
def parse_atom (atom):
	"""Parse a JSON atom into a Python value."""
	assert atom.type == ATOM
	try:
		# Pass in only the atom's value, so the function
		# can be memoized
		return _parse_atom_string (atom.value)
	except errors.UnknownAtomError:
		# Errors thrown within parse_atom_string don't have
		# the atom's value attached.
		raise errors.UnknownAtomError (atom)
		
def _py_read (string):
	"""Parse a unicode string in JSON format into a Python value."""
	read_item_stack = [[]]
	
	# Callbacks
	def on_atom (atom):
		"""Called when an atom token is retrieved."""
		read_item_stack[-1].append (parse_atom (atom))
		
	def on_container_start (_):
		"""Called when an array or object begins."""
		read_item_stack.append ([])
		
	def on_array_end (_):
		"""Called when an array has ended."""
		array = read_item_stack.pop ()
		read_item_stack[-1].append (array)
		
	def on_object_key (token):
		"""Called when an object key is retrieved."""
		key = parse_atom (token)
		if isinstance (key, unicode):
			read_item_stack[-1].append (key)
		else:
			raise errors.BadObjectKeyError (token)
			
	def on_object_end (_):
		"""Called when an object has ended."""
		pairs = read_item_stack.pop ()
		read_item_stack[-1].append (dict (chunk (pairs, 2)))
		
	machine = StateMachine ('need-value', ['root'])
	
	# Register state transitions
	machine.connect_many (
		('root', 'need-value',
			(ATOM, 'complete', on_atom),
			(ARRAY_START, 'empty', on_container_start, PUSH, 'array'),
			(OBJECT_START, 'empty', on_container_start, PUSH, 'object')),
		('root', 'got-value', (EOF, 'complete')),
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
			(COMMA, 'need-value')),
		
		('object', 'empty',
			(ARRAY_START, 'empty', on_container_start, PUSH, 'array'),
			(OBJECT_START, 'empty', on_container_start, PUSH, 'object'),
			(OBJECT_END, 'got-value', on_object_end, POP),
			(ATOM, 'with-key', on_object_key)),
		('object', 'with-key',
			(COLON, 'need-value')),
		('object', 'need-value',
			(ARRAY_START, 'empty', on_container_start, PUSH, 'array'),
			(OBJECT_START, 'empty', on_container_start, PUSH, 'object'),
			(ATOM, 'got-value', on_atom)),
		('object', 'got-value',
			(OBJECT_END, 'got-value', on_object_end, POP),
			(COMMA, 'need-key')),
		('object', 'need-key',
			(ATOM, 'with-key', on_object_key)),
	)
	
	for token in tokenize (string):
		try:
			machine.transition (token.type, token)
		except errors.ReadError:
			raise
		except ValueError, error:
			raise errors.ReadError (error.message)
			
	return read_item_stack[0][0]
	
def unicode_autodetect_encoding (bytes):
	"""Intelligently convert a byte string to Unicode.
	
	Assumes the encoding used is one of the UTF-* variants. If the
	input is already in unicode, this is a noop.
	
	"""
	if isinstance (bytes, unicode):
		return bytes
		
	header = [((ord (b) and 1) or 0) for b in bytes[:4]]
	def struct_decode (format):
		"""Helper for decoding UTF-32."""
		codes = struct.unpack (format % (len (bytes) / 4), bytes)
		return u''.join (unichr (code) for code in codes)
		
	# UTF-32 codecs are not available
	if header == [0, 0, 0, 1]:
		return struct_decode ('>%dl')
	if header == [1, 0, 0, 0]:
		return struct_decode ('<%dl')
	if header[:2] == [0, 1]:
		return unicode (bytes, 'utf-16-be')
	if header[:2] == [1, 0]:
		return unicode (bytes, 'utf-16-le')
	return unicode (bytes, 'utf-8')
	
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
	return _read (unicode_autodetect_encoding (string))
	
