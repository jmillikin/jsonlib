"""JSON serializer/deserializer for Python.

The main implementation of this module is accessed through calls to
``read()`` and ``write()``. See their documentation for details.

"""
__author__ = "John Millikin <jmillikin@gmail.com>"
__version__ = (1, 3, 5)
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
	'read', 'write',
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
	pass
	
class WriteError (ValueError):
	"""Exception raised if there is an error generating a JSON expression."""
	pass
	
class UnknownSerializerError (WriteError):
	"""Exception raised if there is no known way to convert a
	value to a JSON expression.
	
	"""
	
	def __init__ (self, value):
		err = "No known serializer for object: %r" % (value,)
		if isinstance (UnknownSerializerError, type):
			parent = super (UnknownSerializerError, self)
			parent.__init__ (err)
		else:
			WriteError.__init__ (self, err)
			
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
	'^(?P<minus>-)?(?P<int>[0-9]+)' # Basic integer portion
	'(?:\\.(?P<frac>[0-9]+))?'      # Fractional portion
	'(?P<exp>[eE][-+]?[0-9]+)?$',   # Exponent
re.UNICODE)

TOKEN_SPLITTER = re.compile (
	# Basic tokens
	'([\\[\\]{}:,])|'
	
	# String atom
	'((?:"(?:[^"\\\\]|\\\\.)*")|'
	
	# Non-string atom
	u'(?:[^\u0009\u0020\u000a\u000d\\[\\]{}:,]+))|'
	
	# Whitespace
	u'([\u0009\u0020\u000a\u000d])|'
	
	# Anything else, will trigger an exception
	'(.+?)',
re.UNICODE)

BASIC_TOKENS = {
	'[': 'ARRAY_START',
	']': 'ARRAY_END',
	'{': 'OBJECT_START',
	'}': 'OBJECT_END',
	':': 'COLON',
	',': 'COMMA',
}

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

for char_ord in range (0, 0x20):
	WRITE_ESCAPES.setdefault (chr (char_ord), '\\u%04x' % char_ord)
	
# }}}

# Parser {{{
def chunk (iterable, chunk_size):
	"""Retrieve an iterable in chunks.
	
	If there are extra values left over after the iterable is
	exhausted, they are lost.
	
	"""
	_chunk = []
	for value in iterable:
		_chunk.append (value)
		if len (_chunk) == chunk_size:
			yield _chunk
			_chunk = []
			
class StateMachine (object):
	"""A simple push-down automaton."""
	
	def __init__ (self, initial_state, initial_stack = ('')):
		self._state = initial_state
		self._stack = list (initial_stack)[:]
		self._transitions = {}
		
	def connect (self, state, stack, value, end_state, callback = None):
		"""Connect a transition to a callback.
		
		.. describe:: state
			
			A string representing the expected state.
			
		.. describe:: stack
			
			The value that should be on the stack.
			
		.. describe:: value
			
			The value passed to transition.
			
		.. describe:: end_state
			
			The state to transition to.
			
		.. describe:: callback
			
			If not None, this function will be called with
			any extra data passed to transition.
			
		"""
		key = (stack, state, value)
		
		if key in self._transitions:
			raise ValueError ("This state/stack/input combination "
			                  "has already been connected: %r" %
			                  [key])
			
		if callback is None:
			callback = lambda *a, **kw: None
		self._transitions[key] = (end_state, callback)
		
	def connect_many (self, *transitions):
		"""Connect many transitions at once. 
		
		Each transition is in the format (stack, state, (value,
		end_state, callback, stack_action), ...).
		
		"""
		for state_def in transitions:
			stack, state = state_def[:2]
			connections = state_def[2:]
			for connection in connections:
				self.connect (state, stack, *connection)
				
	def transition (self, value, *args, **kwargs):
		"""Execute a transition between one state and another.
		
		.. describe:: value
			
			Combined with the current state and top of the
			stack to discover the transition to take.
			
		.. describe:: *args, **kwargs
			
			Passed to the callback function, if it exists.
		
		"""
		key = (self._stack[-1], self._state, value)
		try:
			end_state, callback = self._transitions[key]
		except KeyError:
			raise ValueError ("No such transition: %r" % (key,))
			
		try:
			retval = callback (*args, **kwargs)
			self._state = end_state
			return retval
		except:
			self._state = 'error'
			raise
			
	def push (self, value):
		self._stack.append (value)
		
	def pop (self):
		self._stack.pop ()
		
class Token (object):
	"""Instance of a JSON token"""
	__slots__ = ['type', 'value', 'offset', 'full_string']
	def __init__ (self, token_type, full_string, offset, value):
		self.type = token_type
		self.offset = offset
		self.full_string = full_string
		self.value = value
	def __repr__ (self):
		return '%s<%r>' % (self.type.name, self.value)
		
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
	
	.. describe:: string
		
		The string to tokenize. Should be in unicode.
	
	"""
	position = 0
	for match in TOKEN_SPLITTER.findall (string):
		basic, atom, whitespace, unknown = match
		if basic:
			token_type = BASIC_TOKENS[basic]
			yield Token (token_type, string, position, basic)
		elif atom:
			yield Token ('ATOM', string, position, atom)
		elif whitespace:
			pass
		else:
			raise ReadError ("Unknown token: %r" % unknown_token)
		position += sum (map (len, match))
		
	yield Token ('EOF', string, position, '')
	
def read_unicode_escape (atom, index):
	"""Read a JSON-style Unicode escape.
	
	Unicode escapes may take one of two forms:
	
	* \\uUUUU, where UUUU is a series of four hexadecimal digits that
	indicate a code point in the Basic Multi-lingual Plane.
	
	* \\uUUUU\\uUUUU, where the two points encode a UTF-16 surrogate pair.
	  In builds of Python without wide character support, these are
	  returned as a surrogate pair.
	
	"""
	s = atom.value
	first_hex_str = s[index+1:index+5]
	if len (first_hex_str) < 4:
		error = format_error (atom.full_string, atom.offset + index - 1,
		                      "Unterminated unicode escape.")
		raise ReadError (error)
	first_hex = int (first_hex_str, 16)
	
	# Some code points are reserved for indicating surrogate pairs
	if 0xDC00 <= first_hex <= 0xDFFF:
		error = format_error (
			atom.full_string, atom.offset + index - 1,
			"U+%04X is a reserved code point." % first_hex
		)
		raise ReadError (error)
		
	# Check if it's a UTF-16 surrogate pair
	if not (0xD800 <= first_hex <= 0xDBFF):
		return unichr (first_hex), index + 4
		
	second_hex_str = s[index+5:index+11]
	if not (len (second_hex_str) >= 6 and second_hex_str.startswith ('\\u')):
		error = format_error (atom.full_string, atom.offset + index + 5,
		                      "Missing surrogate pair half.")
		raise ReadError (error)
		
	second_hex = int (second_hex_str[2:], 16)
	if sys.maxunicode <= 65535:
		retval = unichr (first_hex) + unichr (second_hex)
	else:
		# Convert to 10-bit halves of the 20-bit character
		first_hex -= 0xD800
		second_hex -= 0xDC00
		
		# Merge into 20-bit character
		retval = unichr ((first_half << 10) + second_half + 0x10000)
	return retval, index + 10
	
def read_unichars (atom):
	"""Read unicode characters from an escaped string."""
	string = atom.value
	assert string[0] == '"'
	assert string[-1] == '"'
	
	illegal = set (map (unichr, range (0x20)))
	
	index = 1
	escaped = False
	while True:
		while not escaped:
			char = string[index]
			if char == '\\':
				escaped = True
			elif char == '"':
				return
			elif char in illegal:
				error = format_error (
					atom.full_string, atom.offset + index,
					"Unexpected U+%04X." % ord (char),
				)
				raise ReadError (error)
			else:
				yield char
			index += 1
			
		while escaped:
			char = string[index]
			if char in READ_ESCAPES:
				yield READ_ESCAPES[char]
			elif char == 'u':
				unescaped, index = read_unicode_escape (atom, index)
				yield unescaped
			else:
				error = format_error (
					atom.full_string,
					# -1 to report the start of the escape code
					atom.offset + index - 1,
					"Unknown escape code: \\%s." % char,
				)
				raise ReadError (error)
			index += 1
			escaped = False
			
def parse_long (atom, string):
	"""Convert a string to a long, forbidding leading zeros."""
	if string[0] == '0':
		if len (string) > 1:
			error = format_error (atom, "Number with leading zero.")
			raise ReadError (error)
		return 0
	return int (string, 10)
	
def parse_number (atom, match):
	"""Parse a number from a regex match.
	
	Expects to have a match object from NUMBER_SPLITTER.
	
	"""
	int_part = parse_long (atom, match.group ('int'))
	if match.group ('frac') or match.group ('exp'):
		return Decimal (match.group (0))
	if match.group ('minus'):
		return -int_part
	return int_part
	
def next_char_ord (string):
	value = ord (string[0])
	if (0xD800 <= value <= 0xDBFF) and len (string) >= 2:
		upper = value
		lower = ord (string[1])
		upper -= 0xD800
		lower -= 0xDC00
		value = ((upper << 10) + lower) + 0x10000
		
	if value > 0xffff:
		return "U+%08X" % value
	return "U+%04X" % value
	
def parse_atom (atom):
	"""Parse a JSON atom into a Python value."""
	assert atom.type == 'ATOM'
	
	for keyword, value in KEYWORDS:
		if atom.value == keyword:
			return value
			
	# String
	if atom.value.startswith ('"'):
		assert atom.value.endswith ('"')
		return ''.join (read_unichars (atom))
		
	if atom.value[0] in ('-1234567890'):
		number_match = NUMBER_SPLITTER.match (atom.value)
		
		if number_match:
			return parse_number (atom, number_match)
		error = format_error (atom, "Invalid number.")
		raise ReadError (error)
		
	raise UnknownAtomError (atom.value)
	
def read (string):
	"""Parse a JSON expression into a Python value.
	
	If string is a byte string, it will be converted to Unicode
	before parsing (see unicode_autodetect_encoding).
	
	"""
	string = unicode_autodetect_encoding (string)
	read_item_stack = [([], 0)]
	
	# Callbacks
	def on_expected_root_value (token):
		try:
			parse_atom (token)
		except UnknownAtomError:
			on_unexpected (token)
		error = format_error (token, "Expecting an array or object.")
		raise ReadError (error)
		
	def on_array_start (token):
		machine.push ('array')
		read_item_stack.append (([], token.offset))
		
	def on_array_end (token):
		machine.pop ()
		array, _ = read_item_stack.pop ()
		read_item_stack[-1][0].append (array)
		
	def on_unterminated_array (_):
		_, start = read_item_stack[-1]
		error = format_error (token.full_string, start, "Unterminated array.")
		raise ReadError (error)
		
	def on_object_start (token):
		machine.push ('object')
		read_item_stack.append (([], token.offset))
		
	def on_object_key (token):
		"""Called when an object key is retrieved."""
		key = parse_atom (token)
		if isinstance (key, unicode):
			read_item_stack[-1][0].append (key)
		else:
			char_ord = next_char_ord (token.value)
			error = format_error (token, "Unexpected %s while looking for property name." % char_ord)
			raise ReadError (error)
			
	def on_object_end (_):
		"""Called when an object has ended."""
		machine.pop ()
		pairs, _ = read_item_stack.pop ()
		read_item_stack[-1][0].append (dict (chunk (pairs, 2)))
		
	def on_atom (atom):
		"""Called when an atom token is retrieved."""
		read_item_stack[-1][0].append (parse_atom (atom))
		
	def on_array_value (atom):
		try:
			on_atom (atom)
		except UnknownAtomError:
			on_expecting_array_value (atom)
			
	def on_unterminated_object (token):
		_, start = read_item_stack[-1]
		error = format_error (token.full_string, start, "Unterminated object.")
		raise ReadError (error)
		
	def on_expected_colon (token):
		char_ord = next_char_ord (token.value)
		error = format_error (token, "Unexpected %s while looking for colon." % char_ord)
		raise ReadError (error)
		
	def on_empty_expression (token):
		error = format_error (token.full_string, 0, "No expression found.")
		raise ReadError (error)
		
	def on_expected_object_key (token):
		char_ord = next_char_ord (token.value)
		error = format_error (token, "Unexpected %s while looking for property name." % char_ord)
		raise ReadError (error)
		
	def on_expected_object_value (token):
		char_ord = next_char_ord (token.value)
		error = format_error (token, "Unexpected %s while looking for property value." % char_ord)
		raise ReadError (error)
		
	def on_expecting_array_value (token):
		char_ord = next_char_ord (token.value)
		error = format_error (token, "Unexpected %s while looking for array value." % char_ord)
		raise ReadError (error)
		
	def on_expecting_comma (token):
		char_ord = next_char_ord (token.value)
		error = format_error (token, "Unexpected %s while looking for comma." % char_ord)
		raise ReadError (error)
		
	def on_extra_data (token):
		error = format_error (token, "Extra data after JSON expression.")
		raise ReadError (error)
		
	def on_unexpected (token):
		char_ord = next_char_ord (token.value)
		error = format_error (token, "Unexpected %s." % char_ord)
		raise ReadError (error)
		
	machine = StateMachine ('need-value', ['root'])
	
	# Register state transitions
	machine.connect_many (
		('root', 'need-value',
			('ATOM', 'error', on_expected_root_value),
			('ARRAY_START', 'empty', on_array_start),
			('ARRAY_END', 'error', on_unexpected),
			('OBJECT_START', 'empty', on_object_start),
			('OBJECT_END', 'error', on_unexpected),
			('COMMA', 'error', on_unexpected),
			('COLON', 'error', on_unexpected),
			('EOF', 'error', on_empty_expression)),
		('root', 'got-value',
			('ATOM', 'error', on_extra_data),
			('ARRAY_START', 'error', on_extra_data),
			('ARRAY_END', 'error', on_extra_data),
			('OBJECT_START', 'error', on_extra_data),
			('OBJECT_END', 'error', on_extra_data),
			('COMMA', 'error', on_extra_data),
			('COLON', 'error', on_extra_data),
			('EOF', 'complete')),
		('array', 'empty',
			('ATOM', 'got-value', on_array_value),
			('ARRAY_START', 'empty', on_array_start),
			('ARRAY_END', 'got-value', on_array_end),
			('OBJECT_START', 'empty', on_object_start),
			('OBJECT_END', 'error', on_expecting_array_value),
			('COMMA', 'error', on_expecting_array_value),
			('COLON', 'error', on_expecting_array_value),
			('EOF', 'error', on_unterminated_array)),
		('array', 'need-value',
			('ATOM', 'got-value', on_atom),
			('ARRAY_START', 'empty', on_array_start),
			('ARRAY_END', 'error', on_expecting_array_value),
			('OBJECT_START', 'empty', on_object_start),
			('OBJECT_END', 'error', on_expecting_array_value),
			('COMMA', 'error', on_expecting_array_value),
			('COLON', 'error', on_expecting_array_value),
			('EOF', 'error', on_unterminated_array)),
		('array', 'got-value',
			('ATOM', 'error', on_expecting_comma),
			('ARRAY_START', 'error', on_expecting_comma),
			('ARRAY_END', 'got-value', on_array_end),
			('OBJECT_START', 'error', on_expecting_comma),
			('OBJECT_END', 'error', on_expecting_comma),
			('COMMA', 'need-value'),
			('COLON', 'error', on_expecting_comma),
			('EOF', 'error', on_unterminated_array)),
		('object', 'empty',
			('ATOM', 'with-key', on_object_key),
			('ARRAY_START', 'error', on_expected_object_key),
			('ARRAY_END', 'error', on_expected_object_key),
			('OBJECT_START', 'error', on_expected_object_key),
			('OBJECT_END', 'got-value', on_object_end),
			('COMMA', 'error', on_expected_object_key),
			('COLON', 'error', on_expected_object_key),
			('EOF', 'error', on_unterminated_object)),
		('object', 'with-key',
			('ATOM', 'error', on_expected_colon),
			('ARRAY_START', 'error', on_expected_colon),
			('ARRAY_END', 'error', on_expected_colon),
			('OBJECT_START', 'error', on_expected_colon),
			('OBJECT_END', 'error', on_expected_colon),
			('COMMA', 'error', on_expected_colon),
			('COLON', 'need-value'),
			('EOF', 'error', on_unterminated_object)),
		('object', 'need-value',
			('ATOM', 'got-value', on_atom),
			('ARRAY_START', 'empty', on_array_start),
			('ARRAY_END', 'error', on_expected_object_value),
			('OBJECT_START', 'empty', on_object_start),
			('OBJECT_END', 'error', on_expected_object_value),
			('COMMA', 'error', on_expected_object_value),
			('COLON', 'error', on_expected_object_value),
			('EOF', 'error', on_unterminated_object)),
		('object', 'got-value',
			('ATOM', 'error', on_expecting_comma),
			('ARRAY_START', 'error', on_expecting_comma),
			('ARRAY_END', 'error', on_expecting_comma),
			('OBJECT_START', 'error', on_expecting_comma),
			('OBJECT_END', 'got-value', on_object_end),
			('COMMA', 'need-key'),
			('COLON', 'error', on_expecting_comma),
			('EOF', 'error', on_unterminated_object)),
		('object', 'need-key',
			('ATOM', 'with-key', on_object_key),
			('ARRAY_START', 'error', on_expected_object_key),
			('ARRAY_END', 'error', on_expected_object_key),
			('OBJECT_START', 'error', on_expected_object_key),
			('OBJECT_END', 'error', on_expected_object_key),
			('COMMA', 'error', on_expected_object_key),
			('COLON', 'error', on_expected_object_key),
			('EOF', 'error', on_unterminated_object)),
	)
	
	for token in tokenize (string):
		try:
			machine.transition (token.type, token)
		except ReadError:
			raise
		except ValueError, error:
			raise ReadError (unicode (error))
			
	return read_item_stack[0][0][0]
	
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
	header = tuple (1 if ord (b) else 0 for b in bytestring[:4])
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
		
def write_array (value, sort_keys, indent_string, ascii_only, coerce_keys,
                 on_unknown, parent_objects, indent_level):
	"""Serialize an iterable to a list of strings in JSON array format."""
	
	v_id = id (value)
	if v_id in parent_objects:
		raise WriteError ("Cannot serialize self-referential values.")
		
	if len (value) == 0:
		return '[]'
		
	separators = get_separators ('[', ']', indent_string, indent_level)
	start, end, pre_value, post_value = separators
	
	retval = [start]
	
	for index, item in enumerate (value):
		retval.append (pre_value)
		retval.extend (_py_write (item, sort_keys, indent_string,
		                          ascii_only, coerce_keys, on_unknown,
		                          parent_objects + (v_id,),
		                          indent_level + 1))
		if (index + 1) < len (value):
			retval.append (post_value)
	retval.append (end)
	return retval
	
def write_iterable (value, *args, **kwargs):
	return write_array (tuple (value), *args, **kwargs)
	
def write_object (value, sort_keys, indent_string, ascii_only, coerce_keys,
                  on_unknown, parent_objects, indent_level):
	"""Serialize a mapping to a list of strings in JSON object format."""
	
	v_id = id (value)
	if v_id in parent_objects:
		raise WriteError ("Cannot serialize self-referential values.")
		
	if len (value) == 0:
		return '{}'
		
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
			except UnknownSerializerError:
				new_key = unicode (key)
			retval.extend (write_unicode (new_key, ascii_only))
		else:
			raise WriteError ("Only strings may be used as object "
			                  "keys.")
		if indent_string is not None:
			retval.append (': ')
		else:
			retval.append (':')
		retval.extend (_py_write (sub_value, sort_keys, indent_string,
		                          ascii_only, coerce_keys, on_unknown,
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
	
def _py_write (value, sort_keys, indent_string, ascii_only, coerce_keys,
               on_unknown, parent_objects, indent_level,
               in_on_unknown = False):
	"""Serialize a Python value into a list of byte strings.
	
	When joined together, result in the value's JSON representation.
	
	"""
	# Check basic types first
	for keyword, kw_value in KEYWORDS:
		if value is kw_value:
			return (keyword,)
			
	for type_, func in BASIC_TYPE_WRITERS:
		if isinstance (value, type_):
			if not parent_objects:
				err = "The outermost container must be an array or object."
				raise WriteError (err)
			return func (value)
			
	for type_, func in STR_TYPE_WRITERS:
		if isinstance (value, type_):
			if not parent_objects:
				err = "The outermost container must be an array or object."
				raise WriteError (err)
			return func (value, ascii_only)
			
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
				return _py_write (new_value, sort_keys,
				                  indent_string, ascii_only,
				                  coerce_keys,
				                  on_unknown, parent_objects,
				                  indent_level, True)
			raise UnknownSerializerError (value)
			
	return func (value, sort_keys, indent_string, ascii_only,
	             coerce_keys, on_unknown, parent_objects, indent_level)
	
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
	pieces = _py_write (value, sort_keys, indent, ascii_only,
	                    coerce_keys, on_unknown, (), 0)
	u_string = u''.join (pieces)
	if encoding is None:
		return u_string
	return u_string.encode (encoding)
	
# }}}

