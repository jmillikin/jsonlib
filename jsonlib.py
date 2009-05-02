# Copyright (C) 2008-2009 John Millikin <jmillikin@gmail.com>
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""JSON serializer/deserializer for Python.

The main implementation of this module is accessed through calls to
``read()`` and ``write()``. See their documentation for details.

"""
__author__ = "John Millikin <jmillikin@gmail.com>"
__version__ = (1, 4)
__license__ = "GPL"

__all__ = [
	'loads', 'dumps', 'read', 'write',
	'ReadError', 'WriteError', 'UnknownSerializerError',
]

import codecs
from decimal import Decimal
import re
import sys
import abc
import collections

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
	
ALLOWED_WHITESPACE = '\u0020\u0009\u000A\u000D'
# }}}

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

# Parser {{{
def unicode_autodetect_encoding (bytestring):
	"""Intelligently convert a byte string to Unicode.
	
	Assumes the encoding used is one of the UTF-* variants. If the
	input is already in unicode, this is a noop.
	
	"""
	if isinstance (bytestring, str):
		return bytestring
		
	# Check for UTF byte order marks in the bytestring
	for bom, encoding in UNICODE_BOMS:
		if bytestring.startswith (bom):
			return bytestring[len(bom):].decode (encoding)
			
	# Autodetect UTF-* encodings using the algorithm in the RFC
	# Don't use inline if..else for Python 2.4
	header = tuple ((1 if b else 0) for b in bytestring[:4])
	for utf_header, encoding in UTF_HEADERS:
		if header == utf_header:
			return bytestring.decode (encoding)
			
	# Default to UTF-8
	return bytestring.decode ('utf-8')
	
class Parser:
	def __init__ (self, text, use_float):
		self.text = text
		self.index = 0
		self.use_float = use_float
		
	def parse (self):
		value = self.parse_raw (True)
		self.skip_whitespace ()
		if self.index != len (self.text):
			raise ReadError (self.text, self.index, "Extra data after JSON expression.")
		return value
		
	def parse_raw (self, root = False):
		self.skip_whitespace ()
		if self.index == len (self.text):
			raise ReadError (self.text, 0, "No expression found.")
		c = self.text[self.index]
		if c == '{':
			return self.read_object ()
		if c == '[':
			return self.read_array ()
		if root:
			self.raise_unexpected ()
		if c == '"':
			return self.read_string ()
		if c in 'tfn':
			return self.read_keyword ()
		if c in '-0123456789':
			return self.read_number ()
		self.raise_unexpected ()
		
	def read_object (self):
		retval = {}
		start = self.index
		skip = lambda: self.skip_whitespace (start, "Unterminated object.")
		c = lambda: self.text[self.index]
		
		self.skip ('{', "object start")
		skip ()
		if c () == '}':
			self.skip ('}', "object start")
			return retval
		while True:
			skip ()
			if c () != '"':
				self.raise_unexpected ("property name")
			key = self.parse_raw ()
			skip ()
			self.skip (':', "colon")
			skip ()
			value = self.parse_raw ()
			retval[key] = value
			skip ()
			if c () == '}':
				self.skip ('}', "object start")
				return retval
			self.skip (',', "comma")
			
	def read_array (self):
		retval = []
		start = self.index
		skip = lambda: self.skip_whitespace (start, "Unterminated array.")
		c = lambda: self.text[self.index]
		
		self.skip ('[', "array start")
		skip ()
		if c () == ']':
			self.skip (']', "array start")
			return retval
		while True:
			skip ()
			value = self.parse_raw ()
			retval.append (value)
			skip ()
			if c () == ']':
				self.skip (']', "array start")
				return retval
			self.skip (',', "comma")
			
		
	def read_string (self):
		start = self.index
		escaped = False
		chunks = []
		
		self.skip ('"', "string start")
		while True:
			while not escaped:
				c = self.text[self.index]
				if c == '\\':
					escaped = True
				elif c == '"':
					self.skip ('"', "string end")
					return ''.join (chunks)
				elif ord (c) < 0x20:
					self.raise_unexpected ()
				else:
					chunks.append (c)
				self.index += 1
				
			while escaped:
				c = self.text[self.index]
				if c == 'u':
					unescaped = self.read_unicode_escape ()
					chunks.append (unescaped)
				elif c in READ_ESCAPES:
					chunks.append (READ_ESCAPES[c])
				else:
					raise ReadError (self.text, self.index - 1,
						"Unknown escape code: \\%s." % c)
				self.index += 1
				escaped = False
				
	def read_unicode_escape (self):
		"""Read a JSON-style Unicode escape.
		
		Unicode escapes may take one of two forms:
		
		* \\uUUUU, where UUUU is a series of four hexadecimal digits that
		indicate a code point in the Basic Multi-lingual Plane.
		
		* \\uUUUU\\uUUUU, where the two points encode a UTF-16 surrogate pair.
		  In builds of Python without wide character support, these are
		  returned as a surrogate pair.
		
		"""
		first_hex_str = self.text[self.index+1:self.index+5]
		if len (first_hex_str) < 4 or '"' in first_hex_str:
			raise ReadError (self.text, self.index - 1, "Unterminated unicode escape.")
		first_hex = int (first_hex_str, 16)
		
		# Some code points are reserved for indicating surrogate pairs
		if 0xDC00 <= first_hex <= 0xDFFF:
			raise ReadError (self.text, self.index - 1,
				"U+%04X is a reserved code point." % first_hex)
			
		# Check if it's a UTF-16 surrogate pair
		if not (0xD800 <= first_hex <= 0xDBFF):
			self.index += 4
			return chr (first_hex)
			
		second_hex_str = self.text[self.index+5:self.index+11]
		if (not (len (second_hex_str) >= 6
			and second_hex_str.startswith ('\\u'))
		    or '"' in second_hex_str):
			raise ReadError (self.text, self.index + 5, "Missing surrogate pair half.")
			
		second_hex = int (second_hex_str[2:], 16)
		if sys.maxunicode <= 65535:
			retval = chr (first_hex) + chr (second_hex)
		else:
			# Convert to 10-bit halves of the 20-bit character
			first_hex -= 0xD800
			second_hex -= 0xDC00
			
			# Merge into 20-bit character
			retval = chr ((first_hex << 10) + second_hex + 0x10000)
		self.index += 10
		return retval
		
	def read_keyword (self):
		for text, value in KEYWORDS:
			end = self.index + len (text)
			if self.text[self.index:end] == text:
				self.index = end
				return value
		self.raise_unexpected ()
		
	def read_number (self):
		allowed = '0123456789-+.eE'
		end = self.index
		try:
			while self.text[end] in allowed:
				end += 1
		except IndexError:
			pass
		match = NUMBER_SPLITTER.match (self.text[self.index:end])
		if not match:
			raise ReadError (self.text, self.index, "Invalid number.")
			
		self.index = end
		int_part = int (match.group ('int'), 10)
		if match.group ('frac') or match.group ('exp'):
			if self.use_float:
				return float (match.group (0))
			return Decimal (match.group (0))
		if match.group ('minus'):
			return -int_part
		return int_part
		
	def skip (self, text, error):
		new_index = self.index + len (text)
		skipped = self.text[self.index:new_index]
		if skipped != text:
			self.raise_unexpected (error)
		self.index = new_index
		
	def skip_whitespace (self, start = None, err = None):
		text_len = len (self.text)
		ws = '\x09\x20\x0a\x0d'
		while self.index < text_len and self.text[self.index] in ws:
			self.index += 1
		if self.index >= text_len and (start is not None) and (err is not None):
			raise ReadError (self.text, start, err)
			
	def next_char_ord (self):
		value = ord (self.text[self.index])
		if (0xD800 <= value <= 0xDBFF) and len (self.text) >= 2:
			upper = value
			lower = ord (self.text[self.index + 1])
			upper -= 0xD800
			lower -= 0xDC00
			value = ((upper << 10) + lower) + 0x10000
			
		if value > 0xffff:
			return "U+%08X" % value
		return "U+%04X" % value
		
	def raise_unexpected (self, looking_for = None):
		char_ord = self.next_char_ord ()
		if looking_for is None:
			desc = "Unexpected %s." % (char_ord,)
		else:
			desc = "Unexpected %s while looking for %s." % (char_ord, looking_for)
		raise ReadError (self.text, self.index, desc)
		
def read (bytestring, use_float = False):
	text = unicode_autodetect_encoding (bytestring)
	parser = Parser (text, use_float)
	return parser.parse ()
	
loads = read
# }}}

# Encoder {{{
class Encoder (metaclass = abc.ABCMeta):
	def __init__ (self, sort_keys, indent, ascii_only,
	              coerce_keys, encoding, on_unknown):
		self.sort_keys = sort_keys
		self.indent = validate_indent (indent)
		self.ascii_only = ascii_only
		self.coerce_keys = coerce_keys
		self.encoding = encoding
		self.on_unknown = validate_on_unknown (on_unknown)
		
	@abc.abstractmethod
	def append (self, value):
		raise NotImplementedError
		
	@abc.abstractmethod
	def encode (self, value):
		raise NotImplementedError
		
	def encode_object (self, value, parent_ids, in_unknown_hook = False):
		if isinstance (value, str):
			self.encode_string (value)
		elif isinstance (value, collections.Mapping):
			self.encode_mapping (value, parent_ids)
		elif isinstance (value, collections.Iterable):
			self.encode_iterable (value, parent_ids)
		else:
			try:
				self.encode_basic (value)
			except UnknownSerializerError:
				if in_unknown_hook:
					raise
			else:
				return
			new_value = self.on_unknown (value)
			return self.encode_object (new_value, parent_ids, True)
			
	def get_separators (self, indent_level):
		if self.indent is None:
			return '', ''
		else:
			indent = '\n' + (self.indent * (indent_level + 1))
			post_indent = '\n' + (self.indent * indent_level)
			return indent, post_indent
			
	def encode_mapping (self, value, parent_ids):
		v_id = id (value)
		if v_id in parent_ids:
			raise WriteError ("Cannot serialize self-referential values.")
			
		a = self.append
		first = True
		items = value.items ()
		if self.sort_keys:
			items = sorted (items)
			
		indent, post_indent = self.get_separators (len (parent_ids))
		
		a ('{')
		for key, item in items:
			if not isinstance (key, str):
				if self.coerce_keys:
					key = str (key)
				else:
					raise WriteError ("Only strings may be used as object keys.")
			if first:
				first = False
			else:
				a (',')
			a (indent)
			self.encode_object (key, parent_ids + [v_id])
			if self.indent is None:
				a (':')
			else:
				a (': ')
			self.encode_object (item, parent_ids + [v_id])
		a (post_indent)
		a ('}')
		
	def encode_iterable (self, value, parent_ids):
		v_id = id (value)
		if v_id in parent_ids:
			raise WriteError ("Cannot serialize self-referential values.")
			
		a = self.append
		
		indent, post_indent = self.get_separators (len (parent_ids))
		
		a ('[')
		first = True
		for item in value:
			if first:
				first = False
			else:
				a (',')
			a (indent)
			self.encode_object (item, parent_ids + [v_id])
		a (post_indent)
		a (']')
		
	def encode_basic (self, value):
		for keyword, kw_value in KEYWORDS:
			if value is kw_value:
				return self.append (keyword)
				
		if isinstance (value, int):
			self.append (str (value))
		elif isinstance (value, float):
			return self.encode_float (value)
		elif isinstance (value, complex):
			return self.encode_complex (value)
		elif isinstance (value, Decimal):
			return self.encode_decimal (value)
		else:
			raise UnknownSerializerError (value)
			
	def encode_string (self, value):
		a = self.append
		stream = iter (value)
		a ('"')
		for char in stream:
			ochar = ord (char)
			if char in WRITE_ESCAPES:
				a (WRITE_ESCAPES[char])
			elif ochar > 0x7E:
				# Prevent invalid surrogate pairs from being
				# serialized.
				if 0xD800 <= ochar <= 0xDBFF:
					try:
						nextc = next (stream)
					except StopIteration:
						raise WriteError ("Cannot serialize incomplete surrogate pair.")
					onext = ord (nextc)
					if not (0xDC00 <= onext <= 0xDFFF):
						raise WriteError ("Cannot serialize invalid surrogate pair.")
					if self.ascii_only:
						a ('\\u%04x\\u%04x' % (ochar, onext))
					else:
						a (char)
						a (nextc)
				elif 0xDC00 <= ochar <= 0xDFFF:
					raise WriteError ("Cannot serialize reserved code point U+%04X." % ochar)
				elif self.ascii_only:
					if ochar > 0xFFFF:
						unicode_value = ord (char)
						reduced = unicode_value - 0x10000
						second_half = (reduced & 0x3FF) # Lower 10 bits
						first_half = (reduced >> 10)
					
						first_half += 0xD800
						second_half += 0xDC00
					
						a ('\\u%04x\\u%04x'% (first_half, second_half))
					else:
						a ('\\u%04x' % ochar)
				else:
					a (char)
			else:
				a (char)
				
		a ('"')
		
	def encode_float (self, value):
		if value != value:
			raise WriteError ("Cannot serialize NaN.")
		if value == INFINITY:
			raise WriteError ("Cannot serialize Infinity.")
		if value == -INFINITY:
			raise WriteError ("Cannot serialize -Infinity.")
		self.append (repr (value))
		
	def encode_complex (self, value):
		if value.imag == 0.0:
			self.append (repr (value.real))
		else:
			raise WriteError ("Cannot serialize complex numbers with"
			                  " imaginary components.")
			
	def encode_decimal (self, value):
		if value != value:
			raise WriteError ("Cannot serialize NaN.")
		s_value = str (value)
		if s_value in ('Infinity', '-Infinity'):
			raise WriteError ("Cannot serialize %s." % s_value)
		self.append (s_value)
		
class StreamEncoder(Encoder):
	def __init__ (self, fp, sort_keys, indent, ascii_only,
	              coerce_keys, encoding, on_unknown):
		super (StreamEncoder, self).__init__ (
			sort_keys, indent, ascii_only, coerce_keys,
			encoding, on_unknown)
		self.fp = fp
		
	def append (self, value):
		if self.encoding is not None:
			value = value.encode (self.encoding)
		self.fp.write (value)
		
	def encode (self, value):
		self.encode_object (value, [])
		
class BufferEncoder(Encoder):
	def __init__ (self, sort_keys, indent, ascii_only,
	              coerce_keys, encoding, on_unknown):
		super (BufferEncoder, self).__init__ (
			sort_keys, indent, ascii_only, coerce_keys,
			encoding, on_unknown)
		self.chunks = []
		
	def append (self, value):
		self.chunks.append (value)
		
	def encode (self, value):
		self.encode_object (value, [])
		str_result = ''.join (self.chunks)
		if self.encoding is None:
			return str_result
		return str_result.encode (self.encoding)
		
def dump (value, fp, sort_keys = False, indent = None, ascii_only = True,
          coerce_keys = False, encoding = 'utf-8', on_unknown = None):
	encoder = StreamEncoder (fp, sort_keys, indent, ascii_only,
	                         coerce_keys, encoding, on_unknown)
	encoder.encode (value)
	
def write (value, sort_keys = False, indent = None, ascii_only = True,
           coerce_keys = False, encoding = 'utf-8', on_unknown = None):
	encoder = BufferEncoder (sort_keys, indent, ascii_only, coerce_keys,
	                         encoding, on_unknown)
	return encoder.encode (value)
	
dumps = write

def validate_indent (indent):
	if indent is not None:
		indent = str (indent)
	if not (indent is None or len (indent) == 0):
		if len (indent.strip (ALLOWED_WHITESPACE)) > 0:
			raise TypeError ("Only whitespace may be used for indentation.")
	return indent
	
def validate_on_unknown (f):
	def default_f (value):
		return value
	if f is None:
		return default_f
	if not isinstance (f, collections.Callable):
		raise TypeError ("The on_unknown object must be callable.")
	return f
# }}}
