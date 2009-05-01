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
	header = tuple ((1 if ord (b) else 0) for b in bytestring[:4])
	for utf_header, encoding in UTF_HEADERS:
		if header == utf_header:
			return bytestring.decode (encoding)
			
	# Default to UTF-8
	return bytestring.decode ('utf-8')
	
class Parser:
	def __init__ (self, use_float):
		self.use_float = use_float
	pass
	
def read (bytestring, use_float = False):
	parser = Parser (use_float)
	string = unicode_autodetect_encoding (bytestring)
	return parser.parse (string)
	
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
			
	def encode_mapping (self, value, parent_ids):
		v_id = id (value)
		if v_id in parent_ids:
			raise WriteError ("Cannot serialize self-referential values.")
			
		a = self.append
		a ('{')
		first = True
		items = value.items ()
		if self.sort_keys:
			items = sorted (items)
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
			self.encode_object (key, parent_ids + [v_id])
			a (':')
			self.encode_object (item, parent_ids + [v_id])
		a ('}')
		
	def encode_iterable (self, value, parent_ids):
		v_id = id (value)
		if v_id in parent_ids:
			raise WriteError ("Cannot serialize self-referential values.")
			
		a = self.append
		a ('[')
		first = True
		for item in value:
			if first:
				first = False
			else:
				a (',')
			self.encode_object (item, parent_ids + [v_id])
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
		self.fp.write (value)
		
	def encode (self, value):
		raise NotImplementedError
		
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
