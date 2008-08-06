# Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
# Author: John Millikin <jmillikin@gmail.com>

# Imports {{{
import array
import codecs
import collections
from decimal import Decimal
import sets
import unittest
import UserList
import UserDict
import UserString
import functools

from jsonlib import read, write, ReadError, WriteError, UnknownSerializerError
# }}}

# Support & Utility definitions {{{
try:
	INFINITY = float ('inf')
except ValueError:
	INFINITY = 1e300000
try:
	NAN = float ('nan')
except ValueError:
	NAN = INFINITY/INFINITY
	
try:
	codecs.lookup ('utf32')
except LookupError:
	HAVE_UTF32 = False
else:
	HAVE_UTF32 = True
	
class ContinuableTestCase (unittest.TestCase):
	def run (self, result = None):
		if result is None:
			result = self.defaultTestResult ()
		self._result = result
		return super (ContinuableTestCase, self).run (result)
		
def allow_test_continue (func):
	@functools.wraps (func)
	def new_func (self, *args, **kwargs):
		try:
			return func (self, *args, **kwargs)
		except self.failureException:
			self._result.addFailure (self, self._exc_info ())
	return new_func
	
class ParserTestCase (ContinuableTestCase):
	@allow_test_continue
	def r (self, string, expected):
		value = read (string)
		self.assertEqual (value, expected)
		self.assertEqual (type (value), type (expected))
		
	@allow_test_continue
	def re (self, string, line, column, position, expected_error_message):
		full_expected = ("JSON parsing error at line %d, column %d"
		                 " (position %d): %s" % (line, column,
		                                         position,
		                                         expected_error_message))
		try:
			read (string)
			self.fail ("No exception raised.")
		except ReadError, error:
			self.assertEqual (unicode (error), full_expected)
			
class SerializerTestCase (ContinuableTestCase):
	@allow_test_continue
	def w (self, value, expected, **kwargs):
		serialized = write (value, encoding = None, **kwargs)
		self.assertEqual (serialized, expected)
		self.assertEqual (type (serialized), type (expected))
		
	@allow_test_continue
	def we (self, value, expected_error_message, error_type = None, **kwargs):
		if error_type is None:
			error_type = WriteError
		try:
			write (value, **kwargs)
			self.fail ("No exception raised.")
		except error_type, error:
			self.assertEqual (unicode (error), expected_error_message)
			
def _load_tests (base_class):
	loader = unittest.TestLoader ()
	suite = unittest.TestSuite ()
	from_local = loader.loadTestsFromTestCase
	for name, value in globals ().items ():
		if (isinstance (value, type) and
		    issubclass (value, base_class)):
			suite.addTests (from_local (value))
	return suite
	
def parser ():
	return _load_tests (ParserTestCase)
	
def serializer ():
	return _load_tests (SerializerTestCase)
	
def suite ():
	return _load_tests (unittest.TestCase)
	
# }}}

# Tests for the parser {{{
class ReadMiscTests (ParserTestCase):
	def test_fail_on_empty (self):
		self.re ('', 1, 1, 0, "No expression found.")
		self.re (' ', 1, 1, 0, "No expression found.")
		
	def test_fail_on_invalid_whitespace (self):
		self.re (u'[\u000C]', 1, 2, 1, "Unexpected U+000C.")
		self.re (u'[\u000E]', 1, 2, 1, "Unexpected U+000E.")
		self.re (u'[\u00A0]', 1, 2, 1, "Unexpected U+00A0.")
		self.re (u'[\u2002]', 1, 2, 1, "Unexpected U+2002.")
		self.re (u'[\u2028]', 1, 2, 1, "Unexpected U+2028.")
		self.re (u'[\u2029]', 1, 2, 1, "Unexpected U+2029.")
		
	def test_with_two_lines (self):
		self.re (u'\n[\u000B]', 2, 2, 2, "Unexpected U+000B.")
		
	def test_unexpected_character (self):
		self.re (u'[+]', 1, 2, 1, "Unexpected U+002B.")
		
	def test_unexpected_character_astral (self):
		self.re (u'[\U0001d11e]', 1, 2, 1, "Unexpected U+0001D11E.")
		
	def test_no_unwrapped_values (self):
		self.re (u'1', 1, 1, 0, "Expecting an array or object.")
		
	def test_parse_atom_before_unwrapped_check (self):
		self.re (u'n', 1, 1, 0, "Unexpected U+006E.")
		
class ReadExtraDataTests (ParserTestCase):
	def test_array_start (self):
		self.re ('[][', 1, 3, 2, "Extra data after JSON expression.")
		
	def test_array_end (self):
		self.re ('[]]', 1, 3, 2, "Extra data after JSON expression.")
		
	def test_object_start (self):
		self.re ('[]{', 1, 3, 2, "Extra data after JSON expression.")
		
	def test_object_end (self):
		self.re ('[]}', 1, 3, 2, "Extra data after JSON expression.")
		
	def test_atom (self):
		self.re ('[]1', 1, 3, 2, "Extra data after JSON expression.")
		
	def test_comma (self):
		self.re ('[],', 1, 3, 2, "Extra data after JSON expression.")
		
	def test_colon (self):
		self.re ('[]:', 1, 3, 2, "Extra data after JSON expression.")
		
	def test_other (self):
		self.re ('[]+', 1, 3, 2, "Extra data after JSON expression.")
		
	def test_array_whitespace (self):
		self.r ('[] ', [])
		
	def test_object_whitespace (self):
		self.r ('{} ', {})
		
class ReadUnexpectedTests (ParserTestCase):
	def test_array_end (self):
		self.re (']', 1, 1, 0, "Unexpected U+005D.")
		
	def test_object_end (self):
		self.re ('}', 1, 1, 0, "Unexpected U+007D.")
		
	def test_comma (self):
		self.re (',', 1, 1, 0, "Unexpected U+002C.")
		
	def test_colon (self):
		self.re (':', 1, 1, 0, "Unexpected U+003A.")
		
	def test_other (self):
		self.re ('+', 1, 1, 0, "Unexpected U+002B.")
		
class ReadKeywordTests (ParserTestCase):
	def test_null (self):
		self.r ('[null]', [None])
		
	def test_true (self):
		self.r ('[true]', [True])
		
	def test_false (self):
		self.r ('[false]', [False])
		
	def test_invalid_keyword (self):
		self.re ('[n]', 1, 2, 1, "Unexpected U+006E.")
		self.re ('[t]', 1, 2, 1, "Unexpected U+0074.")
		self.re ('[f]', 1, 2, 1, "Unexpected U+0066.")
		
class ReadNumberTests (ParserTestCase):
	def test_zero (self):
		self.r ('[0]', [0L])
		
	def test_negative_zero (self):
		self.r ('[-0]', [0L])
		
	def test_two_zeroes_error (self):
		self.re ('[00]', 1, 2, 1, "Number with leading zero.")
		self.re ('[01]', 1, 2, 1, "Number with leading zero.")
		self.re ('[00.1]', 1, 2, 1, "Number with leading zero.")
		
	def test_negative_two_zeroes_error (self):
		self.re ('[-00]', 1, 2, 1, "Number with leading zero.")
		self.re ('[-01]', 1, 2, 1, "Number with leading zero.")
		self.re ('[-00.1]', 1, 2, 1, "Number with leading zero.")
		
	def test_int (self):
		for ii in range (10):
			self.r ('[%d]' % ii, [long (ii)])
			self.r ('[-%d]' % ii, [long (-ii)])
			
	def test_decimal (self):
		self.r ('[1.2345]', [Decimal ('1.2345')])
		
	def test_negative_decimal (self):
		self.r ('[-1.2345]', [Decimal ('-1.2345')])
		
	def test_zero_after_decimal (self):
		self.r ('[0.01]', [Decimal ('0.01')])
		
	def test_exponent (self):
		self.r ('[1e2]', [Decimal ('100.0')])
		self.r ('[10e2]', [Decimal ('1000.0')])
		
	def test_exponent_plus (self):
		self.r ('[1e+2]', [Decimal ('100.0')])
		self.r ('[10e+2]', [Decimal ('1000.0')])
		
	def test_negative_exponent (self):
		self.r ('[1e-2]', [Decimal ('0.01')])
		self.r ('[10e-2]', [Decimal ('0.1')])
		
	def test_decimal_exponent (self):
		self.r ('[10.5e2]', [Decimal ('1050.0')])
		
	def test_negative_decimal_exponent (self):
		self.r ('[10.5e-2]', [Decimal ('0.105')])
		
	def test_preserve_negative_decimal_zero (self):
		# Don't use self.r, because Decimal ('0.0') == Decimal ('-0.0')
		value = read ('[0.0]')
		self.assertEqual (type (value[0]), Decimal)
		self.assertEqual (repr (value[0]), 'Decimal("0.0")')
		
		value = read ('[-0.0]')
		self.assertEqual (type (value[0]), Decimal)
		self.assertEqual (repr (value[0]), 'Decimal("-0.0")')
		
	def test_invalid_number (self):
		self.re ('[-.]', 1, 2, 1, "Invalid number.")
	
	def test_invalid_number_2 (self):
		self.re ('[0.]', 1, 2, 1, "Invalid number.")
		
	def test_no_plus_sign (self):
		self.re ('[+1]', 1, 2, 1, "Unexpected U+002B.")
		
	def test_non_ascii_number (self):
		self.re (u'[\u0661]', 1, 2, 1, "Unexpected U+0661.")
		
class ReadStringTests (ParserTestCase):
	def test_empty_string (self):
		self.r ('[""]', [u''])
		
	def test_basic_string (self):
		self.r ('["test"]', [u'test'])
		
	def test_unescape_quote (self):
		self.r ('["\\""]', [u'"'])
		
	def test_unescape_reverse_solidus (self):
		self.r ('["\\\\"]', [u'\\'])
		
	def test_unescape_solidus (self):
		self.r ('["\\/"]', [u'/'])
		
	def test_unescape_backspace (self):
		self.r ('["\\b"]', [u'\b'])
		
	def test_unescape_form_feed (self):
		self.r ('["\\f"]', [u'\f'])
		
	def test_unescape_line_feed (self):
		self.r ('["\\n"]', [u'\n'])
		
	def test_unescape_carriage_return (self):
		self.r ('["\\r"]', [u'\r'])
		
	def test_unescape_tab (self):
		self.r ('["\\t"]', [u'\t'])
		
	def test_string_with_whitespace (self):
		self.r ('[" \\" "]', [u" \" "])
		
	def test_unescape_single_unicode (self):
		self.r ('["\\u005C"]', [u'\\'])
		self.r ('["\\u005c"]', [u'\\'])
		
	def test_unescape_double_unicode (self):
		self.r ('["\\uD834\\uDD1E"]', [u'\U0001d11e'])
		self.r ('["\\ud834\\udd1e"]', [u'\U0001d11e'])
		
	def test_unescape_unicode_followed_by_normal (self):
		self.r ('["\\u00e9a"]', [u'\u00e9a'])
		
	def test_end_of_stream (self):
		self.re ('["test\\u"]', 1, 7, 6,
		        "Unterminated unicode escape.")
		
	def test_missing_surrogate (self):
		self.re ('["\\uD834"]', 1, 9, 8,
		        "Missing surrogate pair half.")
		self.re ('["\\uD834\\u"]', 1, 9, 8,
		        "Missing surrogate pair half.")
		self.re ('["\\uD834\\u", "hello world"]', 1, 9, 8,
		        "Missing surrogate pair half.")
		self.re ('["\\uD834testing"]', 1, 9, 8,
		        "Missing surrogate pair half.")
		
	def test_invalid_codepoint (self):
		self.re ('["\\uDD1E"]', 1, 3, 2,
		        "U+DD1E is a reserved code point.")
		
	def test_invalid_escape (self):
		self.re (u'["\\a"]', 1, 3, 2, "Unknown escape code: \\a.")
		
	def test_direct_unicode (self):
		self.r (u'["\U0001d11e"]', [u'\U0001d11e'])
		
	def test_bmp_unicode (self):
		self.r (u'["\u24CA"]'.encode ('utf-8'), [u'\u24CA'])
		
	def test_astral_unicode (self):
		self.r (u'["\U0001d11e"]'.encode ('utf-8'), [u'\U0001d11e'])
		
	def test_invalid_characters (self):
		self.re (u'["\u0001"]', 1, 3, 2, "Unexpected U+0001.")
		self.re (u'["\u0002"]', 1, 3, 2, "Unexpected U+0002.")
		self.re (u'["\u001F"]', 1, 3, 2, "Unexpected U+001F.")
		
	def test_error_reporting_after_unicode_escape (self):
		self.re (u'["\\u0020\\v"]', 1, 9, 8, "Unknown escape code: \\v.")
		
class ReadArrayTests (ParserTestCase):
	def test_empty_array (self):
		self.r ('[]', [])
		
	def test_integer_array (self):
		self.r ('[1, 2, 3]', [1L, 2L, 3L])
		
	def test_string_array (self):
		self.r ('["a", "b", "c"]', ["a", "b", "c"])
		
	def test_nested_arrays (self):
		self.r ('[[], [1], [2, [3]]]', [[], [1L], [2L, [3L]]])
		
	def test_mixed_array (self):
		self.r ('[1, "b", ["c", "d"]]', [1L, "b", ["c", "d"]])
		
	def test_failure_missing_comma (self):
		self.re ('[1 2]', 1, 4, 3, "Expecting comma.")
		
	def test_error_unterminated_array (self):
		self.re ('[1, 2, 3, [', 1, 11, 10, "Unterminated array.")
		
	def test_error_unterminated_array_with_value (self):
		self.re ('[1', 1, 1, 0, "Unterminated array.")
		
	def test_error_unterminated_array_expecting_value (self):
		self.re ('[1,', 1, 1, 0, "Unterminated array.")
		
	def test_unexpected_array_start (self):
		self.re ('[1[',  1, 3, 2, "Unexpected U+005B.")
		
	def test_unexpected_array_end (self):
		self.re ('[1,]', 1, 4, 3, "Unexpected U+005D.")
		
	def test_unexpected_object_start (self):
		self.re ('[1{',  1, 3, 2, "Unexpected U+007B.")
		
	def test_unexpected_object_end (self):
		self.re ('[}',   1, 2, 1, "Unexpected U+007D.")
		self.re ('[1}',  1, 3, 2, "Unexpected U+007D.")
		self.re ('[1,}', 1, 4, 3, "Unexpected U+007D.")
		
	def test_unexpected_comma (self):
		self.re ('[,',   1, 2, 1, "Unexpected U+002C.")
		self.re ('[1,,', 1, 4, 3, "Unexpected U+002C.")
		
	def test_unexpected_colon (self):
		self.re ('[:',   1, 2, 1, "Unexpected U+003A.")
		self.re ('[1:',  1, 3, 2, "Unexpected U+003A.")
		self.re ('[1,:', 1, 4, 3, "Unexpected U+003A.")
		
class ReadObjectTests (ParserTestCase):
	def test_empty_object (self):
		self.r ('{}', {})
		
	def test_ignore_whitespace (self):
		self.r ('{ "a": true }', {"a": True})
		
	def test_integer_object (self):
		self.r ('{"a": 1, "b": 2}', {"a": 1L, "b": 2L})
		
	def test_string_object (self):
		self.r ('{"a": "first", "b": "second"}',
		        {"a": "first", "b": "second"})
		
	def test_nested_objects (self):
		self.r ('{"a": 1, "b": {"c": "2"}}',
		        {"a": 1L, "b": {"c": "2"}})
		
	def test_failure_no_colon (self):
		self.re ('{"a"}', 1, 5, 4,
		        "Expected colon after object property name.")
		
	def test_failure_invalid_key (self):
		self.re ('{1: 2}', 1, 2, 1, "Expecting property name.")
		self.re ('{"a": 1,}', 1, 9, 8, "Expecting property name.")
		self.re ('{,}', 1, 2, 1, "Expecting property name.")
		
	def test_failure_missing_comma (self):
		self.re ('{"a": 1 "b": 2}', 1, 9, 8, "Expecting comma.")
		
	def test_failure_trailing_newline (self):
		self.re ('{"a": "b",\n}\n', 2, 1, 11, "Expecting property name.")
		
	def test_unterminated (self):
		self.re ('{',       1, 1, 0, "Unterminated object.")
		self.re ('{"a"',    1, 1, 0, "Unterminated object.")
		self.re ('{"a":',   1, 1, 0, "Unterminated object.")
		self.re ('{"a":1',  1, 1, 0, "Unterminated object.")
		self.re ('{"a":1,', 1, 1, 0, "Unterminated object.")
		
	def test_unexpected_atom (self):
		self.re ('{"a"1', 1, 5, 4, "Unexpected U+0031.")
		
	def test_unexpected_array_start (self):
		self.re ('{[',       1, 2, 1, "Unexpected U+005B.")
		self.re ('{"a"[',    1, 5, 4, "Unexpected U+005B.")
		self.re ('{"a":1[',  1, 7, 6, "Unexpected U+005B.")
		self.re ('{"a":1,[', 1, 8, 7, "Unexpected U+005B.")
		
	def test_unexpected_array_end (self):
		self.re ('{]',       1, 2, 1, "Unexpected U+005D.")
		self.re ('{"a"]',    1, 5, 4, "Unexpected U+005D.")
		self.re ('{"a":]',   1, 6, 5, "Unexpected U+005D.")
		self.re ('{"a":1]',  1, 7, 6, "Unexpected U+005D.")
		self.re ('{"a":1,]', 1, 8, 7, "Unexpected U+005D.")
		
	def test_unexpected_object_start (self):
		self.re ('{{',       1, 2, 1, "Unexpected U+007B.")
		self.re ('{"a"{',    1, 5, 4, "Unexpected U+007B.")
		self.re ('{"a":1{',  1, 7, 6, "Unexpected U+007B.")
		self.re ('{"a":1,{', 1, 8, 7, "Unexpected U+007B.")
		
	def test_unexpected_object_end (self):
		self.re ('{"a":}', 1, 6, 5, "Unexpected U+007D.")
		
	def test_unexpected_comma (self):
		self.re ('{"a",}',    1, 5, 4, "Unexpected U+002C.")
		self.re ('{"a":,}',   1, 6, 5, "Unexpected U+002C.")
		self.re ('{"a":1,,}', 1, 8, 7, "Unexpected U+002C.")
		
	def test_unexpected_colon (self):
		self.re ('{:',        1, 2, 1, "Unexpected U+003A.")
		self.re ('{"a"::}',   1, 6, 5, "Unexpected U+003A.")
		self.re ('{"a":1:}',  1, 7, 6, "Unexpected U+003A.")
		self.re ('{"a":1,:}', 1, 8, 7, "Unexpected U+003A.")
		
class UnicodeEncodingDetectionTests (ParserTestCase):
	def de (self, encoding, bom = ''):
		def read_encoded (string, expected):
			self.r (bom + string.encode (encoding), expected)
			
		# Test various string lengths
		read_encoded (u'[]', [])
		read_encoded (u'[1]', [1L])
		read_encoded (u'[12]', [12L])
		read_encoded (u'[123]', [123L])
		read_encoded (u'[1234]', [1234L])
		read_encoded (u'[12345]', [12345L])
		
	if HAVE_UTF32:
		def test_utf32_be (self):
			# u'["testing"]'
			s = ('\x00\x00\x00['
			     '\x00\x00\x00"'
			     '\x00\x00\x00t'
			     '\x00\x00\x00e'
			     '\x00\x00\x00s'
			     '\x00\x00\x00t'
			     '\x00\x00\x00i'
			     '\x00\x00\x00n'
			     '\x00\x00\x00g'
			     '\x00\x00\x00"'
			     '\x00\x00\x00]')
			self.r (s, [u'testing'])
			
		def test_utf32_be_bom (self):
			# u'["testing"]'
			s = ('\x00\x00\xfe\xff'
			     '\x00\x00\x00['
			     '\x00\x00\x00"'
			     '\x00\x00\x00t'
			     '\x00\x00\x00e'
			     '\x00\x00\x00s'
			     '\x00\x00\x00t'
			     '\x00\x00\x00i'
			     '\x00\x00\x00n'
			     '\x00\x00\x00g'
			     '\x00\x00\x00"'
			     '\x00\x00\x00]')
			self.r (s, [u'testing'])
			
		def test_utf32_le (self):
			# u'["testing"]'
			s = ('[\x00\x00\x00'
			     '"\x00\x00\x00'
			     't\x00\x00\x00'
			     'e\x00\x00\x00'
			     's\x00\x00\x00'
			     't\x00\x00\x00'
			     'i\x00\x00\x00'
			     'n\x00\x00\x00'
			     'g\x00\x00\x00'
			     '"\x00\x00\x00'
			     ']\x00\x00\x00')
			self.r (s, [u'testing'])
			
		def test_utf32_le_bom (self):
			# u'["testing"]'
			s = ('\xff\xfe\x00\x00'
			     '[\x00\x00\x00'
			     '"\x00\x00\x00'
			     't\x00\x00\x00'
			     'e\x00\x00\x00'
			     's\x00\x00\x00'
			     't\x00\x00\x00'
			     'i\x00\x00\x00'
			     'n\x00\x00\x00'
			     'g\x00\x00\x00'
			     '"\x00\x00\x00'
			     ']\x00\x00\x00')
			self.r (s, [u'testing'])
			
		def test_utf32_be_astral (self):
			s = ('\x00\x00\x00['
			     '\x00\x00\x00"'
			     '\x00\x01\xd1\x1e'
			     '\x00\x00\x00"'
			     '\x00\x00\x00]')
			self.r (s, [u'\U0001d11e'])
			
		def test_utf32_le_astral (self):
			s = ('[\x00\x00\x00'
			     '"\x00\x00\x00'
			     '\x1e\xd1\x01\x00'
			     '"\x00\x00\x00'
			     ']\x00\x00\x00')
			self.r (s, [u'\U0001d11e'])
			
	def test_utf16_be (self):
		self.de ('utf-16-be')
		
	def test_utf16_be_bom (self):
		self.de ('utf-16-be', '\xfe\xff')
		
	def test_utf16_le (self):
		self.de ('utf-16-le')
		
	def test_utf16_le_bom (self):
		self.de ('utf-16-le', '\xff\xfe')
		
	def test_utf8 (self):
		self.de ('utf-8')
		
	def test_utf8_sig (self):
		self.r ('\xef\xbb\xbf["testing"]', [u'testing'])
		
# }}}

# Tests for the serializer {{{
class WriteMiscTests (SerializerTestCase):
	def test_fail_on_unknown (self):
		obj = object ()
		self.we ([obj], "No known serializer for object: %r" % obj)
		
	def test_fail_on_unwrapped_atom (self):
		self.we (1, "The outermost container must be an array or object.")
		
	def test_fail_on_non_whitespace_indent (self):
		self.we ([], "Only whitespace may be used for indentation.",
		         indent = 'bad', error_type = TypeError)
		
	def test_fail_on_other_whitespace_indent (self):
		# Whitespace that is not valid JSON whitespace
		self.we ([], "Only whitespace may be used for indentation.",
		         indent = u'\u000B', error_type = TypeError)
		
		self.we ([], "Only whitespace may be used for indentation.",
		         indent = u'\x00\u000B', error_type = TypeError)
		
	def test_on_unknown (self):
		obj = object ()
		self.w ([obj], u'["%r"]' % obj, on_unknown = repr)
		
	def test_on_unknown_invalid (self):
		obj = object ()
		self.we ([obj], "No known serializer for object: %r" % obj,
		         on_unknown = lambda v: v)
		
	def test_on_unknown_not_callable (self):
		obj = object ()
		self.we ([obj], "The on_unknown object must be callable.",
		         error_type = TypeError, on_unknown = obj)
		
	def test_int_subclass (self):
		class MyInt (int):
			pass
		self.w ([MyInt (10)], u'[10]')
		
class WriteKeywordTests (SerializerTestCase):
	def test_null (self):
		self.w ([None], u'[null]')
		
	def test_true (self):
		self.w ([True], u'[true]')
		
	def test_false (self):
		self.w ([False], u'[false]')
		
class WriteNumberTests (SerializerTestCase):
	def test_int (self):
		self.w ([1], u'[1]')
		
	def test_long (self):
		self.w ([1L], u'[1]')
		
	def test_decimal (self):
		self.w ([Decimal ('1.1')], u'[1.1]')
		
	def test_long_float (self):
		# Value that will give different string representations
		# depending on whether it is passed to unicode() or repr().
		pi = 3.1415926535897931
		self.assertNotEqual (str (pi), repr (pi))
		self.assertNotEqual (unicode (pi), repr (pi))
		self.w ([pi], u'[3.1415926535897931]')
		
	def test_long_decimal (self):
		pi = Decimal ('3.1415926535897931')
		self.w ([pi], u'[3.1415926535897931]')
		
	if repr (-0.0) != repr (0.0):
		def test_negative_zero (self):
			self.w ([-0.0], u'[-0.0]')
			
	def test_negative_zero_decimal (self):
		self.w ([Decimal ('-0.0')], u'[-0.0]')
		
	def test_complex (self):
		self.w ([5+0j], u'[5.0]')
		self.w ([5.5+0j], u'[5.5]')
		
	def test_long_complex (self):	
		pi = 3.1415926535897931
		self.assertNotEqual (str (pi), repr (pi))
		self.assertNotEqual (unicode (pi), repr (pi))
		self.w ([pi+0j], u'[3.1415926535897931]')
		
	def test_fail_complex (self):
		self.we ([5+1j], "Cannot serialize complex numbers"
		                 " with imaginary components.")
		
	def test_fail_on_infinity (self):
		self.we ([INFINITY], "Cannot serialize Infinity.")
		
	def test_fail_on_neg_infinity (self):
		self.we ([-INFINITY], "Cannot serialize -Infinity.")
		
	def test_fail_on_nan (self):
		self.we ([NAN], "Cannot serialize NaN.")
		
	def test_fail_on_decimal_infinity (self):
		self.we ([Decimal ('Infinity')], "Cannot serialize Infinity.")
		
	def test_fail_on_decimal_neg_infiity (self):
		self.we ([Decimal ('-Infinity')], "Cannot serialize -Infinity.")
		
	def test_fail_on_decimal_nan (self):
		self.we ([Decimal ('NaN')], "Cannot serialize NaN.")
		
class WriteArrayTests (SerializerTestCase):
	def test_empty_array (self):
		self.w ([], u'[]')
		
	def test_single_value_array (self):
		self.w ([True], u'[true]')
		
	def test_multiple_value_array (self):
		self.w ([True, True], u'[true,true]')
		
	def test_empty_indent (self):
		self.w ([True, True], u'[\ntrue,\ntrue\n]', indent = '')
		
	def test_single_indent (self):
		self.w ([True, True], u'[\n\ttrue,\n\ttrue\n]', indent = '\t')
		
	def test_nested_indent (self):
		self.w ([True, [True]], u'[\n\ttrue,\n\t[\n\t\ttrue\n\t]\n]',
		        indent = '\t')
		
	def test_generator (self):
		self.w ((_ for _ in (True, True)), u'[true,true]')
		
	def test_set (self):
		self.w (set (('a', 'b')), u'["a","b"]')
		
	def test_frozenset (self):
		self.w (frozenset (('a', 'b')), u'["a","b"]')
		
	def test_python_set (self):
		self.w (sets.Set (('a', 'b')), u'["a","b"]')
		
	def test_python_immutable_set (self):
		self.w (sets.ImmutableSet (('a', 'b')), u'["a","b"]')
		
	def test_array (self):
		self.w (array.array('i', [1,2,3]), u'[1,2,3]')
		
	def test_deque (self):
		self.w (collections.deque ((1, 2, 3)), u'[1,2,3]')
		
	def test_userlist (self):
		self.w (UserList.UserList ((1, 2, 3)), u'[1,2,3]')
		
	def test_fail_on_self_reference (self):
		a = []
		a.append (a)
		self.we (a, "Cannot serialize self-referential values.")
		
class WriteObjectTests (SerializerTestCase):
	def test_empty_object (self):
		self.w ({}, u'{}')
		
	def test_single_value_object (self):
		self.w ({'a': True}, u'{"a":true}')
		
	def test_multiple_value_object (self):
		self.w ({'a': True, 'b': True}, u'{"a":true,"b":true}')
		
	def test_sort_keys (self):
		self.w ({'e': True, 'm': True}, u'{"e":true,"m":true}',
		        sort_keys = True)
		
	def test_empty_indent (self):
		self.w ({'a': True, 'b': True}, u'{\n"a": true,\n"b": true\n}',
		        sort_keys = True, indent = '')
		
	def test_single_indent (self):
		self.w ({'a': True, 'b': True}, u'{\n\t"a": true,\n\t"b": true\n}',
		        sort_keys = True, indent = '\t')
		
	def test_nested_indent (self):
		self.w ({'a': True, 'b': {'c': True}},
		        u'{\n\t"a": true,\n\t"b": {\n\t\t"c": true\n\t}\n}',
		        sort_keys = True, indent = '\t')
		
	def test_fail_on_invalid_key (self):
		self.we ({1: True}, "Only strings may be used as object keys.")
		
	def test_coerce_invalid_key (self):
		self.w ({1: True}, u'{"1":true}', coerce_keys = True)
		self.w ({True: 1}, u'{"true":1}', coerce_keys = True)
		self.w ({(): 1}, u'{"()":1}', coerce_keys = True)
		
	if hasattr (collections, 'defaultdict'):
		def test_defaultdict (self):
			defdict = collections.defaultdict (lambda: 9)
			defdict['a'] = 42
			self.w (defdict, u'{"a":42}')
			
	def test_userdict (self):
		self.w (UserDict.UserDict (a = 42), u'{"a":42}')
		
	def test_fail_on_self_reference (self):
		a = {}
		a['a'] = a
		self.we (a, "Cannot serialize self-referential values.")
		
	def test_fail_on_self_reference_deep (self):
		a = {}
		a['a'] = [a]
		self.we (a, "Cannot serialize self-referential values.")
		
	def test_not_writing_comma_error (self):
		self.w ({'a': 1, 'b': 2, 'c': 3},
		        u'{"a":1,"c":3,"b":2}')
		
class WriteStringTests (SerializerTestCase):
	def test_empty_string (self):
		self.w ([''], u'[""]', ascii_only = True)
		self.w ([''], u'[""]', ascii_only = False)
		
	def test_escape_quote (self):
		self.w (['"'], u'["\\""]', ascii_only = True)
		self.w (['"'], u'["\\""]', ascii_only = False)
		
	def test_escape_reverse_solidus (self):
		self.w (['\\'], u'["\\\\"]', ascii_only = True)
		self.w (['\\'], u'["\\\\"]', ascii_only = False)
		
	def test_escape_solidus (self):
		self.w (['/'], u'["\\/"]', ascii_only = True)
		self.w (['/'], u'["\\/"]', ascii_only = False)
		
	def test_escape_backspace (self):
		self.w (['\b'], u'["\\b"]', ascii_only = True)
		self.w (['\b'], u'["\\b"]', ascii_only = False)
		
	def test_escape_form_feed (self):
		self.w (['\f'], u'["\\f"]', ascii_only = True)
		self.w (['\f'], u'["\\f"]', ascii_only = False)
		
	def test_escape_line_feed (self):
		self.w (['\n'], u'["\\n"]', ascii_only = True)
		self.w (['\n'], u'["\\n"]', ascii_only = False)
		
	def test_escape_carriage_return (self):
		self.w (['\r'], u'["\\r"]', ascii_only = True)
		self.w (['\r'], u'["\\r"]', ascii_only = False)
		
	def test_escape_tab (self):
		self.w (['\t'], u'["\\t"]', ascii_only = True)
		self.w (['\t'], u'["\\t"]', ascii_only = False)
		
	def test_escape_control_characters (self):
		special_escapes = tuple ('\b\t\n\f\r')
		
		for code in range (0x0, 0x1F + 1):
			char = unichr (code)
			if char not in special_escapes:
				expected = u'["\\u%04x"]' % code
				self.w ([char], expected, ascii_only = True)
				self.w ([char], expected, ascii_only = False)
				
	def test_noescape_above_control (self):
		self.w ([u'\u0020\u001f'], u'[" \\u001f"]', ascii_only = True)
		self.w ([u'\u0020\u001f'], u'[" \\u001f"]', ascii_only = False)
		
	def test_unicode_passthrough (self):
		self.w ([u'\u00B6\u00D7'], u'["\u00b6\u00d7"]', ascii_only = False)
		self.w ([u'\u24CA'], u'["\u24ca"]', ascii_only = False)
		self.w ([u'\U0001D11E'], u'["\U0001D11E"]', ascii_only = False)
		
	def test_fail_incomplete_surrogate (self):
		self.we ([u'\uD834'], "Cannot serialize incomplete"
		                      " surrogate pair.")
		
	def test_fail_reserved_codepoint (self):
		self.we ([u'\uDD1E'], "Cannot serialize reserved code point U+DD1E.")
		
	def test_fail_invalid_surrogate (self):
		self.we ([u'\uD834\u0000'], "Cannot serialize invalid"
		                            " surrogate pair.")
		
	def test_escape_short_unicode (self):
		# Some Latin-1
		self.w ([u'\u00B6\u00D7'], u'["\\u00b6\\u00d7"]')
		
		# Higher planes
		self.w ([u'\u24CA'], u'["\\u24ca"]')
		
	def test_escape_long_unicode (self):
		# Should break into two UTF-16 codepoints
		self.w ([u'\U0001D11E'], u'["\\ud834\\udd1e"]')
		
	def test_userstring (self):
		self.w ([UserString.UserString ('test')], u'["test"]')
		
	def test_fail_nonascii_bytestring (self):
		self.we (['Fail\xa2'],
		         u"'ascii' codec can't decode byte 0xa2 in position 4:"
		         u" ordinal not in range(128)",
		         error_type = UnicodeDecodeError)
		
class WriteEncodingTests (SerializerTestCase):
	# Don't use self.w in these, because it sets the encoding to
	# None.
	def test_encode_utf8_default (self):
		value = write ([u'\U0001D11E \u24CA'], ascii_only = False)
		self.assertEqual (type (value), str)
		self.assertEqual (value, '["\xf0\x9d\x84\x9e \xe2\x93\x8a"]')
		
	def test_encode_utf16 (self):
		value = write ([u'\U0001D11E \u24CA'], ascii_only = False,
		               encoding = 'utf-16-le')
		self.assertEqual (type (value), str)
		self.assertEqual (value, '\x5b\x00\x22\x00\x34\xd8\x1e\xdd'
		                         '\x20\x00\xca\x24\x22\x00\x5d\x00')
		
	def test_encode_unicode_none (self):	
		value = write ([u'\U0001D11E \u24CA'], ascii_only = False,
		               encoding = None)
		self.assertEqual (type (value), unicode)
		self.assertEqual (value, u'["\U0001D11E \u24CA"]')
		
# }}}

if __name__ == '__main__':
	unittest.main (defaultTest = 'suite')
	
