# Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
# Author: John Millikin <jmillikin@gmail.com>

import codecs
from decimal import Decimal
from jsonlib import read, errors
from jsonlib.tests.common import TestCase

class MiscTests (TestCase):
	def test_fail_on_empty (self):
		self.re ('', 1, 1, 0, "No expression found.")
		self.re (' ', 1, 1, 0, "No expression found.")
		
	def test_fail_on_invalid_whitespace (self):
		self.re (u'[\u000B]', 1, 2, 1, "Unexpected U+000B.")
		self.re (u'[\u000D]', 1, 2, 1, "Unexpected U+000D.")
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
		
	def test_extra_data (self):
		self.re ('[][]', 1, 3, 2, "Extra data after JSON expression.")
		
class ReadKeywordTests (TestCase):
	def test_null (self):
		self.r ('[null]', [None])
		
	def test_true (self):
		self.r ('[true]', [True])
		
	def test_false (self):
		self.r ('[false]', [False])
		
	def test_invalid_keyword (self):
		self.re ('n', 1, 1, 0, "Unexpected U+006E.")
		self.re ('t', 1, 1, 0, "Unexpected U+0074.")
		self.re ('f', 1, 1, 0, "Unexpected U+0066.")
		
class ReadNumberTests (TestCase):
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
		self.re ('-.', 1, 1, 0, "Invalid number.")
		self.re ('0.', 1, 1, 0, "Invalid number.")
		
	def test_no_plus_sign (self):
		self.re ('+1', 1, 1, 0, "Unexpected U+002B.")
		
	def test_non_ascii_number (self):
		self.re (u'[\u0661]', 1, 2, 1, "Unexpected U+0661.")
		
class ReadStringTests (TestCase):
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
		
	def test_invalid_escape (self):
		self.re (u'["\\a"]', 1, 3, 2, "Unknown escape code.")
		
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
		
class ReadArrayTests (TestCase):
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
		
class ReadObjectTests (TestCase):
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
		
	def test_failure_unterminated (self):
		self.re ('[[], {"a": 1', 1, 6, 5, "Unterminated object.")
		
	def test_failure_no_colon (self):
		self.re ('{"a"}', 1, 5, 4,
		        "Expected colon after object property name.")
		
	def test_failure_invalid_key (self):
		self.re ('{1: 2}', 1, 2, 1, "Expecting property name.")
		self.re ('{"a": 1,}', 1, 9, 8, "Expecting property name.")
		self.re ('{,}', 1, 2, 1, "Expecting property name.")
		
	def test_failure_missing_comma (self):
		self.re ('{"a": 1 "b": 2}', 1, 9, 8, "Expecting comma.")
		
class UnicodeEncodingDetectionTests (TestCase):
	def de (self, encoding, bom = ''):
		def read_encoded (string, expected):
			self.r (bom + string.encode (encoding), expected)
			
		# Test various string lengths
		read_encoded (u'[1]', [1L])
		read_encoded (u'[12]', [12L])
		read_encoded (u'[123]', [123L])
		read_encoded (u'[1234]', [1234L])
		read_encoded (u'[12345]', [12345L])
		
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
		
