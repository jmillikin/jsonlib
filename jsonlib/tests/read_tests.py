# Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
# Author: John Millikin <jmillikin@gmail.com>

import codecs
from decimal import Decimal
import unittest
from .. import read, errors

class TestCase (unittest.TestCase):
	def r (self, string, expected):
		value = read (string, __speedboost = False)
		self.assertEqual (value, expected)
		self.assertEqual (type (value), type (expected))
		
		value = read (string, __speedboost = True)
		self.assertEqual (value, expected)
		self.assertEqual (type (value), type (expected))
		
class MiscTests (TestCase):
	def test_fail_on_empty (self):
		self.assertRaises (errors.ReadError, read, '')
		self.assertRaises (errors.ReadError, read, ' ')
		
class ReadKeywordTests (TestCase):
	def test_null (self):
		self.r ('null', None)
		
	def test_true (self):
		self.r ('true', True)
		
	def test_false (self):
		self.r ('false', False)
		
	def test_invalid_keyword (self):
		self.assertRaises (errors.ReadError, read, 'n')
		self.assertRaises (errors.ReadError, read, 't')
		self.assertRaises (errors.ReadError, read, 'f')
		
class ReadNumberTests (TestCase):
	def test_zero (self):
		self.r ('0', 0L)
		
	def test_negative_zero (self):
		self.r ('-0', 0L)
		
	def test_two_zeroes_error (self):
		self.assertRaises (errors.LeadingZeroError, read, '00')
		
	def test_negative_two_zeroes_error (self):
		self.assertRaises (errors.LeadingZeroError, read, '-00')
		
	def test_int (self):
		for ii in range (10):
			self.r ('%d' % ii, long (ii))
			self.r ('-%d' % ii, long (-ii))
			
	def test_decimal (self):
		self.r ('1.2345', Decimal ('1.2345'))
		
	def test_negative_decimal (self):
		self.r ('-1.2345', Decimal ('-1.2345'))
		
	def test_zero_after_decimal (self):
		self.r ('0.01', Decimal ('0.01'))
		
	def test_exponent (self):
		self.r ('1e2', Decimal ('100.0'))
		self.r ('10e2', Decimal ('1000.0'))
		
	def test_exponent_plus (self):
		self.r ('1e+2', Decimal ('100.0'))
		self.r ('10e+2', Decimal ('1000.0'))
		
	def test_negative_exponent (self):
		self.r ('1e-2', Decimal ('0.01'))
		self.r ('10e-2', Decimal ('0.1'))
		
	def test_decimal_exponent (self):
		self.r ('10.5e2', Decimal ('1050.0'))
		
	def test_negative_decimal_exponent (self):
		self.r ('10.5e-2', Decimal ('0.105'))
		
	def test_invalid_number (self):
		self.assertRaises (errors.ReadError, read, '-.')
		self.assertRaises (errors.ReadError, read, '+1')
		
	def test_non_ascii_number (self):
		self.assertRaises (errors.ReadError, read, u'\u0661')
		
class ReadStringTests (TestCase):
	def test_empty_string (self):
		self.r ('""', u'')
		
	def test_basic_string (self):
		self.r ('"test"', u'test')
		
	def test_unescape_quote (self):
		self.r (r'"\""', u'"')
		
	def test_unescape_reverse_solidus (self):
		self.r (r'"\\"', u'\\')
		
	def test_unescape_solidus (self):
		self.r (r'"\/"', u'/')
		
	def test_unescape_backspace (self):
		self.r (r'"\b"', u'\b')
		
	def test_unescape_form_feed (self):
		self.r (r'"\f"', u'\f')
		
	def test_unescape_line_feed (self):
		self.r (r'"\n"', u'\n')
		
	def test_unescape_carriage_return (self):
		self.r (r'"\r"', u'\r')
		
	def test_unescape_tab (self):
		self.r (r'"\t"', u'\t')
		
	def test_string_with_whitespace (self):
		self.r ('" \\" "', u" \" ")
		
	def test_unescape_single_unicode (self):
		self.r (r'"\u005C"', u'\\')
		self.r (r'"\u005c"', u'\\')
		
	def test_unescape_double_unicode (self):
		self.r (r'"\uD834\uDD1E"', u'\U0001d11e')
		self.r (r'"\ud834\udd1e"', u'\U0001d11e')
		
	def test_unescape_unicode_followed_by_normal (self):
		self.r (r'"\u00e9a"', u'\u00e9a')
		
	def test_end_of_stream (self):
		self.assertRaises (errors.ReadError, read, r'"\uD834\u"')
		
	def test_missing_surrogate (self):
		self.assertRaises (errors.MissingSurrogateError, read, r'"\uD834"')
		self.assertRaises (errors.MissingSurrogateError, read, r'"\uD834\u"')
		self.assertRaises (errors.MissingSurrogateError, read, r'"\uD834testing"')
		
	def test_direct_unicode (self):
		self.r (u'"\U0001d11e"', u'\U0001d11e')
		
	def test_bmp_unicode (self):
		self.r (u'"\u24CA"'.encode ('utf-8'), u'\u24CA')
		
	def test_astral_unicode (self):
		self.r (u'"\U0001d11e"'.encode ('utf-8'), u'\U0001d11e')
		
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
		self.assertRaises (errors.ReadError, read, '[1 2]')
		
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
		
	def test_failure_no_colon (self):
		self.assertRaises (errors.ReadError, read, '{"a"}')
		
	def test_failure_invalid_key (self):
		self.assertRaises (errors.BadObjectKeyError, read,
		                   '{1: 2}')
		
	def test_failure_missing_comma (self):
		self.assertRaises (errors.ReadError, read, '{"a": 1 "b": 2}')
		
class UnicodeEncodingDetectionTests (TestCase):
	def de (self, encoding):
		def read_encoded (string, expected):
			self.r (string.encode (encoding), expected)
			
		# Test various string lengths
		read_encoded (u'1', 1L)
		read_encoded (u'12', 12L)
		read_encoded (u'123', 123L)
		read_encoded (u'1234', 1234L)
		read_encoded (u'12345', 12345L)
		
	def test_utf32_be (self):
		# u'"testing"'
		s = '\x00\x00\x00"\x00\x00\x00t\x00\x00\x00e\x00\x00\x00s\x00\x00\x00t\x00\x00\x00i\x00\x00\x00n\x00\x00\x00g\x00\x00\x00"'
		self.r (s, u'testing')
		
	def test_utf32_le (self):
		# u'"testing"'
		s = '"\x00\x00\x00t\x00\x00\x00e\x00\x00\x00s\x00\x00\x00t\x00\x00\x00i\x00\x00\x00n\x00\x00\x00g\x00\x00\x00"\x00\x00\x00'
		self.r (s, u'testing')
		
	def test_utf32_be_astral (self):
		s = '\x00\x00\x00"\x00\x01\xd1\x1e\x00\x00\x00"'
		self.r (s, u'\U0001d11e')
		
	def test_utf32_le_astral (self):
		s = '"\x00\x00\x00\x1e\xd1\x01\x00"\x00\x00\x00'
		self.r (s, u'\U0001d11e')
		
	def test_utf16_be (self):
		self.de ('utf-16-be')
		
	def test_utf16_le (self):
		self.de ('utf-16-le')
		
	def test_utf8 (self):
		self.de ('utf-8')
		
