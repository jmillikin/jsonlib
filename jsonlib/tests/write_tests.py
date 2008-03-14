# Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
# Author: John Millikin <jmillikin@gmail.com>

from decimal import Decimal
import unittest
from .. import write, errors

class TestCase (unittest.TestCase):
	def w (self, value, expected):
		serialized = write (value)
		self.assertEqual (serialized, expected)
		self.assertEqual (type (serialized), type (expected))
		
class WriteBasicTests (TestCase):
	def test_null (self):
		self.w (None, u'null')
		
	def test_true (self):
		self.w (True, u'true')
		
	def test_false (self):
		self.w (False, u'false')
		
	def test_int (self):
		self.w (1, u'1')
		
	def test_long (self):
		self.w (1L, u'1')
		
	def test_decimal (self):
		self.w (Decimal ('1.1'), u'1.1')
		
	def test_fail_on_unknown (self):
		self.assertRaises (errors.UnknownSerializerError, write,
		                   object ())
		
class WriteArrayTests (TestCase):
	def test_empty_array (self):
		self.w ([], u'[]')
		
	def test_single_value_array (self):
		self.w ([True], u'[true]')
		
	def test_multiple_value_array (self):
		self.w ([True, True], u'[true, true]')
		
	def test_empty_indent (self):
		self.assertEqual (write ([True, True], indent = ''),
		                  u'[\ntrue,\ntrue\n]')
		
	def test_single_indent (self):
		self.assertEqual (write ([True, True], indent = '\t'),
		                  u'[\n\ttrue,\n\ttrue\n]')
		
	def test_nested_indent (self):
		self.assertEqual (write ([True, [True]], indent = '\t'),
		                  u'[\n\ttrue,\n\t[\n\t\ttrue\n\t]\n]')
		
	def test_fail_on_self_reference (self):
		a = []
		a.append (a)
		
		self.assertRaises (errors.WriteError, write, a)
		
class WriteObjectTests (TestCase):
	def test_empty_object (self):
		self.w ({}, u'{}')
		
	def test_single_value_object (self):
		self.w ({'a': True}, u'{"a": true}')
		
	def test_multiple_value_object (self):
		self.w ({'a': True, 'b': True}, u'{"a": true, "b": true}')
		
	def test_sort_keys (self):
		self.assertEqual (write ({'e': True, 'm': True},
		                         sort_keys = True),
		                  u'{"e": true, "m": true}')
		
	def test_empty_indent (self):
		self.assertEqual (write ({'a': True, 'b': True},
		                         sort_keys = True, indent = ''),
		                  u'{\n"a": true,\n"b": true\n}')
		
	def test_single_indent (self):
		self.assertEqual (write ({'a': True, 'b': True},
		                         sort_keys = True, indent = '\t'),
		                  u'{\n\t"a": true,\n\t"b": true\n}')
		
	def test_nested_indent (self):
		self.assertEqual (write ({'a': True, 'b': {'c': True}},
		                         sort_keys = True, indent = '\t'),
		                  u'{\n\t"a": true,\n\t"b": {\n\t\t"c": true\n\t}\n}')
		
	def test_fail_on_invalid_key (self):
		self.assertRaises (errors.WriteError, write, {1: True})
		
	def test_fail_on_self_reference (self):
		a = {}
		a['a'] = a
		
		self.assertRaises (errors.WriteError, write, a)
		
class WriteStringTests (TestCase):
	def test_empty_string (self):
		self.w ('', u'""')
		
	def test_escape_quote (self):
		self.w ('"', ur'"\""')
		
	def test_escape_reverse_solidus (self):
		self.w ('\\', ur'"\\"')
		
	def test_no_escape_solidus (self):
		self.w ('/', u'"/"')
		
	def test_escape_backspace (self):
		self.w ('\b', ur'"\b"')
		
	def test_escape_form_feed (self):
		self.w ('\f', ur'"\f"')
		
	def test_escape_line_feed (self):
		self.w ('\n', ur'"\n"')
		
	def test_escape_carriage_return (self):
		self.w ('\r', ur'"\r"')
		
	def test_escape_tab (self):
		self.w ('\t', ur'"\t"')
		
	def test_escape_control_characters (self):
		special_escapes = tuple ('\b\t\n\f\r')
		
		for code in range (0x0, 0x1F + 1):
			char = unichr (code)
			if char not in special_escapes:
				expected = u'"\\u%04x"' % code
				self.w (char, expected)
				
	def test_escape_short_unicode (self):
		# Some Latin-1
		self.w (u'\u00B6\u00D7', u'"\\u00b6\\u00d7"')
		
		# Higher planes
		self.w (u'\u24CA', u'"\\u24ca"')
		
	def test_escape_long_unicode (self):
		# Should break into two UTF-16 codepoints
		self.w (u'\U0001D11E', u'"\\ud834\\udd1e"')
		
class WriteSubclassTests (TestCase):
	def test_int_subclass (self):
		class MyInt (int):
			pass
		self.w (MyInt (10), u'10')
		
