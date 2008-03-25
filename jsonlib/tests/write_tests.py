# Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
# Author: John Millikin <jmillikin@gmail.com>

from decimal import Decimal
import array
import collections
import UserList
import UserDict
import UserString
import sets
from jsonlib import write, errors, util
from jsonlib.tests.common import TestCase

class MiscTests (TestCase):
	def test_fail_on_unknown (self):
		obj = object ()
		self.we ([obj], "No known serializer for object: %r" % obj)
		
	def test_fail_on_unwrapped_atom (self):
		self.we (1, "The outermost container must be an array or object.")
		
class WriteKeywordTests (TestCase):
	def test_null (self):
		self.w ([None], u'[null]')
		
	def test_true (self):
		self.w ([True], u'[true]')
		
	def test_false (self):
		self.w ([False], u'[false]')
		
class WriteNumberTests (TestCase):
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
		self.we ([util.INFINITY], "Cannot serialize Infinity.")
		
	def test_fail_on_neg_infinity (self):
		self.we ([-util.INFINITY], "Cannot serialize -Infinity.")
		
	def test_fail_on_nan (self):
		self.we ([util.NAN], "Cannot serialize NaN.")
		
	def test_fail_on_decimal_infinity (self):
		self.we ([Decimal ('Infinity')], "Cannot serialize Infinity.")
		
	def test_fail_on_decimal_neg_infiity (self):
		self.we ([Decimal ('-Infinity')], "Cannot serialize -Infinity.")
		
	def test_fail_on_decimal_nan (self):
		self.we ([Decimal ('NaN')], "Cannot serialize NaN.")
		
class WriteArrayTests (TestCase):
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
		
	def test_set_sorted (self):
		self.w (set (('e', 'm')), u'["e","m"]', sort_keys = True)
		
	def test_frozenset (self):
		self.w (frozenset (('a', 'b')), u'["a","b"]')
		
	def test_frozenset_sorted (self):
		self.w (frozenset (('e', 'm')), u'["e","m"]',
		        sort_keys = True)
		
	def test_python_set (self):
		self.w (sets.Set (('a', 'b')), u'["a","b"]')
		
	def test_python_set_sorted (self):
		self.w (sets.Set (('e', 'm')), u'["e","m"]', sort_keys = True)
		
	def test_python_immutable_set (self):
		self.w (sets.ImmutableSet (('a', 'b')), u'["a","b"]')
		
	def test_python_immutable_set_sorted (self):
		self.w (sets.ImmutableSet (('e', 'm')), u'["e","m"]', sort_keys = True)
		
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
		
class WriteObjectTests (TestCase):
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
		
class WriteStringTests (TestCase):
	def test_empty_string (self):
		self.w ([''], u'[""]')
		
	def test_escape_quote (self):
		self.w (['"'], u'["\\""]')
		
	def test_escape_reverse_solidus (self):
		self.w (['\\'], u'["\\\\"]')
		
	def test_escape_solidus (self):
		self.w (['/'], u'["\\/"]')
		
	def test_escape_backspace (self):
		self.w (['\b'], u'["\\b"]')
		
	def test_escape_form_feed (self):
		self.w (['\f'], u'["\\f"]')
		
	def test_escape_line_feed (self):
		self.w (['\n'], u'["\\n"]')
		
	def test_escape_carriage_return (self):
		self.w (['\r'], u'["\\r"]')
		
	def test_escape_tab (self):
		self.w (['\t'], u'["\\t"]')
		
	def test_escape_control_characters (self):
		special_escapes = tuple ('\b\t\n\f\r')
		
		for code in range (0x0, 0x1F + 1):
			char = unichr (code)
			if char not in special_escapes:
				expected = u'["\\u%04x"]' % code
				self.w ([char], expected)
				
	def test_unicode_passthrough (self):
		self.w ([u'\u00B6\u00D7'], u'["\u00b6\u00d7"]', ascii_only = False)
		self.w ([u'\u24CA'], u'["\u24ca"]', ascii_only = False)
		self.w ([u'\U0001D11E'], u'["\U0001D11E"]', ascii_only = False)
		
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
		
class EncodingTests (TestCase):
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
		
class WriteSubclassTests (TestCase):
	def test_int_subclass (self):
		class MyInt (int):
			pass
		self.w ([MyInt (10)], u'[10]')
		
