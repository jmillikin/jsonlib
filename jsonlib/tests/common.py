import unittest

from jsonlib import read, write, errors, util

class TestCase (unittest.TestCase):
	def r (self, string, expected):
		value = read (string, __speedboost = False)
		self.assertEqual (value, expected)
		self.assertEqual (type (value), type (expected))
		
		value = read (string, __speedboost = True)
		self.assertEqual (value, expected)
		self.assertEqual (type (value), type (expected))
		
	def w (self, value, expected, **kwargs):
		serialized = write (value, encoding = None, __speedboost = False, **kwargs)
		self.assertEqual (serialized, expected)
		self.assertEqual (type (serialized), type (expected))
		
		serialized = write (value, encoding = None, __speedboost = True, **kwargs)
		self.assertEqual (serialized, expected)
		self.assertEqual (type (serialized), type (expected))
		
	def re (self, string, line, column, position, expected_error_message):
		full_expected = ("JSON parsing error at line %d, column %d"
		                 " (position %d): %s" % (line, column,
		                                         position,
		                                         expected_error_message))
		try:
			read (string, __speedboost = False)
			self.fail ("No exception raised in C implementation.")
		except errors.ReadError, error:
			self.assertEqual (unicode (error), full_expected)
		try:
			read (string, __speedboost = True)
			self.fail ("No exception raised in Python implementation.")
		except errors.ReadError, error:
			self.assertEqual (unicode (error), full_expected)
			
	def we (self, value, expected_error_message, **kwargs):
		try:
			write (value, __speedboost = False, **kwargs)
			self.fail ("No exception raised.")
		except errors.WriteError, error:
			self.assertEqual (unicode (error),
			                  expected_error_message)
		try:
			write (value, __speedboost = True, **kwargs)
			self.fail ("No exception raised.")
		except errors.WriteError, error:
			self.assertEqual (unicode (error),
			                  expected_error_message)
			
