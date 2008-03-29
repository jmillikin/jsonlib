import unittest

from jsonlib import read, write, errors

class TestCase (unittest.TestCase):
	def r (self, string, expected):
		value = read (string)
		self.assertEqual (value, expected)
		self.assertEqual (type (value), type (expected))
		
	def w (self, value, expected, **kwargs):
		serialized = write (value, encoding = None, **kwargs)
		self.assertEqual (serialized, expected)
		self.assertEqual (type (serialized), type (expected))
		
	def re (self, string, line, column, position, expected_error_message):
		full_expected = ("JSON parsing error at line %d, column %d"
		                 " (position %d): %s" % (line, column,
		                                         position,
		                                         expected_error_message))
		try:
			read (string)
			self.fail ("No exception raised.")
		except errors.ReadError, error:
			self.assertEqual (unicode (error), full_expected)
			
	def we (self, value, expected_error_message, error_type = None, **kwargs):
		if error_type is None:
			error_type = errors.WriteError
		try:
			write (value, **kwargs)
			self.fail ("No exception raised.")
		except error_type, error:
			self.assertEqual (unicode (error), expected_error_message)
			
