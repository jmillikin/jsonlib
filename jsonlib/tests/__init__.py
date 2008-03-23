import unittest
from jsonlib.tests import read_tests, write_tests

def suite ():
	from_module = unittest.TestLoader ().loadTestsFromModule
	all_tests = unittest.TestSuite ()
	all_tests.addTests (from_module (read_tests))
	all_tests.addTests (from_module (write_tests))
	return all_tests
	
