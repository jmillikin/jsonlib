# Copyright (C) 2008 John Millikin. See COPYING for details.
# Author: John Millikin <jmillikin@gmail.com>

import unittest
from jsonlib import read_tests, write_tests

def main ():
	from_module = unittest.TestLoader ().loadTestsFromModule
	all_tests = unittest.TestSuite ()
	all_tests.addTests (from_module (read_tests))
	all_tests.addTests (from_module (write_tests))
	unittest.TextTestRunner ().run (all_tests)
	

if __name__ == '__main__':
	main ()
	
