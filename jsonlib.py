# Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
# Author: John Millikin <jmillikin@gmail.com>

import codecs
import struct
import sys

from _jsonlib import _read, write, ReadError, WriteError, UnknownSerializerError

__all__ = ('read', 'write', 'ReadError', 'WriteError',
           'UnknownSerializerError')

__version__ = (1, 3, 3)

def read (string):
	"""Parse a JSON expression into a Python value.
	
	If string is a byte string, it will be converted to Unicode
	before parsing (see unicode_autodetect_encoding).
	
	"""
	return _read (string)
	
