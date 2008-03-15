# Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
# Author: John Millikin <jmillikin@gmail.com>

from functools import wraps

KEYWORDS = (('null', None), ('true', True), ('false', False))
try:
	INFINITY = float ('inf')
except ValueError:
	INFINITY = 1e300000
try:
	NAN = float ('nan')
except ValueError:
	NAN = INFINITY/INFINITY
	
def memoized (func):
	"""Store results of a function call in cache for speedy retrieval."""
	cache = {}
	@wraps (func)
	def new_func (*args):
		try:
			in_cache = (args in cache)
		except TypeError:
			return func (*args)
			
		if not in_cache:
			cache[args] = func (*args)
		return cache[args]
	return new_func
	
def chunk (iterable, chunk_size):
	"""Retrieve an iterable in chunks.
	
	If there are extra values left over after the iterable is
	exhausted, they are lost.
	
	"""
	_chunk = []
	for value in iterable:
		_chunk.append (value)
		if len (_chunk) == chunk_size:
			yield _chunk
			_chunk = []
			
