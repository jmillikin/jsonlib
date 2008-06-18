:Author: John Millikin
:Copyright: This document has been placed in the public domain.

Overview
========

`JSON <http://json.org/>`_ is a lightweight data-interchange format. It
is often used for exchanging data between a web server and user agent.

This module aims to produce a library for serializing and deserializing
JSON that conforms strictly to RFC 4627.

.. contents::

Usage
=====

jsonlib has two functions of interest, ``read`` and ``write``. It also
defines some exception: ``ReadError``, ``WriteError``, and
``UnknownSerializerError``.

Deserialization
---------------

To deserialize a JSON expression, call the ``jsonlib.read`` function with
an instance of ``str`` or ``unicode``. ::

	>>> jsonlib.read ('["Hello world!"]')
	[u'Hello world!']

Serialization
-------------

Serialization has more options, but they are set to reasonable defaults.
The simplest use is to call ``jsonlib.write`` with a Python value. ::

	>>> jsonlib.write (['Hello world!'])
	'["Hello world!"]'

Pretty-Printing
~~~~~~~~~~~~~~~

To "pretty-print" the output, pass a value for the ``indent`` parameter. ::

	>>> print jsonlib.write (['Hello world!'], indent = '\t')
	[
		"Hello world!"
	]
	>>> 
	
Mapping Key Sorting
~~~~~~~~~~~~~~~~~~~

By default, mapping keys are serialized in whatever order they are
stored by Python. To force a consistent ordering (for example, in doctests)
use the ``sort_keys`` parameter. ::

	>>> jsonlib.write ({'e': 'Hello', 'm': 'World!'})
	'{"m":"World!","e":"Hello"}'
	>>> jsonlib.write ({'e': 'Hello', 'm': 'World!'}, sort_keys = True)
	'{"e":"Hello","m":"World!"}'

Encoding and Unicode
~~~~~~~~~~~~~~~~~~~~

By default, the output is encoded in UTF-8. If you require a different
encoding, pass the name of a Python codec as the ``encoding`` parameter. ::

	>>> jsonlib.write (['Hello world!'], encoding = 'utf-16-be')
	'\x00[\x00"\x00H\x00e\x00l\x00l\x00o\x00 \x00w\x00o\x00r\x00l\x00d\x00!\x00"\x00]'

To retrieve an unencoded ``unicode`` instance, pass ``None`` for the
encoding. ::

	>>> jsonlib.write (['Hello world!'], encoding = None)
	u'["Hello world!"]'

By default, non-ASCII codepoints are forbidden in the output. To include
higher codepoints in the output, set ``ascii_only`` to ``False``. ::

	>>> jsonlib.write ([u'Hello \u266A'], encoding = None)
	u'["Hello \\u266A"]'
	>>> jsonlib.write ([u'Hello \u266A'], encoding = None, ascii_only = False)
	u'["Hello \u266A"]'

Mapping Key Coercion
~~~~~~~~~~~~~~~~~~~~

Because JSON objects must have string keys, an exception will be raised when
non-string keys are encountered in a mapping. It can be useful to coerce
mapping keys to strings, so the ``coerce_keys`` parameter is available. ::

	>>> jsonlib.write ({True: 1})
	Traceback (most recent call last):
	jsonlib.errors.WriteError: Only strings may be used as object keys.
	>>> jsonlib.write ({True: 1}, coerce_keys = True)
	'{"true":1}'

Serializing Other Types
~~~~~~~~~~~~~~~~~~~~~~~

If the object implements the iterator or mapping protocol, it will be
handled automatically. If the object is intended for use as a basic value,
it should subclass one of the supported basic values.

String-like objects that do not inherit from ``str``, ``unicode``, or
``UserString.UserString`` will likely be serialized as a list. This will
not be changed. If iterating them returns an instance of the same type, the
serializer might crash. This (hopefully) will be changed.

To serialize a type not known to jsonlib, use the ``on_unknown`` parameter
to ``write``::

	>>> from datetime import date
	>>> def unknown_handler (value):
	...     if isinstance (value, date): return str (value)
	...     raise jsonlib.UnknownSerializerError
	>>> jsonlib.write ([date (2000, 1, 1)], on_unknown = unknown_handler)
	'["2000-01-01"]'

Exceptions
-----------

ReadError
~~~~~~~~~

Raised by ``read`` if an error was encountered parsing the expression. Will
contain the line, column, and character position of the error.

Note that this will report the *character*, not the *byte*, of the character
that caused the error.

WriteError
~~~~~~~~~~

Raised by ``write`` if an error was encountered serializing the passed
value.

UnknownSerializerError
~~~~~~~~~~~~~~~~~~~~~~

A subclass of ``WriteError`` that is raised when a value cannot be
serialized. See the ``on_unknown`` parameter to ``write``.

Other JSON Libraries
====================

`demjson <http://pypi.python.org/pypi/demjson>`_ is a powerful and compliant
library, which supports encoding autodetection, UTF-32, and surrogate pair
handling. This is a very good library to use when extension modules cannot
be installed. I advise always using "strict mode".

`simplejson <http://pypi.python.org/pypi/simplejson>`_ is likely the most
popular JSON library for Python, used by many web frameworks such as Django.
Recent versions have improved in their support for Unicode, although it
(as of 2008-03-28) still does not support encoding autodetection. I like
demjson better.

`python-cjson <http://pypi.python.org/pypi/python-cjson>`_ is designed for
speed, but uses bytestrings internally and has poor support for Unicode. I
advise against its use, unless you will only use ASCII text and need the
performance.

`python-json <http://pypi.python.org/pypi/python-json>`_ is one of the first
JSON libraries for Python. It is no longer maintained and has numerous
issues, especially regarding Unicode. I advise against using this library
for any reason.

Change Log
==========

1.3.3
-----
* Support the ``on_unknown`` parameter to ``write``.
* Corrected typo in invalid whitespace detection.
* Added ``__version__`` attribute.
* Merged all code into ``jsonlib`` and ``_jsonlib`` modules, instead of
  a package.

1.3.2
-----
* Improved the README.
* Support for reading text encoded with the ``utf-8-sig`` codec.
* Use ``codecs`` module for detecting BOMs in input data.
* Forbid non-whitespace strings from being used for indentation.

1.3.1
-----
* Removed the Python implementations of the serializer and deserializer.
* Detect and raise an exception if invalid surrogate pairs are serialized
  or deserialized.
* Detect and raise an exception if reserved codepoints are serialized or
  deserialized.
* Added support for operating in a process with multiple Python interpreters.
* Performance improvements.

1.3.0
-----
* Allow ``python setup.py test`` to work.
* Added ``encoding`` parameter to ``write``, which controls the output
  encoding. The default encoding is ``utf-8``. If the encoding is ``None``,
  a ``unicode`` string will be returned.
* Implemented ``write`` using a C extension module.

1.2.7
-----
* Improved error messages when an error is encountered deserializing an
  expression.
* Modified to work with Python 2.4.

1.2.6
-----

Thanks to Deron Meranda (author of ``demjson``) for his excellent `JSON
library comparison <http://deron.meranda.us/python/comparing_json_modules/>`_,
which revealed many areas for improvement:

* Use ``repr`` instead of ``unicode`` for serializing floating-point values,
  to avoid unnecessary rounding.
* Fixed bug that prevented plus signs in an exponent from being parsed
  correctly.
* Added support for serializing the following types:

  - ``generator``
  - ``set``
  - ``frozenset``
  - ``complex``, for values with no imaginary component.
  - ``array.array``
  - ``collections.deque``
  - ``collections.defaultdict``
  - ``UserList.UserList``
  - ``UserDict.UserDict``
  - ``UserString.UserString``

* Raise an exception if a control character is encountered in a string.
* Added support for detecting Unicode byte order marks in the auto decoder.
* Allow only arrays and objects to be serialized directly. All other types
  must be contained within an array or object.
* Stricter detection of whitespace.

Also includes some other miscellaneous fixes:

* More reliable detection of ``Infinity`` and ``NaN`` on Windows.
* Support for decoding UTF-32 on UCS2 builds of Python.
* Faster detection of self-recursive containers.

1.2.5
-----
* Return Unicode strings from ``write``, so the user can control the final
  encoding.
* Prevent ``Infinity``, ``-Infinity``, and ``NaN`` from being serialized
  because JSON does not support these values.
* Added ``coerce_keys`` parameter to ``write``. If ``True``, mapping keys
  will be coerced to strings. Defaults to ``False``.
* Added ``ascii_only`` parameter to ``write``. If ``True``, non-ASCII
  codepoints will always be escaped to a \u sequence. Defaults to ``True``.
* Real detection of self-recursive container types.
* Escape the solidus to prevent against `security issues
  <http://t3.dotgnu.info/blog/insecurity/quotes-dont-help.html>`_.

1.2.4
-----
* Fixed bug that prevented characters from being read after reading a
  Unicode escape sequence.
* Moved test cases into ``jsonlib.tests`` subpackage.

1.2.3
-----
* Port to setuptools.
* Corrected false positive in detection of illegal leading zeroes.

1.2.2
-----
* Raise an exception if values in an object or array are not separated by
  commas.

1.2.1
-----
* Support for building on Windows.

1.2.0
-----
* Added ``sort_keys`` parameter to ``write``. This allows mapping types to
  be serialized to a predictable value, regardless of key ordering.
* Added ``indent`` to ``write``. Any string passed as this value will be
  used for indentation. If the value is not `None`, pretty-printing will
  be activated.

1.1.0
-----
* Support for reading astral Unicode codepoints on UCS2 builds of Python.

1.0.0
-----
* Initial release.
