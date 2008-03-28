/**
 * Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
 * Author: John Millikin <jmillikin@gmail.com>
 * 
 * Implementation of _write in C.
**/

#include "jsonlib-common.h"

typedef struct _WriterState
{
	/* Pulled from the current interpreter to avoid errors when used
	 * with sub-interpreters.
	**/
	PyObject *Decimal;
	PyObject *UserString;
	PyObject *WriteError;
	PyObject *UnknownSerializerError;
	
	/* Options passed to _write */
	int sort_keys;
	PyObject *indent_string;
	int ascii_only;
	int coerce_keys;
	
	/* Constants, saved to avoid lookup later */
	PyObject *true_str;
	PyObject *false_str;
	PyObject *null_str;
	PyObject *inf_str;
	PyObject *neg_inf_str;
	PyObject *nan_str;
	PyObject *quote;
} WriterState;

/* Serialization functions */
static PyObject *
write_object (WriterState *state, PyObject *object, int indent_level);

static PyObject *
write_iterable (WriterState *state, PyObject *iterable, int indent_level);

static PyObject *
write_mapping (WriterState *state, PyObject *mapping, int indent_level);

static PyObject *
write_basic (WriterState *state, PyObject *value);

static PyObject *
write_string (WriterState *state, PyObject *string);

static PyObject *
write_unicode (WriterState *state, PyObject *unicode);

/* Variants of the unicode serializer */
static PyObject *
unicode_to_unicode (PyObject *unicode);

static PyObject *
unicode_to_ascii (PyObject *unicode);

static const char *hexdigit = "0123456789abcdef";

static PyObject *
unicode_from_ascii (const char *value)
{
	PyObject *str, *retval;
	str = PyString_FromString (value);
	retval = PyUnicode_FromEncodedObject (str, "ascii", "strict");
	Py_DECREF (str);
	return retval;
}

static void
get_separators (PyObject *indent_string, int indent_level,
                char start, char end,
                PyObject **start_ptr, PyObject **end_ptr,
                PyObject **pre_value_ptr, PyObject **post_value_ptr)
{
	if (indent_string == Py_None)
	{
		(*start_ptr) = PyString_FromFormat ("%c", start);
		(*pre_value_ptr) = NULL;
		(*post_value_ptr) = PyString_FromString (",");
		(*end_ptr) = PyString_FromFormat ("%c", end);
	}
	else
	{
		PyObject *format_args, *format_tmpl, *indent, *next_indent;
		
		(*start_ptr) = PyString_FromFormat ("%c%c", start, '\n');
		(*post_value_ptr) = PyString_FromFormat (",%c", '\n');
		
		indent = PySequence_Repeat (indent_string, indent_level + 1);
		(*pre_value_ptr) = indent;
		
		next_indent = PySequence_Repeat (indent_string, indent_level);
		format_args = Py_BuildValue ("(N)", next_indent);
		format_tmpl = PyString_FromFormat ("\n%%s%c", end);
		(*end_ptr) = PyString_Format (format_tmpl, format_args);
		Py_DECREF (format_args);
		Py_DECREF (format_tmpl);
	}
}

static PyObject *
write_string (WriterState *state, PyObject *string)
{
	PyObject *unicode, *retval;
	int safe = TRUE;
	char *buffer;
	Py_ssize_t ii, str_len;
	
	/* Scan the string for non-ASCII values. If none exist, the string
	 * can be returned directly (with quotes).
	**/
	if (PyString_AsStringAndSize (string, &buffer, &str_len) == -1)
		return NULL;
	
	for (ii = 0; ii < str_len; ++ii)
	{
		if (buffer[ii] < 0x20 ||
		    buffer[ii] > 0x7E ||
		    buffer[ii] == '"' ||
		    buffer[ii] == '/' ||
		    buffer[ii] == '\\')
		{
			safe = FALSE;
			break;
		}
	}
	
	if (safe)
	{
		retval = PyList_New (3);
		Py_INCREF (state->quote);
		PyList_SetItem (retval, 0, state->quote);
		Py_INCREF (string);
		PyList_SetItem (retval, 1, string);
		Py_INCREF (state->quote);
		PyList_SetItem (retval, 2, state->quote);
		return retval;
	}
	
	/* Convert to Unicode and run through the escaping
	 * mechanism.
	**/
	Py_INCREF (string);
	unicode = PyString_AsDecodedObject (string, "ascii", "strict");
	Py_DECREF (string);
	if (!unicode) return NULL;
	
	if (state->ascii_only)
		retval = unicode_to_ascii (unicode);
	else
		retval = unicode_to_unicode (unicode);
	Py_DECREF (unicode);
	return retval;
}

static PyObject *
unicode_to_unicode (PyObject *unicode)
{
	PyObject *retval;
	Py_UNICODE *old_buffer, *new_buffer, *buffer_pos;
	size_t ii, old_buffer_size, new_buffer_size;
	
	old_buffer = PyUnicode_AS_UNICODE (unicode);
	old_buffer_size = PyUnicode_GET_SIZE (unicode);
	
	/*
	Calculate the size needed to store the final string:
	
		* 2 chars for opening and closing quotes
		* 2 chars each for each of these characters:
			* U+0008
			* U+0009
			* U+000A
			* U+000C
			* U+000D
			* U+0022
			* U+002F
			* U+005C
		* 6 chars for other characters <= U+001F
		* 1 char for other characters.
	
	*/
	new_buffer_size = 2;
	for (ii = 0; ii < old_buffer_size; ii++)
	{
		Py_UNICODE c = old_buffer[ii];
		if (c == 0x08 ||
		    c == 0x09 ||
		    c == 0x0A ||
		    c == 0x0C ||
		    c == 0x0D ||
		    c == 0x22 ||
		    c == 0x2F ||
		    c == 0x5C)
			new_buffer_size += 2;
		else if (c <= 0x1F)
			new_buffer_size += 6;
		else
			new_buffer_size += 1;
	}
	
	new_buffer = PyMem_New (Py_UNICODE, new_buffer_size);
	if (!new_buffer) return NULL;
	
	/* Fill the new buffer */
	buffer_pos = new_buffer;
	*buffer_pos++ = '"';
	for (ii = 0; ii < old_buffer_size; ii++)
	{
		Py_UNICODE c = old_buffer[ii];
		if (c == 0x08)
		{
			*buffer_pos++ = '\\';
			*buffer_pos++ = 'b';
		}
		else if (c == 0x09)
		{
			*buffer_pos++ = '\\';
			*buffer_pos++ = 't';
		}
		else if (c == 0x0A)
		{
			*buffer_pos++ = '\\';
			*buffer_pos++ = 'n';
		}
		else if (c == 0x0C)
		{
			*buffer_pos++ = '\\';
			*buffer_pos++ = 'f';
		}
		else if (c == 0x0D)
		{
			*buffer_pos++ = '\\';
			*buffer_pos++ = 'r';
		}
		else if (c == 0x22)
		{
			*buffer_pos++ = '\\';
			*buffer_pos++ = '"';
		}
		else if (c == 0x2F)
		{
			*buffer_pos++ = '\\';
			*buffer_pos++ = '/';
		}
		else if (c == 0x5C)
		{
			*buffer_pos++ = '\\';
			*buffer_pos++ = '\\';
		}
		else if (c <= 0x1F)
		{
			*buffer_pos++ = '\\';
			*buffer_pos++ = 'u';
			*buffer_pos++ = '0';
			*buffer_pos++ = '0';
			*buffer_pos++ = hexdigit[(c >> 4) & 0x0000000F];
			*buffer_pos++ = hexdigit[c & 0x0000000F];
		}
		else
		{
			*buffer_pos++ = c;
		}
	}
	*buffer_pos++ = '"';
	
	retval = PyUnicode_FromUnicode (new_buffer, new_buffer_size);
	PyMem_Del (new_buffer);
	return retval;
}

static PyObject *
unicode_to_ascii (PyObject *unicode)
{
	PyObject *retval;
	Py_UNICODE *old_buffer;
	char *new_buffer, *buffer_pos;
	size_t ii, old_buffer_size, new_buffer_size;
	
	old_buffer = PyUnicode_AS_UNICODE (unicode);
	old_buffer_size = PyUnicode_GET_SIZE (unicode);
	
	/*
	Calculate the size needed to store the final string:
	
		* 2 chars for opening and closing quotes
		* 2 chars each for each of these characters:
			* U+0008
			* U+0009
			* U+000A
			* U+000C
			* U+000D
			* U+0022
			* U+002F
			* U+005C
		* 6 chars for other characters <= U+001F
		* 12 chars for characters > 0xFFFF
		* 6 chars for characters > 0x7E
		* 1 char for other characters.
	
	*/
	new_buffer_size = 2;
	for (ii = 0; ii < old_buffer_size; ii++)
	{
		Py_UNICODE c = old_buffer[ii];
		if (c == 0x08 ||
		    c == 0x09 ||
		    c == 0x0A ||
		    c == 0x0C ||
		    c == 0x0D ||
		    c == 0x22 ||
		    c == 0x2F ||
		    c == 0x5C)
			new_buffer_size += 2;
		else if (c <= 0x1F)
			new_buffer_size += 6;
			
#		ifdef Py_UNICODE_WIDE
			else if (c > 0xFFFF)
				new_buffer_size += 12;
#		endif
		
		else if (c > 0x7E)
			new_buffer_size += 6;
		else
			new_buffer_size += 1;
	}
	
	new_buffer = PyMem_Malloc (new_buffer_size);
	if (!new_buffer) return NULL;
	
	/* Fill the new buffer */
	buffer_pos = new_buffer;
	*buffer_pos++ = '"';
	for (ii = 0; ii < old_buffer_size; ii++)
	{
		Py_UNICODE c = old_buffer[ii];
		if (c == 0x08)
		{
			*buffer_pos++ = '\\';
			*buffer_pos++ = 'b';
		}
		else if (c == 0x09)
		{
			*buffer_pos++ = '\\';
			*buffer_pos++ = 't';
		}
		else if (c == 0x0A)
		{
			*buffer_pos++ = '\\';
			*buffer_pos++ = 'n';
		}
		else if (c == 0x0C)
		{
			*buffer_pos++ = '\\';
			*buffer_pos++ = 'f';
		}
		else if (c == 0x0D)
		{
			*buffer_pos++ = '\\';
			*buffer_pos++ = 'r';
		}
		else if (c == 0x22)
		{
			*buffer_pos++ = '\\';
			*buffer_pos++ = '"';
		}
		else if (c == 0x2F)
		{
			*buffer_pos++ = '\\';
			*buffer_pos++ = '/';
		}
		else if (c == 0x5C)
		{
			*buffer_pos++ = '\\';
			*buffer_pos++ = '\\';
		}
		else if (c <= 0x1F)
		{
			*buffer_pos++ = '\\';
			*buffer_pos++ = 'u';
			*buffer_pos++ = '0';
			*buffer_pos++ = '0';
			*buffer_pos++ = hexdigit[(c >> 4) & 0x0000000F];
			*buffer_pos++ = hexdigit[c & 0x0000000F];
		}
#ifdef Py_UNICODE_WIDE
		else if (c > 0xFFFF)
		{
			/* Separate into upper and lower surrogate pair */
			Py_UNICODE reduced, upper, lower;
			
			reduced = c - 0x10000;
			lower = (reduced & 0x3FF);
			upper = (reduced >> 10);
			
			upper += 0xD800;
			lower += 0xDC00;
			
			*buffer_pos++ = '\\';
			*buffer_pos++ = 'u';
			*buffer_pos++ = hexdigit[(upper >> 12) & 0x0000000F];
			*buffer_pos++ = hexdigit[(upper >> 8) & 0x0000000F];
			*buffer_pos++ = hexdigit[(upper >> 4) & 0x0000000F];
			*buffer_pos++ = hexdigit[upper & 0x0000000F];
			
			*buffer_pos++ = '\\';
			*buffer_pos++ = 'u';
			*buffer_pos++ = hexdigit[(lower >> 12) & 0x0000000F];
			*buffer_pos++ = hexdigit[(lower >> 8) & 0x0000000F];
			*buffer_pos++ = hexdigit[(lower >> 4) & 0x0000000F];
			*buffer_pos++ = hexdigit[lower & 0x0000000F];
		}
#endif
		else if (c > 0x7E)
		{
			*buffer_pos++ = '\\';
			*buffer_pos++ = 'u';
			*buffer_pos++ = hexdigit[(c >> 12) & 0x000F];
			*buffer_pos++ = hexdigit[(c >> 8) & 0x000F];
			*buffer_pos++ = hexdigit[(c >> 4) & 0x000F];
			*buffer_pos++ = hexdigit[c & 0x000F];
		}
		else
		{
			*buffer_pos++ = (char) (c);
		}
	}
	*buffer_pos++ = '"';
	
	retval = PyString_FromStringAndSize (new_buffer, new_buffer_size);
	PyMem_Free (new_buffer);
	return retval;
}

static PyObject *
write_unicode (WriterState *state, PyObject *unicode)
{
	PyObject *retval;
	int safe = TRUE;
	Py_UNICODE *buffer;
	Py_ssize_t ii, str_len;
	
	/* Check if the string can be returned directly */
	buffer = PyUnicode_AS_UNICODE (unicode);
	str_len = PyUnicode_GET_SIZE (unicode);
	
	for (ii = 0; ii < str_len; ++ii)
	{
		if (buffer[ii] < 0x20 ||
		    (state->ascii_only && buffer[ii] > 0x7E) ||
		    buffer[ii] == '"' ||
		    buffer[ii] == '/' ||
		    buffer[ii] == '\\')
		{
			safe = FALSE;
			break;
		}
	}
	
	if (safe)
	{
		retval = PyList_New (3);
		Py_INCREF (state->quote);
		PyList_SetItem (retval, 0, state->quote);
		Py_INCREF (unicode);
		PyList_SetItem (retval, 1, unicode);
		Py_INCREF (state->quote);
		PyList_SetItem (retval, 2, state->quote);
		return retval;
	}
	
	/* Scan through again to check for invalid surrogate pairs */
	for (ii = 0; ii < str_len; ++ii)
	{
		if (0xD800 <= buffer[ii] && buffer[ii] <= 0xDBFF)
		{
			if (++ii == str_len)
			{
				PyErr_SetString (state->WriteError,
				                 "Cannot serialize incomplete"
						 " surrogate pair.");
				return NULL;
			}
			else if (!(0xDC00 <= buffer[ii] && buffer[ii] <= 0xDFFF))
			{
				PyErr_SetString (state->WriteError,
				                 "Cannot serialize invalid surrogate pair.");
				return NULL;
			}
		}
		else if (0xDC00 <= buffer[ii] && buffer[ii] <= 0xDFFF)
		{
			PyObject *err_msg;
			
			err_msg = jsonlib_str_format ("Cannot serialize reserved code point U+%04X.",
			                              Py_BuildValue ("(k)", buffer[ii]));
			if (err_msg)
			{
				PyErr_SetObject (state->WriteError, err_msg);
				Py_DECREF (err_msg);
			}
			return NULL;
		}
	}
	
	if (state->ascii_only)
		return unicode_to_ascii (unicode);
	return unicode_to_unicode (unicode);
}

static int
write_sequence_impl (WriterState *state, PyObject *seq, PyObject *pieces,
                     PyObject *start, PyObject *end,
                     PyObject *pre_value, PyObject *post_value,
                     int indent_level)
{
	Py_ssize_t ii;
	
	if (PyList_Append (pieces, start) == -1)
		return FALSE;
	
	/* Check size every loop because the sequence might be mutable */
	for (ii = 0; ii < PySequence_Fast_GET_SIZE (seq); ++ii)
	{
		PyObject *item, *serialized, *pieces2;
		
		if (pre_value && PyList_Append (pieces, pre_value) == -1)
			return FALSE;
		
		if (!(item = PySequence_Fast_GET_ITEM (seq, ii)))
			return FALSE;
		
		serialized = write_object (state, item, indent_level + 1);
		if (!serialized) return FALSE;
		
		pieces2 = PySequence_InPlaceConcat (pieces, serialized);
		Py_DECREF (serialized);
		if (!pieces2) return FALSE;
		Py_DECREF (pieces2);
		
		if (ii + 1 < PySequence_Fast_GET_SIZE (seq))
		{
			if (PyList_Append (pieces, post_value) == -1)
				return FALSE;
		}
	}
	
	if (PyList_Append (pieces, end) == -1)
		return FALSE;
	
	return TRUE;
}

static PyObject*
write_iterable (WriterState *state, PyObject *iter, int indent_level)
{
	PyObject *sequence, *pieces;
	PyObject *start, *end, *pre, *post;
	int has_parents, succeeded;
	
	/* Guard against infinite recursion */
	has_parents = Py_ReprEnter (iter);
	if (has_parents > 0)
	{
		PyErr_SetString (state->WriteError,
		                 "Cannot serialize self-referential"
		                 " values.");
	}
	if (has_parents != 0) return NULL;
	
	sequence = PySequence_Fast (iter, "Error converting iterable to sequence.");
	
	/* Shortcut for len (sequence) == 0 */
	if (PySequence_Fast_GET_SIZE (sequence) == 0)
	{
		Py_DECREF (sequence);
		Py_ReprLeave (iter);
		return PyString_FromString ("[]");
	}
	
	if (!(pieces = PyList_New (0)))
	{
		Py_DECREF (sequence);
		Py_ReprLeave (iter);
		return NULL;
	}
	
	/* Build separator strings */
	get_separators (state->indent_string, indent_level, '[', ']',
	                &start, &end, &pre, &post);
	
	succeeded = write_sequence_impl (state, sequence, pieces,
	                                 start, end, pre, post,
	                                 indent_level);
	
	Py_DECREF (sequence);
	Py_ReprLeave (iter);
	
	Py_XDECREF (start);
	Py_XDECREF (end);
	Py_XDECREF (pre);
	Py_XDECREF (post);
	
	if (!succeeded)
	{
		Py_DECREF (pieces);
		pieces = NULL;
	}
	return pieces;
}

static int
mapping_get_key_and_value (WriterState *state, PyObject *item,
                           PyObject **key_ptr, PyObject **value_ptr)
{
	PyObject *key, *value;
	
	(*key_ptr) = NULL;
	(*value_ptr) = NULL;
	
	if (!(key = PySequence_GetItem (item, 0)))
		return FALSE;
	
	if (!(PyString_Check (key) || PyUnicode_Check (key)))
	{
		if (state->coerce_keys)
		{
			PyObject *new_key = NULL;
			if (!(new_key = write_basic (state, key)))
			{
				if (PyErr_ExceptionMatches (state->UnknownSerializerError))
				{
					PyErr_Clear ();
					new_key = PyObject_Unicode (key);
				}
			}
			
			Py_DECREF (key);
			if (!new_key) return FALSE;
			key = new_key;
		}
		else
		{
			Py_DECREF (key);
			PyErr_SetString (state->WriteError,
			                 "Only strings may be used"
			                 " as object keys.");
			return FALSE;
		}
	}
	if (!(value = PySequence_GetItem (item, 1)))
	{
		Py_DECREF (key);
		return FALSE;
	}
	*key_ptr = key;
	*value_ptr = value;
	return TRUE;
}

static int
write_mapping_impl (WriterState *state, PyObject *items, PyObject *pieces,
                    PyObject *start, PyObject *end, PyObject *pre_value,
                    PyObject *post_value, PyObject *colon, int indent_level)
{
	int status;
	size_t ii, item_count;
	
	if (PyList_Append (pieces, start) == -1)
		return FALSE;
	
	item_count = PySequence_Size (items);
	for (ii = 0; ii < item_count; ++ii)
	{
		PyObject *item, *key, *value, *serialized, *pieces2;
		
		if (pre_value && PyList_Append (pieces, pre_value) == -1)
			return FALSE;
		
		if (!(item = PySequence_GetItem (items, ii)))
			return FALSE;
		
		status = mapping_get_key_and_value (state, item, &key, &value);
		Py_DECREF (item);
		if (!status) return FALSE;
		
		serialized = write_basic (state, key);
		Py_DECREF (key);
		if (!serialized)
		{
			Py_DECREF (value);
			return FALSE;
		}
		
		pieces2 = PySequence_InPlaceConcat (pieces, serialized);
		Py_DECREF (serialized);
		if (!pieces2)
		{
			Py_DECREF (value);
			return FALSE;
		}
		Py_DECREF (pieces2);
		
		if (PyList_Append (pieces, colon) == -1)
		{
			Py_DECREF (value);
			return FALSE;
		}
		
		serialized = write_object (state, value, indent_level + 1);
		Py_DECREF (value);
		if (!serialized)
		{
			return FALSE;
		}
		
		pieces2 = PySequence_InPlaceConcat (pieces, serialized);
		Py_DECREF (serialized);
		if (!pieces2) return FALSE;
		Py_DECREF (pieces2);
		
		if (ii + 1 < item_count)
		{
			if (PyList_Append (pieces, post_value) == -1)
			{
				return FALSE;
			}
		}
	}
	
	if (PyList_Append (pieces, end) == -1)
		return FALSE;
	
	return TRUE;
}

static PyObject *
write_mapping (WriterState *state, PyObject *mapping, int indent_level)
{
	int has_parents, succeeded;
	PyObject *pieces, *items;
	PyObject *start, *end, *pre_value, *post_value, *colon;
	
	if (PyMapping_Size (mapping) == 0)
		return PyString_FromString ("{}");
	
	has_parents = Py_ReprEnter (mapping);
	if (has_parents != 0)
	{
		if (has_parents > 0)
		{
			PyErr_SetString (state->WriteError,
			                 "Cannot serialize self-referential"
			                 " values.");
		}
		return NULL;
	}
	
	if (!(pieces = PyList_New (0)))
	{
		Py_ReprLeave (mapping);
		return NULL;
	}
	
	Py_INCREF (mapping);
	if (!(items = PyMapping_Items (mapping)))
	{
		Py_ReprLeave (mapping);
		Py_DECREF (mapping);
		return NULL;
	}
	if (state->sort_keys) PyList_Sort (items);
	
	if (state->indent_string == Py_None)
		colon = PyString_FromString (":");
	else
		colon = PyString_FromString (": ");
	if (!colon)
	{
		Py_ReprLeave (mapping);
		Py_DECREF (mapping);
		return NULL;
	}
	
	get_separators (state->indent_string, indent_level, '{', '}',
	                &start, &end, &pre_value, &post_value);
	
	succeeded = write_mapping_impl (state, items, pieces,
	                                start, end, pre_value, post_value,
	                                colon, indent_level);
	
	Py_ReprLeave (mapping);
	Py_DECREF (mapping);
	
	Py_DECREF (items);
	Py_XDECREF (start);
	Py_XDECREF (end);
	Py_XDECREF (pre_value);
	Py_XDECREF (post_value);
	
	if (!succeeded)
	{
		Py_DECREF (pieces);
		pieces = NULL;
	}
	return pieces;
}

static int
check_valid_number (WriterState *state, PyObject *serialized)
{
	int invalid;
	
	invalid = PyObject_RichCompareBool (state->inf_str, serialized, Py_NE);
	if (invalid < 1) return invalid;
	
	invalid = PyObject_RichCompareBool (state->neg_inf_str, serialized, Py_NE);
	if (invalid < 1) return invalid;
	
	invalid = PyObject_RichCompareBool (state->nan_str, serialized, Py_NE);
	if (invalid < 1) return invalid;
	
	return TRUE;
}

static PyObject *
write_basic (WriterState *state, PyObject *value)
{
	if (value == Py_True)
	{
		Py_INCREF (state->true_str);
		return state->true_str;
	}
	if (value == Py_False)
	{
		Py_INCREF (state->false_str);
		return state->false_str;
	}
	if (value == Py_None)
	{
		Py_INCREF (state->null_str);
		return state->null_str;
	}
	
	if (PyString_Check (value))
		return write_string (state, value);
	if (PyUnicode_Check (value))
		return write_unicode (state, value);
	if (PyInt_Check (value) || PyLong_Check (value))
		return PyObject_Str (value);
	if (PyComplex_Check (value))
	{
		Py_complex complex = PyComplex_AsCComplex (value);
		if (complex.imag == 0)
		{
			PyObject *real, *serialized;
			if (!(real = PyFloat_FromDouble (complex.real)))
				return NULL;
			serialized = PyObject_Repr (real);
			Py_DECREF (real);
			return serialized;
		}
		PyErr_SetString (state->WriteError,
		                 "Cannot serialize complex numbers with"
		                 " imaginary components.");
		return NULL;
	}
	
	if (PyFloat_Check (value))
	{
		double val = PyFloat_AS_DOUBLE (value);
		if (Py_IS_NAN (val))
		{
			PyErr_SetString (state->WriteError,
			                 "Cannot serialize NaN.");
			return NULL;
		}
		
		if (Py_IS_INFINITY (val))
		{
			const char *msg;
			if (val > 0)
				msg = "Cannot serialize Infinity.";
			else
				msg = "Cannot serialize -Infinity.";
			
			PyErr_SetString (state->WriteError, msg);
			return NULL;
		}
		
		return PyObject_Repr (value);
	}
	
	if (PyObject_IsInstance (value, state->Decimal))
	{
		PyObject *serialized = PyObject_Str (value);
		int valid;
		
		valid = check_valid_number (state, serialized);
		if (valid == TRUE)
			return serialized;
		
		if (valid == FALSE)
		{
			PyErr_Format (state->WriteError,
			              "Cannot serialize %s.",
			              PyString_AsString (serialized));
		}
		/* else valid == -1, error */
		Py_DECREF (serialized);
		return NULL;
	}
	
	if (PyObject_IsInstance (value, state->UserString))
	{
		PyObject *as_string, *retval;
		if (!(as_string = PyObject_Str (value)))
			return NULL;
		retval = write_string (state, as_string);
		Py_DECREF (as_string);
		return retval;
	}
	
	PyErr_SetObject (state->UnknownSerializerError, value);
	return NULL;
}

static PyObject *
write_object_pieces (WriterState *state, PyObject *object, int indent_level)
{
	PyObject *pieces, *iter;
	PyObject *exc_type, *exc_value, *exc_traceback;
	
	if (PyList_Check (object) || PyTuple_Check (object))
	{
		return write_iterable (state, object, indent_level);
	}
	
	else if (PyDict_Check (object))
	{
		return write_mapping (state, object, indent_level);
	}
	
	if ((pieces = write_basic (state, object)))
	{
		if (indent_level == 0)
		{
			Py_DECREF (pieces);
			PyErr_SetString (state->WriteError,
			                 "The outermost container must be"
			                 " an array or object.");
			return NULL;
		}
		return pieces;
	}
	
	if (!PyErr_ExceptionMatches (state->UnknownSerializerError))
		return NULL;
	
	PyErr_Fetch (&exc_type, &exc_value, &exc_traceback);
	if (PyObject_HasAttrString (object, "items"))
	{
		PyErr_Clear ();
		return write_mapping (state, object, indent_level);
	}
	
	if (PySequence_Check (object))
	{
		PyErr_Clear ();
		return write_iterable (state, object, indent_level);
	}
	
	iter = PyObject_GetIter (object);
	PyErr_Restore (exc_type, exc_value, exc_traceback);
	if (iter)
	{
		PyErr_Clear ();
		pieces = write_iterable (state, iter, indent_level);
		Py_DECREF (iter);
		return pieces;
	}
	
	return NULL;
}

static PyObject *
write_object (WriterState *state, PyObject *object, int indent_level)
{
	PyObject *pieces, *retval = NULL;
	
	if ((pieces = write_object_pieces (state, object, indent_level)))
	{
		if (PyString_Check (pieces) || PyUnicode_Check (pieces))
		{
			retval = PyTuple_New (1);
			PyTuple_SetItem (retval, 0, pieces);
		}
		else
		{
			retval = PySequence_Fast (pieces, "Failed to convert to sequence.");
			Py_DECREF (pieces);
		}
	}
	return retval;
}

static PyObject*
_write_entry (PyObject *self, PyObject *args)
{
	PyObject *result = NULL, *value;
	WriterState state;
	
	if (!PyArg_ParseTuple (args, "OiOiiOOOO:_write",
	                       &value, &state.sort_keys, &state.indent_string,
	                       &state.ascii_only, &state.coerce_keys,
	                       &state.Decimal, &state.UserString,
	                       &state.WriteError, &state.UnknownSerializerError))
		return NULL;
	
	if ((state.true_str = unicode_from_ascii ("true")) &&
	    (state.false_str = unicode_from_ascii ("false")) &&
	    (state.null_str = unicode_from_ascii ("null")) &&
	    (state.inf_str = unicode_from_ascii ("Infinity")) &&
	    (state.neg_inf_str = unicode_from_ascii ("-Infinity")) &&
	    (state.nan_str = unicode_from_ascii ("NaN")) &&
	    (state.quote = unicode_from_ascii ("\"")))
	{
		result = write_object (&state, value, 0);
	}
	
	Py_XDECREF (state.true_str);
	Py_XDECREF (state.false_str);
	Py_XDECREF (state.null_str);
	Py_XDECREF (state.inf_str);
	Py_XDECREF (state.neg_inf_str);
	Py_XDECREF (state.nan_str);
	Py_XDECREF (state.quote);
	
	return result;
}

static PyMethodDef writer_methods[] = {
	{"_write", (PyCFunction) (_write_entry), METH_VARARGS,
	PyDoc_STR ("Serialize a Python object to JSON.")},
	
	{NULL, NULL}
};

PyDoc_STRVAR (module_doc,
	"Fast implementation of jsonlib._write."
);

PyMODINIT_FUNC
init_writer(void)
{
	Py_InitModule3 ("_writer", writer_methods, module_doc);
}
