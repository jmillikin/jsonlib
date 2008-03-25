/**
 * Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
 * Author: John Millikin <jmillikin@gmail.com>
 * 
 * Implementation of _write in C.
**/

#include <Python.h>
#include <stddef.h>
#include <stdio.h>
#include <ctype.h>
#include <math.h>

#define FALSE 0
#define TRUE 1

static void
get_indent (PyObject *indent_string, int indent_level,
            PyObject **newline, PyObject **indent, PyObject **next_indent);

static PyObject *
write_string (PyObject *string, int ascii_only);

static PyObject *
unicode_to_unicode (PyObject *unicode);

static PyObject *
unicode_to_ascii (PyObject *unicode);

static PyObject *
write_unicode_full (PyObject *unicode, int ascii_only);

static PyObject *
write_unicode (PyObject *unicode, int ascii_only);

static PyObject *
json_write (PyObject *object, int sort_keys, PyObject *indent_string,
            int ascii_only, int coerce_keys, int indent_level);

static PyObject *
write_sequence (PyObject *object, int sort_keys, PyObject *indent_string,
                int ascii_only, int coerce_keys, int indent_level);

static PyObject *
write_mapping (PyObject *object, int sort_keys, PyObject *indent_string,
               int ascii_only, int coerce_keys, int indent_level);

static PyObject *
write_basic (PyObject *value, int ascii_only);

static PyObject *WriteError;
static PyObject *UnknownSerializerError;

static const char *hexdigit = "0123456789abcdef";

static void
get_indent (PyObject *indent_string, int indent_level,
            PyObject **newline, PyObject **indent, PyObject **next_indent)
{
	if (indent_string == Py_None)
	{
		(*newline) = NULL;
		(*indent) = NULL;
		(*next_indent) = NULL;
	}
	else
	{
		(*newline) = PyString_FromString ("\n");
		(*indent) = PySequence_Repeat (indent_string, indent_level + 1);
		(*next_indent) = PySequence_Repeat (indent_string, indent_level);
	}
}

static PyObject*
write_string (PyObject *string, int ascii_only)
{
	PyObject *unicode, *retval;
	int safe = TRUE;
	char *buffer;
	size_t ii;
	Py_ssize_t str_len;
	
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
		PyObject *quote = PyString_FromString ("\"");
		retval = PyList_New (3);
		Py_INCREF (quote);
		PyList_SetItem (retval, 0, quote);
		Py_INCREF (string);
		PyList_SetItem (retval, 1, string);
		PyList_SetItem (retval, 2, quote);
		return retval;
	}
	
	/* Convert to Unicode and run through the escaping
	 * mechanism.
	**/
	Py_INCREF (string);
	unicode = PyUnicode_FromObject (string);
	Py_DECREF (string);
	if (!unicode) return NULL;
	
	retval = write_unicode_full (unicode, ascii_only);
	
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
#ifdef Py_UNICODE_WIDE
		else if (c > 0xFFFF)
			new_buffer_size += 12;
#endif
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
			*buffer_pos++ = c;
		}
	}
	*buffer_pos++ = '"';
	
	retval = PyString_FromStringAndSize (new_buffer, new_buffer_size);
	PyMem_Free (new_buffer);
	return retval;
}

static PyObject *
write_unicode_full (PyObject *unicode, int ascii_only)
{
	if (ascii_only)
		return unicode_to_ascii (unicode);
	return unicode_to_unicode (unicode);
}

static PyObject *
write_unicode (PyObject *unicode, int ascii_only)
{
	PyObject *retval;
	int safe = TRUE;
	Py_UNICODE *buffer;
	size_t ii;
	Py_ssize_t str_len;
	
	/* Check if the string can be returned directly */
	buffer = PyUnicode_AS_UNICODE (unicode);
	str_len = PyUnicode_GET_SIZE (unicode);
	
	for (ii = 0; ii < str_len; ++ii)
	{
		if (buffer[ii] < 0x20 ||
		    (ascii_only && buffer[ii] > 0x7E) ||
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
		PyObject *quote = PyString_FromString ("\"");
		retval = PyList_New (3);
		Py_INCREF (quote);
		PyList_SetItem (retval, 0, quote);
		Py_INCREF (unicode);
		PyList_SetItem (retval, 1, unicode);
		PyList_SetItem (retval, 2, quote);
		return retval;
	}
	
	return write_unicode_full (unicode, ascii_only);
}

static int
write_sequence_impl (PyObject *seq, PyObject *pieces,
                     PyObject *newline, PyObject *indent, PyObject *next_indent,
                     int sort_keys, PyObject *indent_string,
                     int ascii_only, int coerce_keys, int indent_level)
{
	PyObject *start, *end;
	int status;
	size_t ii;
	
	start = PyString_FromString ("[");
	status = PyList_Append (pieces, start);
	Py_DECREF (start);
	if (status == -1) return FALSE;
	if (newline && PyList_Append (pieces, newline) == -1)
		return FALSE;
	
	/* Use PySequence_Size because the sequence might be mutable */
	for (ii = 0; ii < PySequence_Size (seq); ++ii)
	{
		PyObject *item, *serialized, *pieces2;
		
		if (indent && PyList_Append (pieces, indent) == -1)
			return FALSE;
		
		if (!(item = PySequence_GetItem (seq, ii)))
			return FALSE;
		
		serialized = json_write (item, sort_keys,
		                         indent_string,
		                         ascii_only, coerce_keys,
		                         indent_level + 1);
		Py_DECREF (item);
		if (!serialized) return FALSE;
		
		pieces2 = PySequence_InPlaceConcat (pieces, serialized);
		Py_DECREF (serialized);
		if (!pieces2) return FALSE;
		Py_DECREF (pieces2);
		
		if (ii + 1 < PySequence_Size (seq))
		{
			PyObject *separator = PyString_FromString (",");
			status = PyList_Append (pieces, separator);
			Py_DECREF (separator);
			if (status == -1) return FALSE;
			if (newline && PyList_Append (pieces, newline) == -1)
				return FALSE;
		}
	}
	
	if (newline && PyList_Append (pieces, newline) == -1)
		return FALSE;
	if (next_indent && PyList_Append (pieces, next_indent) == -1)
		return FALSE;
	end = PyString_FromString ("]");
	status = PyList_Append (pieces, end);
	Py_DECREF (end);
	if (status == -1) return FALSE;
	
	return TRUE;
}

static PyObject*
write_sequence (PyObject *seq, int sort_keys, PyObject *indent_string,
                int ascii_only, int coerce_keys, int indent_level)
{
	int has_parents, succeeded;
	PyObject *pieces;
	PyObject *newline, *indent, *next_indent;
	
	if (PySequence_Size (seq) == 0)
		return PyString_FromString ("[]");
	
	has_parents = Py_ReprEnter (seq);
	if (has_parents != 0)
	{
		if (has_parents > 0)
		{
			PyErr_SetString (WriteError, "Cannot serialize self-referential values.");
		}
		return NULL;
	}
	
	if (!(pieces = PyList_New (0)))
	{
		Py_ReprLeave (seq);
		return NULL;
	}
	
	get_indent (indent_string, indent_level, &newline, &indent,
	            &next_indent);
	
	Py_INCREF (seq);
	
	succeeded = write_sequence_impl (seq, pieces, newline, indent, next_indent,
	                                 sort_keys, indent_string, ascii_only,
	                                 coerce_keys, indent_level);
	
	Py_ReprLeave (seq);
	
	Py_DECREF (seq);
	Py_XDECREF (newline);
	Py_XDECREF (indent);
	Py_XDECREF (next_indent);
	
	if (!succeeded)
	{
		Py_DECREF (pieces);
		pieces = NULL;
	}
	return pieces;
}

static int
mapping_get_key_and_value (PyObject *item, PyObject **key_ptr,
                           PyObject **value_ptr, int coerce_keys, int ascii_only)
{
	PyObject *key, *value;
	
	(*key_ptr) = NULL;
	(*value_ptr) = NULL;
	
	if (!(key = PySequence_GetItem (item, 0)))
		return FALSE;
	
	if (!PyString_Check (key) && !PyUnicode_Check (key))
	{
		if (coerce_keys)
		{
			PyObject *new_key;
			if (!(new_key = write_basic (key, ascii_only)))
			{
				if (!PyErr_ExceptionMatches(UnknownSerializerError))
				{
					Py_DECREF (key);
					return FALSE;
				}
				
				PyErr_Clear();
				if (!(new_key = PyObject_Unicode (key)))
				{
					Py_DECREF (key);
					return FALSE;
				}
			}
			
			Py_DECREF (key);
			key = new_key;
		}
		else
		{
			Py_DECREF (key);
			PyErr_SetString (WriteError, "Only strings may be used as object keys.");
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
write_mapping_impl (PyObject *items, PyObject *pieces,
                    PyObject *newline, PyObject *indent, PyObject *next_indent,
                    int sort_keys, PyObject *indent_string,
                    int ascii_only, int coerce_keys, int indent_level)
{
	PyObject *start, *end;
	int status;
	size_t ii, item_count;
	
	start = PyString_FromString ("{");
	status = PyList_Append (pieces, start);
	Py_DECREF (start);
	if (status == -1) return FALSE;
	if (newline && PyList_Append (pieces, newline) == -1)
		return FALSE;
	
	item_count = PySequence_Size (items);
	for (ii = 0; ii < item_count; ++ii)
	{
		PyObject *item, *key, *value, *serialized, *pieces2;
		
		if (indent && PyList_Append (pieces, indent) == -1)
			return FALSE;
		
		if (!(item = PySequence_GetItem (items, ii)))
			return FALSE;
		
		status = mapping_get_key_and_value (item, &key, &value,
		                                    coerce_keys, ascii_only);
		Py_DECREF (item);
		if (!status) return FALSE;
		
		serialized = write_basic (key, ascii_only);
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
		
		{
			PyObject *colon;
			if (newline)
				colon = PyString_FromString (": ");
			else
				colon = PyString_FromString (":");
			status = PyList_Append (pieces, colon);
			Py_DECREF (colon);
			if (status == -1)
			{
				Py_DECREF (value);
				return FALSE;
			}
		}
		
		serialized = json_write (value, sort_keys, indent_string,
		                         ascii_only, coerce_keys,
		                         indent_level + 1);
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
			PyObject *separator = PyString_FromString (",");
			status = PyList_Append (pieces, separator);
			Py_DECREF (separator);
			if (status == -1) return FALSE;
			if (newline && PyList_Append (pieces, newline) == -1)
				return FALSE;
		}
	}
	
	if (newline && PyList_Append (pieces, newline) == -1)
		return FALSE;
	if (next_indent && PyList_Append (pieces, next_indent) == -1)
		return FALSE;
	end = PyString_FromString ("}");
	status = PyList_Append (pieces, end);
	Py_DECREF (end);
	if (status == -1) return FALSE;
	
	return TRUE;
}

static PyObject*
write_mapping (PyObject *mapping, int sort_keys, PyObject *indent_string,
               int ascii_only, int coerce_keys, int indent_level)
{
	int has_parents, succeeded;
	PyObject *pieces, *items;
	PyObject *newline, *indent, *next_indent;
	
	if (PyMapping_Size (mapping) == 0)
		return PyString_FromString ("{}");
	
	has_parents = Py_ReprEnter (mapping);
	if (has_parents != 0)
	{
		if (has_parents > 0)
		{
			PyErr_SetString (WriteError, "Cannot serialize self-referential values.");
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
		return NULL;
	}
	if (sort_keys) PyList_Sort (items);
	
	get_indent (indent_string, indent_level, &newline, &indent,
	            &next_indent);
	
	succeeded = write_mapping_impl (items, pieces, newline, indent, next_indent,
	                                sort_keys, indent_string, ascii_only,
	                                coerce_keys, indent_level);
	
	Py_ReprLeave (mapping);
	Py_DECREF (mapping);
	
	Py_DECREF (items);
	Py_XDECREF (newline);
	Py_XDECREF (indent);
	Py_XDECREF (next_indent);
	
	if (!succeeded)
	{
		Py_DECREF (pieces);
		pieces = NULL;
	}
	return pieces;
}

static PyObject *
write_basic (PyObject *value, int ascii_only)
{
	if (value == Py_True)
		return PyString_FromString ("true");
	else if (value == Py_False)
		return PyString_FromString ("false");
	else if (value == Py_None)
		return PyString_FromString ("null");
	
	else if (PyString_Check (value))
		return write_string (value, ascii_only);
	else if (PyUnicode_Check (value))
		return write_unicode (value, ascii_only);
	else if (PyInt_Check (value) || PyLong_Check (value))
		return PyObject_Str(value);
	else if (PyFloat_Check (value))
	{
		double val = PyFloat_AS_DOUBLE (value);
		if (Py_IS_NAN (val))
		{
			PyErr_SetString(WriteError, "Cannot serialize NaN.");
			return NULL;
		}
		
		else if (Py_IS_INFINITY (val))
		{
			if (val > 0)
				PyErr_SetString (WriteError, "Cannot serialize Infinity.");
			else
				PyErr_SetString (WriteError, "Cannot serialize -Infinity.");
			return NULL;
		}
		else
			return PyObject_Repr (value);
	}
	
	else
	{
		PyErr_SetObject (UnknownSerializerError, value);
		return NULL;
	}
}

static PyObject*
json_write (PyObject *object, int sort_keys, PyObject *indent_string,
            int ascii_only, int coerce_keys, int indent_level)
{
	PyObject *retval = NULL, *pieces;
	if (PyList_Check (object) || PyTuple_Check (object))
	{
		pieces = write_sequence (object, sort_keys, indent_string,
		                          ascii_only, coerce_keys,
		                          indent_level);
	}
	
	else if (PyDict_Check(object))
	{
		pieces = write_mapping (object, sort_keys, indent_string,
		                         ascii_only, coerce_keys,
		                         indent_level);
	}
	
	else
	{
		pieces = write_basic (object, ascii_only);
	}
	
	if (pieces) retval = PySequence_List (pieces);
	Py_XDECREF (pieces);
	return retval;
}

static PyObject*
_write_entry (PyObject *self, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = {"value", "sort_keys", "indent_string",
	                         "ascii_only", "coerce_keys",
	                         "parent_objects", "indent_level", NULL};
	PyObject *result, *value, *indent_string, *parent_objects;
	int sort_keys, ascii_only, coerce_keys, indent_level;
	
	if (!PyArg_ParseTupleAndKeywords (args, kwargs, "OiOiiOi:_write", kwlist,
	                                  &value, &sort_keys, &indent_string,
	                                  &ascii_only, &coerce_keys,
	                                  &parent_objects, &indent_level))
		return NULL;
	
	Py_INCREF (value);
	Py_INCREF (indent_string);
	result = json_write (value, sort_keys, indent_string,
	                     ascii_only, coerce_keys,
	                     indent_level);
	Py_DECREF (value);
	Py_DECREF (indent_string);
	
	return result;
}

static PyMethodDef writer_methods[] = {
	{"_write", (PyCFunction) (_write_entry), METH_VARARGS|METH_KEYWORDS,
	PyDoc_STR ("Serialize a Python object to JSON.")},
	
	{NULL, NULL}
};

PyDoc_STRVAR (module_doc,
	"Fast implementation of jsonlib._write."
);

PyMODINIT_FUNC
init_writer(void)
{
	PyObject *m, *errors;
	
	if (!(m = Py_InitModule3 ("_writer", writer_methods, module_doc)))
		return;
	if (!(errors = PyImport_ImportModule ("jsonlib.errors")))
		return;
	if (!(WriteError = PyObject_GetAttrString (errors, "WriteError")))
		return;
	if (!(UnknownSerializerError = PyObject_GetAttrString (errors, "UnknownSerializerError")))
		return;
}
