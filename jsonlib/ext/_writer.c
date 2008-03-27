/**
 * Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
 * Author: John Millikin <jmillikin@gmail.com>
 * 
 * Implementation of _write in C.
**/

#include "jsonlib-common.h"

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
write_unicode (PyObject *unicode, int ascii_only);

static PyObject *
json_write (PyObject *object, int sort_keys, PyObject *indent_string,
            int ascii_only, int coerce_keys, int indent_level);

static PyObject *
write_iterable (PyObject *object, int sort_keys, PyObject *indent_string,
                int ascii_only, int coerce_keys, int indent_level);

static PyObject *
write_mapping (PyObject *object, int sort_keys, PyObject *indent_string,
               int ascii_only, int coerce_keys, int indent_level);

static PyObject *
write_basic (PyObject *value, int ascii_only);

static const char *hexdigit = "0123456789abcdef";

static PyObject *
get_WriteError (void)
{
	PyObject *module, *obj = NULL;
	if ((module = PyImport_ImportModule ("jsonlib.errors")))
	{
		obj = PyObject_GetAttrString (module, "WriteError");
		Py_DECREF (module);
	}
	return obj;
}

static PyObject *
get_UnknownSerializerError (void)
{
	PyObject *module, *obj = NULL;
	if ((module = PyImport_ImportModule ("jsonlib.errors")))
	{
		obj = PyObject_GetAttrString (module, "UnknownSerializerError");
		Py_DECREF (module);
	}
	return obj;
}

static PyObject *
get_Decimal (void)
{
	PyObject *module, *obj = NULL;
	if ((module = PyImport_ImportModule ("decimal")))
	{
		obj = PyObject_GetAttrString (module, "Decimal");
		Py_DECREF (module);
	}
	return obj;
}

static PyObject *
get_UserString (void)
{
	PyObject *module, *obj = NULL;
	if ((module = PyImport_ImportModule ("UserString")))
	{
		obj = PyObject_GetAttrString (module, "UserString");
		Py_DECREF (module);
	}
	return obj;
}

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
		
		(*start_ptr) = PyString_FromFormat ("[%c", '\n');
		(*post_value_ptr) = PyString_FromFormat (",%c", '\n');
		
		indent = PySequence_Repeat (indent_string, indent_level + 1);
		(*pre_value_ptr) = indent;
		
		next_indent = PySequence_Repeat (indent_string, indent_level);
		format_args = Py_BuildValue ("(N)", next_indent);
		format_tmpl = PyString_FromString ("\n%s]");
		(*end_ptr) = PyString_Format (format_tmpl, format_args);
		Py_DECREF (format_args);
		Py_DECREF (format_tmpl);
	}
}

static PyObject *
write_string (PyObject *string, int ascii_only)
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
	
	if (ascii_only)
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
write_unicode (PyObject *unicode, int ascii_only)
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
	
	/* Scan through again to check for invalid surrogate pairs */
	for (ii = 0; ii < str_len; ++ii)
	{
		if (0xD800 <= buffer[ii] && buffer[ii] <= 0xDBFF)
		{
			if (++ii == str_len)
			{
				PyObject *err_class;
				if ((err_class = get_WriteError ()))
				{
					PyErr_SetString (err_class,
					                 "Cannot serialize incomplete"
							 " surrogate pair.");
					Py_DECREF (err_class);
				}
				return NULL;
			}
		}
		else if (0xDC00 <= buffer[ii] && buffer[ii] <= 0xDFFF)
		{	
			PyObject *err_class, *err_tmpl, *err_tmpl_args, *err_msg = NULL;
			
			if ((err_tmpl = PyString_FromString ("Cannot serialize reserved code point U+%04X.")))
			{
				if ((err_tmpl_args = Py_BuildValue ("(k)", buffer[ii])))
				{
					err_msg = PyString_Format (err_tmpl, err_tmpl_args);
					Py_DECREF (err_tmpl_args);
				}
				Py_DECREF (err_tmpl);
			}
			if (!err_msg) return NULL;
			
			if ((err_class = get_WriteError ()))
			{
				PyErr_SetObject (err_class,err_msg);
				Py_DECREF (err_class);
			}
			Py_DECREF (err_msg);
			return NULL;
		}
	}
	
	if (ascii_only)
		return unicode_to_ascii (unicode);
	return unicode_to_unicode (unicode);
}

static int
write_sequence_impl (PyObject *seq, PyObject *pieces,
                     PyObject *start, PyObject *end,
                     PyObject *pre_value, PyObject *post_value,
                     int sort_keys, PyObject *indent_string,
                     int ascii_only, int coerce_keys, int indent_level)
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
		
		serialized = json_write (item, sort_keys, indent_string,
		                         ascii_only, coerce_keys,
		                         indent_level + 1);
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
write_iterable (PyObject *iter, int sort_keys, PyObject *indent_string,
                int ascii_only, int coerce_keys, int indent_level)
{
	PyObject *sequence, *pieces;
	PyObject *start, *end, *pre, *post;
	int has_parents, succeeded;
	
	/* Guard against infinite recursion */
	has_parents = Py_ReprEnter (iter);
	if (has_parents > 0)
	{
		PyObject *err_class;
		if ((err_class = get_WriteError ()))
		{
			PyErr_SetString (err_class,
			                 "Cannot serialize self-referential"
			                 " values.");
			Py_DECREF (err_class);
		}
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
	get_separators (indent_string, indent_level, '[', ']',
	                &start, &end, &pre, &post);
	
	succeeded = write_sequence_impl (sequence, pieces, start, end, pre, post,
	                                 sort_keys, indent_string, ascii_only,
	                                 coerce_keys, indent_level);
	
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
mapping_get_key_and_value (PyObject *item, PyObject **key_ptr,
                           PyObject **value_ptr, int coerce_keys, int ascii_only)
{
	PyObject *key, *value;
	
	(*key_ptr) = NULL;
	(*value_ptr) = NULL;
	
	if (!(key = PySequence_GetItem (item, 0)))
		return FALSE;
	
	if (!(PyString_Check (key) || PyUnicode_Check (key)))
	{
		if (coerce_keys)
		{
			PyObject *new_key = NULL;
			if (!(new_key = write_basic (key, ascii_only)))
			{	
				PyObject *us_error;
				PyObject *exc_type, *exc_value, *exc_traceback;
				PyErr_Fetch (&exc_type, &exc_value, &exc_traceback);
				
				if ((us_error = get_UnknownSerializerError ()))
				{
					int is_us_error;
					
					PyErr_Restore (exc_type, exc_value, exc_traceback);
					is_us_error = PyErr_ExceptionMatches (us_error);
					Py_DECREF (us_error);
					
					if (is_us_error)
					{
						PyErr_Clear ();
						new_key = PyObject_Unicode (key);
					}
				}
			}
			
			Py_DECREF (key);
			if (!new_key) return FALSE;
			key = new_key;
		}
		else
		{
			PyObject *err_class;
			Py_DECREF (key);
			
			if ((err_class = get_WriteError ()))
			{
				PyErr_SetString (err_class,
				                 "Only strings may be used"
				                 " as object keys.");
				Py_DECREF (err_class);
			}
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
			PyObject *err_class;
			if ((err_class = get_WriteError ()))
			{
				PyErr_SetString (err_class,
				                 "Cannot serialize"
				                 " self-referential values.");
				Py_DECREF (err_class);
			}
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

static int
check_valid_number (PyObject *serialized)
{
	PyObject *cmp_str;
	int invalid;
	
	cmp_str = PyString_InternFromString ("Infinity");
	invalid = PyObject_RichCompareBool (cmp_str, serialized, Py_NE);
	Py_DECREF (cmp_str);
	if (invalid < 1) return invalid;
	
	cmp_str = PyString_InternFromString ("-Infinity");
	invalid = PyObject_RichCompareBool (cmp_str, serialized, Py_NE);
	Py_DECREF (cmp_str);
	if (invalid < 1) return invalid;
	
	cmp_str = PyString_InternFromString ("NaN");
	invalid = PyObject_RichCompareBool (cmp_str, serialized, Py_NE);
	Py_DECREF (cmp_str);
	if (invalid < 1) return invalid;
	
	return TRUE;
}

static PyObject *
write_basic (PyObject *value, int ascii_only)
{
	PyObject *Decimal, *UserString;
	int is_decimal = -1, is_userstring = -1;
	
	if (value == Py_True)
		return PyString_FromString ("true");
	if (value == Py_False)
		return PyString_FromString ("false");
	if (value == Py_None)
		return PyString_FromString ("null");
	
	if (PyString_Check (value))
		return write_string (value, ascii_only);
	if (PyUnicode_Check (value))
		return write_unicode (value, ascii_only);
	if (PyInt_Check (value) || PyLong_Check (value))
		return PyObject_Str(value);
	if (PyComplex_Check (value))
	{	
		PyObject *err_class;
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
		if ((err_class = get_WriteError ()))
		{
			PyErr_SetString (err_class, "Cannot serialize complex"
			                            " numbers with imaginary"
			                            " components.");
			Py_DECREF (err_class);
		}
		return NULL;
	}
	
	if (PyFloat_Check (value))
	{
		double val = PyFloat_AS_DOUBLE (value);
		if (Py_IS_NAN (val))
		{
			PyObject *err_class;
			if ((err_class = get_WriteError ()))
			{
				PyErr_SetString (err_class,
				                 "Cannot serialize NaN.");
				Py_DECREF (err_class);
			}
			return NULL;
		}
		
		if (Py_IS_INFINITY (val))
		{
			PyObject *err_class;
			const char *msg;
			if (val > 0)
				msg = "Cannot serialize Infinity.";
			else
				msg = "Cannot serialize -Infinity.";
			
			if ((err_class = get_WriteError ()))
			{
				PyErr_SetString (err_class, msg);
				Py_DECREF (err_class);
			}
			return NULL;
		}
		
		return PyObject_Repr (value);
	}
	
	if ((Decimal = get_Decimal ()))
	{
		is_decimal = PyObject_IsInstance (value, Decimal);
		Py_DECREF (Decimal);
	}
	if (is_decimal == -1) return NULL;
	
	if (is_decimal)
	{
		PyObject *serialized = PyObject_Str (value);
		int valid;
		
		valid = check_valid_number (serialized);
		if (valid == TRUE)
			return serialized;
		
		if (valid == FALSE)
		{
			PyObject *err_class;
			if ((err_class = get_WriteError ()))
			{
				PyErr_Format (err_class, "Cannot serialize %s.",
				              PyString_AsString (serialized));
				Py_DECREF (err_class);
			}
		}
		/* else valid == -1, error */
		Py_DECREF (serialized);
		return NULL;
	}
	
	if ((UserString = get_UserString ()))
	{
		is_userstring = PyObject_IsInstance (value, UserString);
		Py_DECREF (UserString);
	}
	if (is_userstring == -1) return NULL;
	
	if (is_userstring)
	{
		PyObject *repr, *retval;
		if (!(repr = PyObject_Str (value)))
			return NULL;
		retval = write_string (repr, ascii_only);
		Py_DECREF (repr);
		return retval;
	}
	
	{
		PyObject *err_class;
		if ((err_class = get_UnknownSerializerError ()))
		{
			PyErr_SetObject (err_class, value);
			Py_DECREF (err_class);
		}
		
	}
	
	return NULL;
}

static PyObject*
json_write (PyObject *object, int sort_keys, PyObject *indent_string,
            int ascii_only, int coerce_keys, int indent_level)
{
	PyObject *retval = NULL, *pieces;
	if (PyList_Check (object) || PyTuple_Check (object))
	{
		pieces = write_iterable (object, sort_keys, indent_string,
		                         ascii_only, coerce_keys,
		                         indent_level);
	}
	
	else if (PyObject_HasAttrString (object, "items"))
	{
		pieces = write_mapping (object, sort_keys, indent_string,
		                        ascii_only, coerce_keys,
		                        indent_level);
	}
	
	else
	{
		PyObject *UnknownSerializerError;
		if (!(UnknownSerializerError = get_UnknownSerializerError ()))
			return NULL;
		pieces = write_basic (object, ascii_only);
		if (pieces && indent_level == 0)
		{	
			PyObject *err_class;
			Py_DECREF (pieces);
			pieces = NULL;
			
			if ((err_class = get_WriteError ()))
			{
				PyErr_SetString (err_class,
				                 "The outermost container"
				                 " must be an array or"
				                 " object.");
				Py_DECREF (err_class);
			}
		}
		if (!pieces && PyErr_ExceptionMatches (UnknownSerializerError))
		{
			PyObject *iter;
			
			/* Used when testing for iterability */
			PyObject *exc_type, *exc_value, *exc_traceback;
			
			if (PySequence_Check (object))
			{
				PyErr_Clear ();
				pieces = write_iterable (object, sort_keys, indent_string,
				                         ascii_only, coerce_keys,
				                         indent_level);
			}
			
			PyErr_Fetch (&exc_type, &exc_value, &exc_traceback);
			iter = PyObject_GetIter (object);
			PyErr_Restore (exc_type, exc_value, exc_traceback);
			if (iter)
			{
				PyErr_Clear ();
				pieces = write_iterable (iter, sort_keys, indent_string,
				                         ascii_only, coerce_keys,
				                         indent_level);
				Py_DECREF (iter);
			}
		}
		Py_DECREF (UnknownSerializerError);
	}
	
	if (pieces)
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
	Py_InitModule3 ("_writer", writer_methods, module_doc);
}
