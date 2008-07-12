/**
 * Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
 * Author: John Millikin <jmillikin@gmail.com>
 * 
 * Implementation of jsonlib.
**/

/* includes {{{ */
#include <Python.h>
#include <stddef.h>
#include <stdio.h>
#include <ctype.h>
#include <math.h>

#define FALSE 0
#define TRUE 1

#if PY_VERSION_HEX < 0x02050000
typedef int Py_ssize_t;
#endif
/* }}} */

/* util declarations {{{ */
static PyObject *
jsonlib_import (const char *module_name, const char *obj_name);

static PyObject *
jsonlib_str_format (const char *tmpl, PyObject *args);

static Py_ssize_t
next_power_2 (Py_ssize_t start, Py_ssize_t min);
/* }}} */

/* parser declarations {{{ */
enum
{
	UTF_8 = 0,
	UTF_8_BOM,
	UTF_16_LE,
	UTF_16_LE_BOM,
	UTF_16_BE,
	UTF_16_BE_BOM,
	UTF_32_LE,
	UTF_32_LE_BOM,
	UTF_32_BE,
	UTF_32_BE_BOM
};

#define BOM_UTF8     "\xef\xbb\xbf"
#define BOM_UTF16_LE "\xff\xfe"
#define BOM_UTF16_BE "\xfe\xff"
#define BOM_UTF32_LE "\xff\xfe\x00\x00"
#define BOM_UTF32_BE "\x00\x00\xfe\xff"

typedef struct _ParserState {
	Py_UNICODE *start;
	Py_UNICODE *end;
	Py_UNICODE *index;
	PyObject *Decimal;
} ParserState;

typedef enum
{
	ARRAY_EMPTY,
	ARRAY_NEED_VALUE,
	ARRAY_GOT_VALUE
} ParseArrayState;

typedef enum
{
	OBJECT_EMPTY,
	OBJECT_NEED_KEY,
	OBJECT_GOT_VALUE
} ParseObjectState;

static PyObject *ReadError;

static PyObject *read_keyword (ParserState *state);
static PyObject *read_string (ParserState *state);
static PyObject *read_number (ParserState *state);
static PyObject *read_array (ParserState *state);
static PyObject *read_object (ParserState *state);
static PyObject *json_read (ParserState *state);
/* }}} */

/* serializer declarations {{{ */
typedef struct _WriterState
{
	/* Pulled from the current interpreter to avoid errors when used
	 * with sub-interpreters.
	**/
	PyObject *Decimal;
	PyObject *UserString;
	
	/* Options passed to _write */
	int sort_keys;
	PyObject *indent_string;
	int ascii_only;
	int coerce_keys;
	PyObject *on_unknown;
	
	Py_UNICODE *buffer;
	Py_ssize_t buffer_size;
	Py_ssize_t buffer_max_size;
	
	/* Constants, saved to avoid lookup later */
	PyObject *true_str;
	PyObject *false_str;
	PyObject *null_str;
	PyObject *inf_str;
	PyObject *neg_inf_str;
	PyObject *nan_str;
	PyObject *quote;
	PyObject *colon;
} WriterState;

static const char *hexdigit = "0123456789abcdef";
#define INITIAL_BUFFER_SIZE 32

static PyObject *WriteError;
static PyObject *UnknownSerializerError;

static int
writer_buffer_resize (WriterState *state, Py_ssize_t delta);

static PyObject *
writer_buffer_get (WriterState *state);

static void
writer_buffer_clear (WriterState *state);

static int
writer_append_ascii (WriterState *state, const char *text);

static int
writer_append_unicode (WriterState *state, Py_UNICODE *text, Py_ssize_t len);

static int
writer_append_unicode_obj (WriterState *state, PyObject *text);

static int
writer_append_chunks (WriterState *state, PyObject *list);


static PyObject *
unicode_from_ascii (const char *value);

static int
write_object (WriterState *state, PyObject *object, int indent_level);

static int
write_iterable (WriterState *state, PyObject *iterable, int indent_level);

static int
write_mapping (WriterState *state, PyObject *mapping, int indent_level);

static PyObject *
write_basic (WriterState *state, PyObject *value);

static PyObject *
write_string (WriterState *state, PyObject *string);

static PyObject *
write_unicode (WriterState *state, PyObject *unicode);

static PyObject *
unicode_to_unicode (PyObject *unicode);

static PyObject *
unicode_to_ascii (PyObject *unicode);
/* }}} */

/* util function definitions {{{ */
static PyObject *
jsonlib_import (const char *module_name, const char *obj_name)
{
	PyObject *module, *obj = NULL;
	if ((module = PyImport_ImportModule (module_name)))
	{
		obj = PyObject_GetAttrString (module, obj_name);
		Py_DECREF (module);
	}
	return obj;
}

static PyObject *
jsonlib_str_format (const char *c_tmpl, PyObject *args)
{
	PyObject *template, *retval;
	
	if (!args) return NULL;
	if (!(template = PyString_FromString (c_tmpl))) return NULL;
	retval = PyString_Format (template, args);
	Py_DECREF (template);
	Py_DECREF (args);
	return retval;
}

static Py_ssize_t
next_power_2 (Py_ssize_t start, Py_ssize_t min)
{
	while (start < min) start <<= 1;
	return start;
}
/* }}} */

/* parser {{{ */
static void
skip_spaces (ParserState *state)
{
	/* Don't use Py_UNICODE_ISSPACE, because it returns TRUE for
	 * codepoints that are not valid JSON whitespace.
	**/
	Py_UNICODE c;
	while ((c = (*state->index)) && (
	        c == '\x09' ||
	        c == '\x0A' ||
	        c == '\x0D' ||
	        c == '\x20'
	))
		state->index++;
}

static Py_UCS4
next_ucs4 (ParserState *state, Py_UNICODE *index)
{
	unsigned long value = index[0];
	if (value >= 0xD800 && value <= 0xDBFF)
	{
		unsigned long upper = value, lower = index[1];
		
		if (lower)
		{
			upper -= 0xD800;
			lower -= 0xDC00;
			value = ((upper << 10) + lower) + 0x10000;
		}
	}
	return value;
}

static void
count_row_column (Py_UNICODE *start, Py_UNICODE *pos, unsigned long *offset,
                  unsigned long *row, unsigned long *column)
{
	Py_UNICODE *ptr;
	*offset = (pos - start);
	*row = 1;
	
	/* Count newlines in chars <= pos */
	for (ptr = start; ptr && ptr <= pos; ptr++)
	{
		if (*ptr == '\n') (*row)++;
	}
	ptr--;
	
	/* Loop backwards to find the column */
	while (ptr > start && *ptr != '\n') ptr--;
	*column = (pos - ptr);
	if (*row == 1) (*column)++;
}

static void
set_error (ParserState *state, Py_UNICODE *position, PyObject *description,
           PyObject *description_args)
{
	const char *tmpl = "JSON parsing error at line %d, column %d"
	                   " (position %d): %s";
	unsigned long row, column, char_offset;
	PyObject *err_str, *err_str_tmpl, *err_format_args;
	
	Py_INCREF (description);
	
	if (description_args)
	{
		PyObject *new_desc;
		new_desc = PyString_Format (description, description_args);
		Py_DECREF (description);
		if (!new_desc) return;
		description = new_desc;
	}
	
	count_row_column (state->start, position, &char_offset,
	                  &row, &column);
	
	err_str_tmpl = PyString_FromString (tmpl);
	if (err_str_tmpl)
	{
		err_format_args = Py_BuildValue ("(kkkO)", row, column,
		                                 char_offset, description);
		if (err_format_args)
		{
			err_str = PyString_Format (err_str_tmpl, err_format_args);
			if (err_str)
			{
				PyErr_SetObject (ReadError, err_str);
				Py_DECREF (err_str);
			}
			Py_DECREF (err_format_args);
		}
		Py_DECREF (err_str_tmpl);
	}
	Py_DECREF (description);
}

static void
set_error_simple (ParserState *state, Py_UNICODE *position,
                  const char *description)
{
	PyObject *desc_obj;
	desc_obj = PyString_FromString (description);
	if (desc_obj)
	{
		set_error (state, position, desc_obj, NULL);
		Py_DECREF (desc_obj);
	}
}

static void
set_error_unexpected (ParserState *state, Py_UNICODE *position)
{
	PyObject *err_str, *err_format_args;
	Py_UCS4 c = next_ucs4 (state, position);
	
	if (c > 0xFFFF)
		err_str = PyString_FromString ("Unexpected U+%08X.");
	else
		err_str = PyString_FromString ("Unexpected U+%04X.");
	
	if (err_str)
	{
		err_format_args = Py_BuildValue ("(k)", c);
		if (err_format_args)
		{
			set_error (state, position, err_str, err_format_args);
			Py_DECREF (err_format_args);
		}
		Py_DECREF (err_str);
	}
}

/* Helper function to create a new decimal.Decimal object */
static PyObject *
make_Decimal (ParserState *state, PyObject *string)
{
	PyObject *args, *retval = NULL;
	
	if ((args = PyTuple_Pack (1, string)))
	{
		retval = PyObject_CallObject (state->Decimal, args);
		Py_DECREF (args);
	}
	return retval;
}

/* Helper function to perform strncmp between Py_UNICODE and char* */
static int
unicode_utf8_strncmp (Py_UNICODE *unicode, const char *utf8, Py_ssize_t count)
{
	PyObject *str;
	char *c_str;
	int retval = -1;
	
	str = PyUnicode_EncodeUTF8 (unicode, count, "strict");
	if (str)
	{
		c_str = PyString_AsString (str);
		if (c_str)
		{
			retval = strncmp (c_str, utf8, count);
		}
		Py_DECREF (str);
	}
	
	return retval;
}

static PyObject *
keyword_compare (ParserState *state, const char *expected, PyObject *retval)
{
	size_t left, len = strlen (expected);
	
	left = state->end - state->index;
	
	if (left >= len &&
	    unicode_utf8_strncmp (state->index, expected, len) == 0)
	{
		state->index += len;
		Py_INCREF (retval);
		return retval;
	}
	return NULL;
}

static PyObject *
read_keyword (ParserState *state)
{
	PyObject *retval;
	
	if ((retval = keyword_compare (state, "null", Py_None)))
		return retval;
	if ((retval = keyword_compare (state, "true", Py_True)))
		return retval;
	if ((retval = keyword_compare (state, "false", Py_False)))
		return retval;
	
	set_error_unexpected (state, state->index);
	return NULL;
}

static int
read_4hex (Py_UNICODE *start, Py_UNICODE *retval_ptr)
{
	PyObject *py_long;
	
	py_long = PyLong_FromUnicode (start, 4, 16);
	if (!py_long) return FALSE;
	
	(*retval_ptr) = (Py_UNICODE) (PyLong_AsUnsignedLong (py_long));
	Py_DECREF (py_long);
	return TRUE;
}

static int
read_unicode_escape (ParserState *state, Py_UNICODE *string_start,
                     Py_UNICODE *buffer, Py_ssize_t *buffer_idx,
                     Py_ssize_t *index_ptr, Py_ssize_t max_char_count)
{
	Py_ssize_t remaining;
	Py_UNICODE value;
	
	(*index_ptr)++;
	
	remaining = max_char_count - (*index_ptr);
	
	if (remaining < 4)
	{
		set_error_simple (state, state->index + (*index_ptr) - 1,
		                  "Unterminated unicode escape.");
		return FALSE;
	}
	
	if (!read_4hex (string_start + (*index_ptr), &value))
		return FALSE;
		
	(*index_ptr) += 4;
	
	/* Check for surrogate pair */
	if (0xD800 <= value && value <= 0xDBFF)
	{
		Py_UNICODE upper = value, lower;
		
		if (remaining < 10)
		{
			set_error_simple (state, state->index + (*index_ptr) + 1,
			                  "Missing surrogate pair half.");
			return FALSE;
		}
		
		if (string_start[(*index_ptr)] != '\\' ||
		    string_start[(*index_ptr) + 1] != 'u')
		{
			set_error_simple (state, state->index + (*index_ptr) + 1,
			                  "Missing surrogate pair half.");
			return FALSE;
		}
		(*index_ptr) += 2;
		
		if (!read_4hex (string_start + (*index_ptr), &lower))
			return FALSE;
			
		(*index_ptr) += 4;
		
#		ifdef Py_UNICODE_WIDE
			upper -= 0xD800;
			lower -= 0xDC00;
			
			/* Merge upper and lower components */
			value = ((upper << 10) + lower) + 0x10000;
			buffer[*buffer_idx] = value;
#		else
			/* No wide character support, return surrogate pairs */
			buffer[(*buffer_idx)++] = upper;
			buffer[*buffer_idx] = lower;
#		endif
	}
	else if (0xDC00 <= value && value <= 0xDFFF)
	{
		PyObject *err_str, *err_format_args;
		Py_UNICODE *position = state->index + (*index_ptr) - 5;

		err_str = PyString_FromString ("U+%04X is a reserved code point.");

		if (err_str)
		{
			err_format_args = Py_BuildValue ("(k)", value);
			if (err_format_args)
			{
				set_error (state, position, err_str, err_format_args);
				Py_DECREF (err_format_args);
			}
			Py_DECREF (err_str);
		}
		return FALSE;
	}
	else
	{
		buffer[*buffer_idx] = value;
	}
	return TRUE;
}

static PyObject *
read_string (ParserState *state)
{
	PyObject *unicode;
	int escaped = FALSE;
	Py_UNICODE c, *buffer, *start;
	Py_ssize_t ii, max_char_count, buffer_idx;
	
	/* Start at 1 to skip first double quote. */
	start = state->index + 1;
	
	/* Scan through for maximum character count, and to ensure the string
	 * is terminated.
	**/
	for (ii = 0;; ii++)
	{
		c = start[ii];
		if (c == 0)
		{
			set_error_simple (state, state->index,
			                  "Unterminated string.");
			return NULL;
		}
		
		/* Check for illegal characters */
		if (c < 0x20)
		{
			set_error_unexpected (state, start + ii);
			return NULL;
		}
		
		if (escaped)
		{
			/* Invalid escape codes will be caught
			 * later.
			**/
			escaped = FALSE;
		}
		
		else
		{	if (c == '\\') escaped = TRUE;
			else if (c == '"') break;
		}
	}
	
	/* Allocate enough to hold the worst case */
	max_char_count = ii;
	buffer = PyMem_New (Py_UNICODE, max_char_count);
	
	/* Scan through the string, adding values to the buffer as
	 * appropriate.
	**/
	escaped = FALSE;
	buffer_idx = 0;
	for (ii = 0; ii < max_char_count; ii++)
	{
		c = start[ii];
		assert (c != 0);
		
		if (escaped)
		{
			switch (c)
			{
				case '\\':
				case '"':
				case '/':
					buffer[buffer_idx] = c;
					break;
				case 'b': buffer[buffer_idx] = 0x08; break;
				case 'f': buffer[buffer_idx] = 0x0C; break;
				case 'n': buffer[buffer_idx] = 0x0A; break;
				case 'r': buffer[buffer_idx] = 0x0D; break;
				case 't': buffer[buffer_idx] = 0x09; break;
				case 'u':
				{
					Py_ssize_t next_ii = ii;
					if (read_unicode_escape (state, start,
					                         buffer,
					                         &buffer_idx,
					                         &next_ii,
					                         max_char_count))
					{
						ii = next_ii - 1;
					}
					
					else
					{
						PyMem_Free (buffer);
						return NULL;
					}
					break;
				}
				
				default:
				{
					set_error_simple (state, start + ii - 1,
					                  "Unknown escape code.");
					PyMem_Free (buffer);
					return NULL;
				}
			}
			escaped = FALSE;
			buffer_idx += 1;
		}
		
		else
		{
			if (c == '\\') escaped = TRUE;
			else if (c == '"') break;
			else
			{
				buffer[buffer_idx] = c;
				buffer_idx += 1;
			}
		}
	}
	
	unicode = PyUnicode_FromUnicode (buffer, buffer_idx);
	PyMem_Free (buffer);
	
	if (unicode)
	{
		state->index = start + max_char_count + 1;
	}
	
	return unicode;
}

static PyObject *
read_number (ParserState *state)
{
	PyObject *object = NULL;
	int is_float = FALSE, should_stop = FALSE, got_digit = FALSE,
	    leading_zero = FALSE, has_exponent = FALSE;
	Py_UNICODE *ptr, c;
	
	ptr = state->index;
	
	while ((c = *ptr))
	{
		switch (c) {
		case '0':
			if (!got_digit)
			{
				leading_zero = TRUE;
			}
			else if (leading_zero && !is_float)
			{
				set_error_simple (state, state->index,
				                  "Number with leading zero.");
				return NULL;
			}
			got_digit = TRUE;
			break;
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			if (leading_zero && !is_float)
			{
				set_error_simple (state, state->index,
				                  "Number with leading zero.");
				return NULL;
			}
			got_digit = TRUE;
			break;
		case '-':
		case '+':
			break;
		case 'e':
		case 'E':
			has_exponent = TRUE;
			break;
		case '.':
			is_float = TRUE;
			got_digit = FALSE;
			break;
		default:
			should_stop = TRUE;
		}
		if (should_stop) {
			break;
		}
		ptr++;
	}
	
	if (got_digit)
	{
		if (is_float || has_exponent)
		{
			PyObject *str, *unicode;
			if (!(unicode = PyUnicode_FromUnicode (state->index,
			                                      ptr - state->index)))
				return NULL;
			str = PyUnicode_AsUTF8String (unicode);
			Py_DECREF (unicode);
			if (!str) return NULL;
			object = make_Decimal (state, str);
			Py_DECREF (str);
		}
		
		else
		{
			object = PyLong_FromUnicode (state->index,
			                             ptr - state->index, 10);
		}
	}
	
	if (object == NULL)
	{
		set_error_simple (state, state->index, "Invalid number.");
		return NULL;
	}
	
	state->index = ptr;
	return object;
}

static int
read_array_impl (PyObject *list, ParserState *state)
{
	Py_UNICODE *start, c;
	ParseArrayState array_state = ARRAY_EMPTY;
	
	start = state->index;
	state->index++;
	while (TRUE)
	{
		skip_spaces (state);
		c = *state->index;
		if (c == 0)
		{
			set_error_simple (state, state->index,
			                  "Unterminated array.");
			return FALSE;
		}
		
		else if (c == ']')
		{
			if (array_state == ARRAY_NEED_VALUE)
			{
				set_error_simple (state, state->index,
				                  "Expecting array item.");
				return FALSE;
			}
			state->index++;
			return TRUE;
		}
		
		else if (c == ',')
		{
			if (array_state != ARRAY_GOT_VALUE)
			{
				set_error_simple (state, state->index,
				                  "Expecting array item.");
				return FALSE;
			}
			array_state = ARRAY_NEED_VALUE;
			state->index++;
		}
		
		else
		{
			PyObject *value;
			int result;
			
			if (array_state == ARRAY_GOT_VALUE)
			{
				set_error_simple (state, state->index,
				                  "Expecting comma.");
				return FALSE;
			}
			
			if (!(value = json_read (state)))
				return FALSE;
			
			result  = PyList_Append (list, value);
			Py_DECREF (value);
			if (result == -1)
				return FALSE;
			
			array_state = ARRAY_GOT_VALUE;
		}
	}
}

static PyObject *
read_array (ParserState *state)
{
	PyObject *object = PyList_New (0);
	
	if (!read_array_impl (object, state))
	{
		Py_DECREF (object);
		return NULL;
	}
	
	return object;
}

static int
read_object_impl (PyObject *object, ParserState *state)
{
	Py_UNICODE *start, c;
	ParseObjectState object_state = OBJECT_EMPTY;
	
	start = state->index;
	state->index++;
	while (TRUE)
	{
		skip_spaces (state);
		c = *state->index;
		if (c == 0)
		{
			set_error_simple (state, start,
			                  "Unterminated object.");
			return FALSE;
		}
		
		else if (c == '}')
		{
			if (object_state == OBJECT_NEED_KEY)
			{
				set_error_simple (state, state->index,
				                  "Expecting property name.");
				return FALSE;
			}
			state->index++;
			return TRUE;
		}
		
		else if (c == ',')
		{
			if (object_state != OBJECT_GOT_VALUE)
			{
				set_error_simple (state, state->index,
				                  "Expecting property name.");
				return FALSE;
			}
			object_state = OBJECT_NEED_KEY;
			state->index++;
		}
		
		else if (c == '"')
		{
			PyObject *key, *value;
			int result;
			
			if (object_state == OBJECT_GOT_VALUE)
			{
				set_error_simple (state, state->index,
				                  "Expecting comma.");
				return FALSE;
			}
			
			if (!(key = json_read (state)))
				return FALSE;
			
			skip_spaces (state);
			if (*state->index != ':')
			{
				set_error_simple (state, state->index,
				                  "Expected colon after object"
				                  " property name.");
				Py_DECREF (key);
				return FALSE;
			}
			
			state->index++;
			if (!(value = json_read (state)))
			{
				Py_DECREF (key);
				return FALSE;
			}
			
			result = PyDict_SetItem (object, key, value);
			Py_DECREF (key);
			Py_DECREF (value);
			if (result == -1)
				return FALSE;
			
			object_state = OBJECT_GOT_VALUE;
		}
		
		else
		{
			set_error_simple (state, state->index,
			                  "Expecting property name.");
			return FALSE;
		}
	}
}

static PyObject *
read_object (ParserState *state)
{
	PyObject *object = PyDict_New ();
	
	if (!read_object_impl (object, state))
	{
		Py_DECREF (object);
		return NULL;
	}
	
	return object;
}

static PyObject *
json_read (ParserState *state)
{
	skip_spaces (state);
	switch (*state->index)
	{
		case 0:
			set_error_simple (state, state->start,
			                  "No expression found.");
			return NULL;
		case '{':
			return read_object (state);
		case '[':
			return read_array (state);
		case '"':
			return read_string (state);
		case 't':
		case 'f':
		case 'n':
			return read_keyword (state);
		case '-':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			return read_number (state);
		default:
			set_error_unexpected (state, state->index);
			return NULL;
	}
}

static int
detect_encoding (const char *const bytes, Py_ssize_t size)
{
	/* 4 is the minimum size of a JSON expression encoded without UTF-8. */
	if (size < 4) { return UTF_8; }
	
	if (memcmp (bytes, BOM_UTF8, 3) == 0) return UTF_8_BOM;
	if (memcmp (bytes, BOM_UTF32_LE, 4) == 0) return UTF_32_LE_BOM;
	if (memcmp (bytes, BOM_UTF32_BE, 4) == 0) return UTF_32_BE_BOM;
	if (memcmp (bytes, BOM_UTF16_LE, 2) == 0) return UTF_16_LE_BOM;
	if (memcmp (bytes, BOM_UTF16_BE, 2) == 0) return UTF_16_BE_BOM;
	
	/* No BOM found. Examine the byte patterns of the first four
	 * characters.
	**/
	if (bytes[0] && !bytes[1] && bytes[2] && !bytes[3])
		return UTF_16_LE;
	
	if (!bytes[0] && bytes[1] && !bytes[2] && bytes[3])
		return UTF_16_BE;
	
	if (bytes[0] && !bytes[1] && !bytes[2] && !bytes[3])
		return UTF_32_LE;
	
	if (!bytes[0] && !bytes[1] && !bytes[2] && bytes[3])
		return UTF_32_BE;
	
	/* Default to UTF-8. */
	return UTF_8;
}

/**
 * Intelligently convert a byte string to Unicode.
 * 
 * Assumes the encoding used is one of the UTF-* variants. If the
 * input is already in unicode, this is a noop.
**/
static PyObject *
unicode_autodetect (PyObject *bytestring)
{
	PyObject *u = NULL;
	char *bytes;
	Py_ssize_t byte_count;
	
	bytes = PyString_AS_STRING (bytestring);
	byte_count = PyString_GET_SIZE (bytestring);
	switch (detect_encoding (bytes, byte_count))
	{
	case UTF_8:
		u = PyUnicode_Decode (bytes, byte_count, "utf-8", "strict");
		break;
	case UTF_8_BOM:
		/* 3 = sizeof UTF-8 BOM */
		u = PyUnicode_Decode (bytes + 3, byte_count - 3, "utf-8", "strict");
		break;
	case UTF_16_LE:
		u = PyUnicode_Decode (bytes, byte_count, "utf-16-le", "strict");
		break;
	case UTF_16_LE_BOM:
		u = PyUnicode_Decode (bytes + 2, byte_count - 2, "utf-16-le", "strict");
		break;
	case UTF_16_BE:
		u = PyUnicode_Decode (bytes, byte_count, "utf-16-be", "strict");
		break;
	case UTF_16_BE_BOM:
		u = PyUnicode_Decode (bytes + 2, byte_count - 2, "utf-16-be", "strict");
		break;
	case UTF_32_LE:
		u = PyUnicode_Decode (bytes, byte_count, "utf-32-le", "strict");
		break;
	case UTF_32_LE_BOM:
		u = PyUnicode_Decode (bytes + 4, byte_count - 4, "utf-32-le", "strict");
		break;
	case UTF_32_BE:
		u = PyUnicode_Decode (bytes, byte_count, "utf-32-be", "strict");
		break;
	case UTF_32_BE_BOM:
		u = PyUnicode_Decode (bytes + 4, byte_count - 4, "utf-32-be", "strict");
		break;
	}
	return u;
}

/* Parses the argument list to _read(), automatically converting from
 * a UTF-* encoded bytestring to unicode if needed.
**/
static int
parse_unicode_arg (PyObject *args, PyObject *kwargs, PyObject **unicode)
{
	int retval;
	PyObject *bytestring;
	PyObject *exc_type, *exc_value, *exc_traceback;
	
	static char *kwlist[] = {"string", NULL};
	
	/* Try for the common case of a direct unicode string. */
	retval = PyArg_ParseTupleAndKeywords (args, kwargs, "U:read",
	                                      kwlist, unicode);
	if (retval)
	{
		Py_INCREF (*unicode);
		return retval;
	}
	
	/* Might have been passed a string. Try to autodecode it. */
	PyErr_Fetch (&exc_type, &exc_value, &exc_traceback);
	retval = PyArg_ParseTupleAndKeywords (args, kwargs, "S:read",
	                                      kwlist, &bytestring);
	if (!retval)
	{
		PyErr_Restore (exc_type, exc_value, exc_traceback);
		return retval;
	}
	
	*unicode = unicode_autodetect (bytestring);
	if (!(*unicode)) return 0;
	return 1;
}

static PyObject*
_read_entry (PyObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject *result = NULL, *unicode;
	ParserState state = {NULL};
	
	if (!parse_unicode_arg (args, kwargs, &unicode))
		return NULL;
	
	state.start = PyUnicode_AsUnicode (unicode);
	state.end = state.start + PyUnicode_GetSize (unicode);
	state.index = state.start;
	
	if ((state.Decimal = jsonlib_import ("decimal", "Decimal")))
	{
		result = json_read (&state);
	}
	
	Py_XDECREF (state.Decimal);
	
	if (result)
	{
		skip_spaces (&state);
		if (state.index < state.end)
		{
			set_error_simple (&state, state.index,
			                  "Extra data after JSON expression.");
			Py_DECREF (result);
			result = NULL;
		}
	}
	Py_DECREF (unicode);
	
	return result;
}
/* }}} */

/* serializer {{{ */
static int
writer_buffer_resize (WriterState *state, Py_ssize_t delta)
{
	Py_ssize_t new_size;
	if (!state->buffer)
	{
		new_size = (delta > INITIAL_BUFFER_SIZE? delta : INITIAL_BUFFER_SIZE);
		new_size = next_power_2 (1, new_size);
		state->buffer = PyMem_Malloc (sizeof (Py_UNICODE) * new_size);
		state->buffer_max_size = new_size;
		return TRUE;
	}
	
	new_size = state->buffer_size + delta;
	if (state->buffer_max_size < new_size)
	{
		Py_UNICODE *new_buf;
		new_size = next_power_2 (state->buffer_max_size, new_size);
		new_buf = PyMem_Realloc (state->buffer,
		                         sizeof (Py_UNICODE) * new_size);
		if (!new_buf)
		{
			writer_buffer_clear (state);
			return FALSE;
		}
		state->buffer = new_buf;
		state->buffer_max_size = new_size;
		return TRUE;
	}
	return TRUE;
}

static PyObject *
writer_buffer_get (WriterState *state)
{
	if (!state->buffer_size)
		return unicode_from_ascii ("");
	return PyUnicode_FromUnicode (state->buffer, state->buffer_size);
}

static void
writer_buffer_clear (WriterState *state)
{
	state->buffer_size = 0;
	state->buffer_max_size = 0;
	PyMem_Free (state->buffer);
	state->buffer = NULL;
}

static int
writer_append_ascii (WriterState *state, const char *text)
{
	Py_ssize_t ii, text_len = strlen (text);
	
	if (!writer_buffer_resize (state, text_len))
		return FALSE;
	for (ii = 0; ii < text_len; ii++)
	{
		state->buffer[state->buffer_size++] = text[ii];
	}
	return TRUE;
}

static int
writer_append_unicode (WriterState *state, Py_UNICODE *text, Py_ssize_t len)
{
	Py_ssize_t ii;
	if (!writer_buffer_resize (state, len))
		return FALSE;
	for (ii = 0; ii < len; ii++)
	{
		state->buffer[state->buffer_size++] = text[ii];
	}
	return TRUE;
}

static int
writer_append_unicode_obj (WriterState *state, PyObject *text)
{
	if (PyUnicode_CheckExact (text))
		return writer_append_unicode (state,
			PyUnicode_AS_UNICODE (text),
			PyUnicode_GET_SIZE (text)
		);
	if (PyString_CheckExact (text))
		return writer_append_ascii (state, PyString_AS_STRING (text));
	
	PyErr_SetString (PyExc_AssertionError, "type (text) in (str, unicode)");
	return FALSE;
}

static int
writer_append_chunks (WriterState *state, PyObject *list)
{
	Py_ssize_t ii, len;
	
	if (PyUnicode_CheckExact (list) || PyString_CheckExact (list))
		return writer_append_unicode_obj (state, list);
	
#ifdef DEBUG
	if (!PySequence_Check (list))
	{
		PyErr_SetString (PyExc_AssertionError, "is_sequence (seq)");
		return FALSE;
	}
#endif
	
	len = PySequence_Fast_GET_SIZE (list);
	for (ii = 0; ii < len; ++ii)
	{
		PyObject *item;
		if (!(item = PySequence_Fast_GET_ITEM (list, ii)))
			return FALSE;
		
		if (PyUnicode_CheckExact (item) || PyString_CheckExact (item))
			if (!writer_append_unicode_obj (state, item))
				return FALSE;
	}
	
	return TRUE;
}

static void
set_unknown_serializer (PyObject *value)
{
	PyObject *message;
	
	message = jsonlib_str_format ("No known serializer for object: %r",
	                              Py_BuildValue ("(O)", value));
	if (message)
	{
		PyErr_SetObject (UnknownSerializerError, message);
		Py_DECREF (message);
	}
}

static PyObject *
unicode_from_ascii (const char *value)
{
	PyObject *str, *retval;
	str = PyString_FromString (value);
	retval = PyUnicode_FromEncodedObject (str, "ascii", "strict");
	Py_DECREF (str);
	return retval;
}

static PyObject *
unicode_from_format (const char *format, ...)
{
	PyObject *retval, *string;
	va_list args;
	
	va_start (args, format);
	string = PyString_FromFormatV (format, args);
	va_end (args);
	
	if (!string) return NULL;
	retval = PyUnicode_FromObject (string);
	Py_DECREF (string);
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
		(*start_ptr) = PyString_FromStringAndSize (&start, 1);
		(*pre_value_ptr) = NULL;
		(*post_value_ptr) = PyString_FromStringAndSize (",", 1);
		(*end_ptr) = PyString_FromStringAndSize (&end, 1);
	}
	else
	{
		PyObject *format_args, *format_tmpl, *indent, *next_indent;
		char start_str[] = {0, '\n'};
		start_str[0] = start;
		
		(*start_ptr) = PyString_FromStringAndSize (start_str, 2);
		(*post_value_ptr) = PyString_FromStringAndSize (",\n", 2);
		
		indent = PySequence_Repeat (indent_string, indent_level + 1);
		(*pre_value_ptr) = indent;
		
		next_indent = PySequence_Repeat (indent_string, indent_level);
		format_args = Py_BuildValue ("(N)", next_indent);
		format_tmpl = unicode_from_format ("\n%%s%c", end);
		(*end_ptr) = PyUnicode_Format (format_tmpl, format_args);
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
				PyErr_SetString (WriteError,
				                 "Cannot serialize incomplete"
						 " surrogate pair.");
				return NULL;
			}
			else if (!(0xDC00 <= buffer[ii] && buffer[ii] <= 0xDFFF))
			{
				PyErr_SetString (WriteError,
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
				PyErr_SetObject (WriteError, err_msg);
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
write_sequence_impl (WriterState *state, PyObject *seq,
                     PyObject *start, PyObject *end,
                     PyObject *pre_value, PyObject *post_value,
                     int indent_level)
{
	Py_ssize_t ii;
	
	if (!writer_append_unicode_obj (state, start))
		return FALSE;
	
	/* Check size every loop because the sequence might be mutable */
	for (ii = 0; ii < PySequence_Fast_GET_SIZE (seq); ++ii)
	{
		PyObject *item;
		
		if (pre_value && !writer_append_unicode_obj (state, pre_value))
			return FALSE;
		
		if (!(item = PySequence_Fast_GET_ITEM (seq, ii)))
			return FALSE;
		
		if (!write_object (state, item, indent_level + 1))
			return FALSE;
		
		if (ii + 1 < PySequence_Fast_GET_SIZE (seq))
		{
			if (!writer_append_unicode_obj (state, post_value))
				return FALSE;
		}
	}
	
	return writer_append_unicode_obj (state, end);
}

static int
write_iterable (WriterState *state, PyObject *iter, int indent_level)
{
	PyObject *sequence;
	PyObject *start, *end, *pre, *post;
	int has_parents, succeeded;
	
	/* Guard against infinite recursion */
	has_parents = Py_ReprEnter (iter);
	if (has_parents > 0)
	{
		PyErr_SetString (WriteError,
		                 "Cannot serialize self-referential"
		                 " values.");
	}
	if (has_parents != 0) return FALSE;
	
	sequence = PySequence_Fast (iter, "Error converting iterable to sequence.");
	
	/* Shortcut for len (sequence) == 0 */
	if (PySequence_Fast_GET_SIZE (sequence) == 0)
	{
		Py_DECREF (sequence);
		Py_ReprLeave (iter);
		return writer_append_ascii (state, "[]");
	}
	
	/* Build separator strings */
	get_separators (state->indent_string, indent_level, '[', ']',
	                &start, &end, &pre, &post);
	
	succeeded = write_sequence_impl (state, sequence,
	                                 start, end, pre, post,
	                                 indent_level);
	
	Py_DECREF (sequence);
	Py_ReprLeave (iter);
	
	Py_XDECREF (start);
	Py_XDECREF (end);
	Py_XDECREF (pre);
	Py_XDECREF (post);
	return succeeded;
}

static int
mapping_process_key (WriterState *state, PyObject *key, PyObject **key_ptr)
{
	(*key_ptr) = NULL;
	
	if (PyString_Check (key) || PyUnicode_Check (key))
	{
		*key_ptr = key;
		return TRUE;
	}
	
	if (state->coerce_keys)
	{
		PyObject *new_key = NULL;
		Py_INCREF (key);
		if (!(new_key = write_basic (state, key)))
		{
			if (PyErr_ExceptionMatches (UnknownSerializerError))
			{
				PyErr_Clear ();
				new_key = PyObject_Unicode (key);
			}
		}
		Py_DECREF (key);
		
		if (!new_key) return FALSE;
		*key_ptr = new_key;
		return TRUE;
	}
	PyErr_SetString (WriteError,
	                 "Only strings may be used"
	                 " as object keys.");
	return FALSE;
}

static int
mapping_get_key_and_value_from_item (WriterState *state, PyObject *item,
                                     PyObject **key_ptr, PyObject **value_ptr)
{
	PyObject *key = NULL, *value = NULL;
	int retval;
	
	(*key_ptr) = NULL;
	(*value_ptr) = NULL;
	
	key = PySequence_GetItem (item, 0);
	if (key)
		value = PySequence_GetItem (item, 1);
	
	if (!(key && value))
	{
		Py_XDECREF (key);
		Py_XDECREF (value);
		return FALSE;
	}
	
	if ((retval = mapping_process_key (state, key, key_ptr)))
	{
		*value_ptr = value;
	}
	return retval;
}

/* Special case for dictionaries */
static int
write_dict (WriterState *state, PyObject *dict, PyObject *start,
            PyObject *end, PyObject *pre_value, PyObject *post_value,
            int indent_level)
{
	Py_ssize_t ii = 0, item_count;
	PyObject *raw_key, *value;
	int status;
	
	if (!writer_append_unicode_obj (state, start))
		return FALSE;
	
	item_count = PyDict_Size (dict);
	while (PyDict_Next (dict, &ii, &raw_key, &value))
	{
		PyObject *serialized, *key;
		
		if (pre_value && !writer_append_unicode_obj (state, pre_value))
			return FALSE;
		
		if (!mapping_process_key (state, raw_key, &key))
			return FALSE;
		
		if (!(serialized = write_basic (state, key)))
			return FALSE;
		
		status = writer_append_chunks (state, serialized);
		Py_DECREF (serialized);
		if (!status)
			return FALSE;
		
		if (!writer_append_unicode_obj (state, state->colon))
			return FALSE;
		
		if (!write_object (state, value, indent_level + 1))
			return FALSE;
		
		if (ii < item_count)
		{
			if (!writer_append_unicode_obj (state, post_value))
			{
				return FALSE;
			}
		}
	}
	
	return writer_append_unicode_obj (state, end);
}

static int
write_mapping_impl (WriterState *state, PyObject *items,
                    PyObject *start, PyObject *end, PyObject *pre_value,
                    PyObject *post_value, int indent_level)
{
	int status;
	size_t ii, item_count;
	
	if (!writer_append_unicode_obj (state, start))
		return FALSE;
	
	item_count = PySequence_Size (items);
	for (ii = 0; ii < item_count; ++ii)
	{
		PyObject *item, *key, *value, *serialized;
		
		if (pre_value && !writer_append_unicode_obj (state, pre_value))
			return FALSE;
		
		if (!(item = PySequence_GetItem (items, ii)))
			return FALSE;
		
		status = mapping_get_key_and_value_from_item (state, item, &key, &value);
		Py_DECREF (item);
		if (!status) return FALSE;
		
		serialized = write_basic (state, key);
		Py_DECREF (key);
		if (!serialized)
		{
			Py_DECREF (value);
			return FALSE;
		}
		
		status = writer_append_chunks (state, serialized);
		Py_DECREF (serialized);
		if (!status)
		{
			Py_DECREF (value);
			return FALSE;
		}
		
		if (!writer_append_unicode_obj (state, state->colon))
		{
			Py_DECREF (value);
			return FALSE;
		}
		
		status = write_object (state, value, indent_level + 1);
		Py_DECREF (value);
		if (!status)
			return FALSE;
		
		if (ii + 1 < item_count)
		{
			if (!writer_append_unicode_obj (state, post_value))
			{
				return FALSE;
			}
		}
	}
	
	return writer_append_unicode_obj (state, end);
}

static int
write_mapping (WriterState *state, PyObject *mapping, int indent_level)
{
	int has_parents, succeeded;
	PyObject *items;
	PyObject *start, *end, *pre_value, *post_value;
	
	if (PyMapping_Size (mapping) == 0)
		return writer_append_ascii (state, "{}");
	
	has_parents = Py_ReprEnter (mapping);
	if (has_parents != 0)
	{
		if (has_parents > 0)
		{
			PyErr_SetString (WriteError,
			                 "Cannot serialize self-referential"
			                 " values.");
		}
		return FALSE;
	}
	
	get_separators (state->indent_string, indent_level, '{', '}',
	                &start, &end, &pre_value, &post_value);
	
	Py_INCREF (mapping);
	if (PyDict_CheckExact (mapping) && !state->sort_keys)
		succeeded = write_dict (state, mapping, start, end,
		                        pre_value, post_value,
		                        indent_level);
	
	else
	{
		if (!(items = PyMapping_Items (mapping)))
		{
			Py_ReprLeave (mapping);
			Py_DECREF (mapping);
			return FALSE;
		}
		if (state->sort_keys) PyList_Sort (items);
		
		
		succeeded = write_mapping_impl (state, items, start, end,
		                                pre_value, post_value,
		                                indent_level);
		Py_DECREF (items);
	}
	
	Py_ReprLeave (mapping);
	Py_DECREF (mapping);
	Py_XDECREF (start);
	Py_XDECREF (end);
	Py_XDECREF (pre_value);
	Py_XDECREF (post_value);
	
	return succeeded;
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
		PyErr_SetString (WriteError,
		                 "Cannot serialize complex numbers with"
		                 " imaginary components.");
		return NULL;
	}
	
	if (PyFloat_Check (value))
	{
		double val = PyFloat_AS_DOUBLE (value);
		if (Py_IS_NAN (val))
		{
			PyErr_SetString (WriteError,
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
			
			PyErr_SetString (WriteError, msg);
			return NULL;
		}
		
		return PyObject_Repr (value);
	}
	
	if (PyObject_IsInstance (value, state->Decimal))
	{
		PyObject *serialized;
		int valid;
		
		Py_INCREF (value);
		serialized = PyObject_Str (value);
		Py_DECREF (value);
		
		valid = check_valid_number (state, serialized);
		if (valid == TRUE)
			return serialized;
		
		if (valid == FALSE)
		{
			PyErr_Format (WriteError,
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
		Py_INCREF (value);
		as_string = PyObject_Str (value);
		Py_DECREF (value);
		if (!as_string)
			return NULL;
		retval = write_string (state, as_string);
		Py_DECREF (as_string);
		return retval;
	}
	
	set_unknown_serializer (value);
	return NULL;
}

static int
write_object_pieces (WriterState *state, PyObject *object,
                     int indent_level, int in_unknown_hook)
{
	PyObject *pieces, *iter, *on_unknown_args;
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
		int retval = FALSE;
		if (indent_level == 0)
		{
			Py_DECREF (pieces);
			PyErr_SetString (WriteError,
			                 "The outermost container must be"
			                 " an array or object.");
			return retval;
		}
		retval = writer_append_chunks (state, pieces);
		Py_DECREF (pieces);
		return retval;
	}
	
	if (!PyErr_ExceptionMatches (UnknownSerializerError))
		return FALSE;
	
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
		int retval;
		PyErr_Clear ();
		retval = write_iterable (state, iter, indent_level);
		Py_DECREF (iter);
		return retval;
	}
	
	if (in_unknown_hook) return FALSE;
	
	PyErr_Clear ();
	if (state->on_unknown == Py_None)
	{
		set_unknown_serializer (object);
	}
	else
	{
		/* Call the on_unknown hook */
		if (!(on_unknown_args = PyTuple_Pack (1, object)))
			return FALSE;
		
		object = PyObject_CallObject (state->on_unknown, on_unknown_args);
		Py_DECREF (on_unknown_args);
		if (object)
			return write_object_pieces (state, object, indent_level, TRUE);
	}
	return FALSE;
}

static int
write_object (WriterState *state, PyObject *object, int indent_level)
{
	return write_object_pieces (state, object, indent_level, FALSE);
}

static int
valid_json_whitespace (PyObject *string)
{
	char *c_str;
	Py_ssize_t c_str_len, ii;
	
	if (string == Py_None) return TRUE;
	if (PyString_AsStringAndSize (string, &c_str, &c_str_len) == -1)
		return -1;
	for (ii = 0; ii < c_str_len; ii++)
	{
		char c = c_str[ii];
		if (!(c == '\x09' ||
		      c == '\x0A' ||
		      c == '\x0D' ||
		      c == '\x20'))
			return FALSE;
	}
	return TRUE;
}

static PyObject*
_write_entry (PyObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject *value;
	WriterState state = {NULL};
	int indent_is_valid, succeeded = FALSE;
	char *encoding;
	
	static char *kwlist[] = {"value", "sort_keys", "indent",
	                         "ascii_only", "coerce_keys", "encoding",
	                         "on_unknown", NULL};
	
	/* Defaults */
	state.sort_keys = FALSE;
	state.indent_string = Py_None;
	state.ascii_only = TRUE;
	state.coerce_keys = FALSE;
	state.on_unknown = Py_None;
	encoding = "utf-8";
	
	if (!PyArg_ParseTupleAndKeywords (args, kwargs, "O|iOiizO:write",
	                                  kwlist,
	                                  &value, &state.sort_keys,
	                                  &state.indent_string,
	                                  &state.ascii_only,
	                                  &state.coerce_keys,
	                                  &encoding, &state.on_unknown))
		return NULL;
	
	if (!(state.on_unknown == Py_None || PyCallable_Check (state.on_unknown)))
	{
		PyErr_SetString (PyExc_TypeError,
		                 "The on_unknown object must be callable.");
		return NULL;
	}
	
	indent_is_valid = valid_json_whitespace (state.indent_string);
	if (!indent_is_valid)
	{
		if (indent_is_valid > -1)
			PyErr_SetString (PyExc_TypeError,
			                 "Only whitespace may be used for indentation.");
		return NULL;
	}
	
	if (state.indent_string == Py_None)
		state.colon = PyString_FromString (":");
	else
		state.colon = PyString_FromString (": ");
	if (!state.colon) return NULL;
	
	if ((state.Decimal = jsonlib_import ("decimal", "Decimal")) &&
	    (state.UserString = jsonlib_import ("UserString", "UserString")) &&
	    (state.true_str = unicode_from_ascii ("true")) &&
	    (state.false_str = unicode_from_ascii ("false")) &&
	    (state.null_str = unicode_from_ascii ("null")) &&
	    (state.inf_str = unicode_from_ascii ("Infinity")) &&
	    (state.neg_inf_str = unicode_from_ascii ("-Infinity")) &&
	    (state.nan_str = unicode_from_ascii ("NaN")) &&
	    (state.quote = unicode_from_ascii ("\"")))
	{
		succeeded = write_object (&state, value, 0);
	}
	
	Py_XDECREF (state.Decimal);
	Py_XDECREF (state.UserString);
	Py_XDECREF (state.true_str);
	Py_XDECREF (state.false_str);
	Py_XDECREF (state.null_str);
	Py_XDECREF (state.inf_str);
	Py_XDECREF (state.neg_inf_str);
	Py_XDECREF (state.nan_str);
	Py_XDECREF (state.quote);
	Py_XDECREF (state.colon);
	
	if (succeeded)
	{
		PyObject *u_string, *encoded;
		
		u_string = writer_buffer_get (&state);
		writer_buffer_clear (&state);
		if (!u_string) return NULL;
		
		if (encoding == NULL)
			return u_string;
		
		encoded = PyUnicode_AsEncodedString (u_string, encoding,
		                                     "strict");
		Py_DECREF (u_string);
		return encoded;
		if (!encoded) return NULL;
	}
	return NULL;
}
/* }}} */

/* python hooks {{{ */
static PyMethodDef module_methods[] = {
	{"read", (PyCFunction) (_read_entry), METH_VARARGS|METH_KEYWORDS,
	PyDoc_STR (
	"read (string)\n"
	"\n"
	"Parse a JSON expression into a Python value.\n"
	"\n"
	"If ``string`` is a byte string, it will be converted to Unicode\n"
	"before parsing.\n"
	)},
	
	{"write", (PyCFunction) (_write_entry), METH_VARARGS|METH_KEYWORDS,
	PyDoc_STR (
	"write (value[, sort_keys[, indent[, ascii_only[, coerce_keys[, encoding[, on_unknown]]]]]])\n"
	"\n"
	"Serialize a Python value to a JSON-formatted byte string.\n"
	"\n"
	"value\n"
	"	The Python object to serialize.\n"
	"\n"
	"sort_keys\n"
	"	Whether object keys should be kept sorted. Useful\n"
	"	for tests, or other cases that check against a\n"
	"	constant string value.\n"
	"	\n"
	"	Default: False\n"
	"\n"
	"indent\n"
	"	A string to be used for indenting arrays and objects.\n"
	"	If this is non-None, pretty-printing mode is activated.\n"
	"	\n"
	"	Default: None\n"
	"\n"
	"ascii_only\n"
	"	Whether the output should consist of only ASCII\n"
	"	characters. If this is True, any non-ASCII code points\n"
	"	are escaped even if their inclusion would be legal.\n"
	"	\n"
	"	Default: True\n"
	"\n"
	"coerce_keys\n"
	"	Whether to coerce invalid object keys to strings. If\n"
	"	this is False, an exception will be raised when an\n"
	"	invalid key is specified.\n"
	"	\n"
	"	Default: False\n"
	"\n"
	"encoding\n"
	"	The output encoding to use. This must be the name of an\n"
	"	encoding supported by Python's codec mechanism. If\n"
	"	None, a Unicode string will be returned rather than an\n"
	"	encoded bytestring.\n"
	"	\n"
	"	If a non-UTF encoding is specified, the resulting\n"
	"	bytestring might not be readable by many JSON libraries,\n"
	"	including jsonlib.\n"
	"	\n"
	"	The default encoding is UTF-8.\n"
	"\n"
	"on_unknown\n"
	"	An object that will be called to convert unknown values\n"
	"	into a JSON-representable value. The default simply raises\n"
	"	an UnknownSerializerError.\n"
	"\n"
	)},
	
	{NULL, NULL}
};

PyDoc_STRVAR (module_doc,
	"Implementation of jsonlib."
);

PyMODINIT_FUNC
initjsonlib (void)
{
	PyObject *module;
	PyObject *version;
	
	if (!(module = Py_InitModule3 ("jsonlib", module_methods,
	                               module_doc)))
		return;
	
	if (!(ReadError = PyErr_NewException ("jsonlib.ReadError",
	                                      PyExc_ValueError, NULL)))
		return;
	Py_INCREF (ReadError);
	PyModule_AddObject(module, "ReadError", ReadError);
	
	if (!(WriteError = PyErr_NewException ("jsonlib.WriteError",
	                                       PyExc_ValueError, NULL)))
		return;
	Py_INCREF (WriteError);
	PyModule_AddObject(module, "WriteError", WriteError);
	
	if (!(UnknownSerializerError = PyErr_NewException ("jsonlib.UnknownSerializerError",
	                                                   WriteError, NULL)))
		return;
	Py_INCREF (UnknownSerializerError);
	PyModule_AddObject(module, "UnknownSerializerError",
	                   UnknownSerializerError);
	
	/* If you change the version here, also change it in setup.py. */
	version = Py_BuildValue ("(iii)", 1, 3, 3);
	PyModule_AddObject (module, "__version__", version);
}
/* }}} */
