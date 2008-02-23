/**
 * Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
 * Author: John Millikin <jmillikin@gmail.com>
 * 
 * Implementation of _read in C.
**/

#include <Python.h>
#include <stddef.h>
#include <stdio.h>
#include <ctype.h>
#include <math.h>

#define FALSE 0
#define TRUE 1

#if PY_VERSION_HEX < 0x02050000
	typedef int Py_ssize_t;
#	define PY_SSIZE_T_F "%d"
#else
#	define PY_SSIZE_T_F "%" PY_FORMAT_SIZE_T "d"
#endif

#if Py_UNICODE_SIZE < 4
#	define PY_UNICODE_F "%u"
#else
#	define PY_UNICODE_F "%lu"
#endif

typedef struct _ParserState {
	Py_UNICODE *start;
	Py_UNICODE *end;
	Py_UNICODE *index;
} ParserState;

static PyObject *read_keyword (ParserState *state);
static PyObject *read_string (ParserState *state);
static PyObject *read_number (ParserState *state);
static PyObject *read_array (ParserState *state);
static PyObject *read_object (ParserState *state);
static PyObject *json_read (ParserState *state);

static PyObject *ReadError;
static PyObject *LeadingZeroError;
static PyObject *BadObjectKeyError;
static PyObject *MissingSurrogateError;
static PyObject *_Decimal;

static void
skipSpaces (ParserState *state)
{
	while (state->index && Py_UNICODE_ISSPACE (*state->index))
		state->index++;
}

/* Helper function to create a new decimal.Decimal object */
static PyObject *
Decimal (PyObject *string)
{
	PyObject *args, *new_obj;
	
	args = PyTuple_Pack (1, string);
	new_obj = PyObject_CallObject (_Decimal, args);
	
	Py_DECREF (args);
	return new_obj;
}

/* Helper function to perform strncmp between Py_UNICODE and char* */
static int
unicode_utf8_strncmp (Py_UNICODE *unicode, const char *utf8, Py_ssize_t count)
{
	PyObject *str;
	char *c_str;
	int retval;
	
	str = PyUnicode_EncodeUTF8 (unicode, count, "strict");
	c_str = PyString_AsString (str);
	
	retval = strncmp (c_str, utf8, count);
	Py_DECREF (str);
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
	
	PyErr_Format (ReadError, "cannot parse JSON description");
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
		PyErr_Format (ReadError,
		              "Unterminated escape in string starting at position " PY_SSIZE_T_F,
		              (Py_ssize_t)(state->index - state->start));
		return FALSE;
	}
	
	if (!read_4hex (string_start + (*index_ptr), &value))
		return FALSE;
		
	(*index_ptr) += 4;
	
	/* Check for surrogate pair */
	if (value >= 0xD800 && value <= 0xDBFF)
	{
		Py_UNICODE upper = value, lower;
		
		if (remaining < 10)
		{
			PyErr_Format (MissingSurrogateError,
			              "Surrogate pair half is required at " PY_SSIZE_T_F,
			              (Py_ssize_t)(state->index - state->start));
			return FALSE;
		}
		
		if (string_start[(*index_ptr)] != '\\' ||
		    string_start[(*index_ptr) + 1] != 'u')
		{
			PyErr_Format (MissingSurrogateError,
			              "Surrogate pair half is required at " PY_SSIZE_T_F,
			              (Py_ssize_t)(state->index - state->start));
			return FALSE;
		}
		(*index_ptr) += 2;
		
		if (!read_4hex (string_start + (*index_ptr), &lower))
			return FALSE;
			
		(*index_ptr) += 4;
		
#		if Py_UNICODE_SIZE >= 4
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
			PyErr_Format (ReadError,
			              "unterminated string starting at position " PY_SSIZE_T_F,
			              (Py_ssize_t)(state->index - state->start));
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
						ii = next_ii;
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
					PyErr_Format (ReadError,
					              "Illegal escape code '" PY_UNICODE_F "' at position " PY_SSIZE_T_F,
					              c, (Py_ssize_t)(start - state->start) + ii);
					
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
	PyObject *object;
	int is_float = FALSE, should_stop = FALSE, got_digit = FALSE,
	    leading_zero = FALSE, has_exponent = FALSE;
	Py_UNICODE *ptr, c;
	
	ptr = state->index;
	
	while ((c = *ptr))
	{
		switch(c) {
		case '0':
			if (!got_digit)
			{
				leading_zero = TRUE;
			}
			if (got_digit && leading_zero)
			{
				PyErr_Format (LeadingZeroError, "Invalid leading zero");
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
			if (leading_zero)
			{
				PyErr_Format (LeadingZeroError, "Invalid leading zero");
				return NULL;
			}
			got_digit = TRUE;
			break;
		case '-':
			break;
		case 'e':
		case 'E':
			has_exponent = TRUE;
			break;
		case '.':
			is_float = TRUE;
			break;
		default:
			should_stop = TRUE;
		}
		if (should_stop) {
			break;
		}
		ptr++;
	}
	
	if (is_float || has_exponent)
	{
		PyObject *str, *unicode;
		if (!(unicode = PyUnicode_FromUnicode (state->index,
		                                      ptr - state->index)))
			return NULL;
		str = PyUnicode_AsUTF8String (unicode);
		Py_DECREF (unicode);
		if (!str) return NULL;
		object = Decimal (str);
		Py_DECREF (str);
	}
	
	else
	{
		object = PyLong_FromUnicode (state->index,
		                             ptr - state->index, 10);
	}
	
	if (object == NULL)
	{
		PyErr_Format(ReadError, "invalid number starting at position " PY_SSIZE_T_F,
		             (Py_ssize_t)(state->index - state->start));
		return NULL;
	}
	
	state->index = ptr;
	return object;
}


static PyObject *
read_array(ParserState *state)
{
	PyObject *object, *item;
	int expect_item, items, result;
	Py_UNICODE *start, c;
	
	object = PyList_New(0);
	
	start = state->index;
	state->index++;
	expect_item = TRUE;
	items = 0;
	while (TRUE) {
		skipSpaces(state);
		c = *state->index;
		if (c == 0) {
			PyErr_Format(ReadError,
			             "unterminated array starting at "
			             "position " PY_SSIZE_T_F,
			             (Py_ssize_t)(start - state->start));
			goto failure;;
		} else if (c == ']') {
			if (expect_item && items>0) {
				PyErr_Format(ReadError,
				             "expecting array item at "
				             "position " PY_SSIZE_T_F,
				             (Py_ssize_t)(state->index - state->start));
				goto failure;
			}
			state->index++;
			break;
		} else if (c == ',') {
			if (expect_item) {
				PyErr_Format(ReadError,
				             "expecting array item at "
				             "position " PY_SSIZE_T_F,
				             (Py_ssize_t)(state->index - state->start));
				goto failure;
			}
			expect_item = TRUE;
			state->index++;
			continue;
		} else {
			item = json_read (state);
			if (item == NULL)
				goto failure;
			result = PyList_Append(object, item);
			Py_DECREF(item);
			if (result == -1)
				goto failure;
			expect_item = FALSE;
			items++;
		}
	}

	return object;

failure:
	Py_DECREF(object);
	return NULL;
}


static PyObject *
read_object(ParserState *state)
{
	PyObject *object, *key, *value;
	int expect_key, items, result;
	Py_UNICODE *start, c;
	
	object = PyDict_New ();
	
	expect_key = TRUE;
	items = 0;
	start = state->index;
	state->index++;
	
	while (TRUE) {
		skipSpaces (state);
		c = *state->index;
		if (c == 0) {
			PyErr_Format(ReadError,
			             "unterminated object starting at "
			             "position " PY_SSIZE_T_F,
			             (Py_ssize_t)(start - state->start));
			goto failure;;
		} else if (c == '}') {
			if (expect_key && items>0) {
				PyErr_Format(ReadError,
				             "expecting object property name"
				             " at position " PY_SSIZE_T_F,
				             (Py_ssize_t)(state->index - state->start));
				goto failure;
			}
			state->index++;
			break;
		} else if (c == ',') {
			if (expect_key) {
				PyErr_Format(ReadError,
				             "expecting object property name"
				             "at position " PY_SSIZE_T_F,
				             (Py_ssize_t)(state->index - state->start));
				goto failure;
			}
			expect_key = TRUE;
			state->index++;
			continue;
		} else {
			if (c != '"') {
				PyErr_Format(BadObjectKeyError,
				             "expecting property name in "
				             "object at position " PY_SSIZE_T_F,
				             (Py_ssize_t)(state->index - state->start));
				goto failure;
			}

			key = json_read (state);
			if (key == NULL)
				goto failure;

			skipSpaces(state);
			if (*state->index != ':') {
				PyErr_Format(ReadError,
				             "missing colon after object "
				             "property name at position " PY_SSIZE_T_F,
				             (Py_ssize_t)(state->index - state->start));
				Py_DECREF(key);
				goto failure;
			} else {
				state->index++;
			}

			value = json_read (state);
			if (value == NULL) {
				Py_DECREF(key);
				goto failure;
			}

			result = PyDict_SetItem(object, key, value);
			Py_DECREF(key);
			Py_DECREF(value);
			if (result == -1)
				goto failure;
			expect_key = FALSE;
			items++;
		}
	}

	return object;

failure:
	Py_DECREF(object);
	return NULL;
}


static PyObject *
json_read (ParserState *state)
{
	PyObject *object;

	skipSpaces (state);
	switch (*state->index) {
	case 0:
		PyErr_SetString (ReadError, "empty JSON description");
		return NULL;
	case '{':
		object = read_object (state);
		break;
	case '[':
		object = read_array (state);
		break;
	case '"':
		object = read_string (state);
		break;
	case 't':
	case 'f':
	case 'n':
		object = read_keyword (state);
		break;
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
		object = read_number (state);
		break;
	default:
		PyErr_SetString (ReadError, "cannot parse JSON description");
		return NULL;
	}

	return object;
}

static PyObject*
_read_entry (PyObject *self, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = {"json", NULL};
	PyObject *result, *unicode;
	ParserState state;
	
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O:read", kwlist,
	                                 &unicode))
		return NULL;
	
	Py_INCREF (unicode);
	
	state.start = PyUnicode_AsUnicode (unicode);
	state.end = state.start + PyUnicode_GetSize (unicode);
	state.index = state.start;
	
	result = json_read (&state);
	
	if (result != NULL) {
		skipSpaces (&state);
		if (state.index < state.end) {
			PyErr_Format(ReadError,
			             "extra data after JSON description"
			             " at position " PY_SSIZE_T_F,
			             (Py_ssize_t)(state.index - state.start));
			Py_DECREF (result);
			result = NULL;
		}
	}
	
	Py_DECREF (unicode);
	
	return result;
}


/* List of functions defined in the module */

static PyMethodDef reader_methods[] = {
	{"_read", (PyCFunction) (_read_entry), METH_VARARGS|METH_KEYWORDS,
	PyDoc_STR("_read (string) -> parse the JSON representation into\n"
	          "python objects.")},
	
	{NULL, NULL}
};

PyDoc_STRVAR(module_doc,
"Fast JSON encoder/decoder module."
);

PyMODINIT_FUNC
init_reader (void)
{
	PyObject *m, *errors, *decimal_module;
	
	m = Py_InitModule3("_reader", reader_methods, module_doc);
	
	if (m == NULL)
		return;
	
	if (!(errors = PyImport_ImportModule ("errors")))
		return;
	if (!(ReadError = PyObject_GetAttrString (errors, "ReadError")))
		return;
	if (!(LeadingZeroError = PyObject_GetAttrString (errors, "LeadingZeroError")))
		return;
	if (!(BadObjectKeyError = PyObject_GetAttrString (errors, "BadObjectKeyError")))
		return;
	if (!(MissingSurrogateError = PyObject_GetAttrString (errors, "MissingSurrogateError")))
		return;
	
	if (!(decimal_module = PyImport_ImportModule ("decimal")))
		return;
	if (!(_Decimal = PyObject_GetAttrString (decimal_module, "Decimal")))
		return;
}

