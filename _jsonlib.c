/**
 * Copyright (C) 2008-2009 John Millikin <jmillikin@gmail.com>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
**/

#include <Python.h>
#include <stddef.h>
#include <stdio.h>
#include <ctype.h>
#include <math.h>

typedef struct _ModuleState
{
	PyObject *Decimal;
	PyObject *UserString;
	
	/* Constants, saved to avoid lookup in the serializer */
	PyObject *true_str;
	PyObject *false_str;
	PyObject *null_str;
	PyObject *quote;
} ModuleState;

/* Parser {{{ */
typedef struct _Parser
{
	Py_UNICODE *start, *end, *index;
	PyObject *error_helper;
	ModuleState *module;
	
	Py_UNICODE *stringparse_buffer;
	size_t stringparse_buffer_size;
	
	unsigned char use_float: 1;
	unsigned char got_root: 1;
} Parser;

static PyObject *
jsonlib_read (PyObject *, PyObject *);

static PyObject *
parse_raw (Parser *);

static PyObject *
parse_object (Parser *);

static PyObject *
parse_array (Parser *);

static PyObject *
parse_string (Parser *);

static PyObject *
parse_string_full (Parser *, Py_UNICODE *, size_t);

static int
parse_unicode_escape (Parser *, Py_UNICODE *, Py_UNICODE *,
                      size_t *, size_t *, size_t);

static PyObject *
parse_keyword (Parser *);

static PyObject *
parse_number (Parser *);

static unsigned char
skip_whitespace (Parser *, Py_UNICODE *, const char *);

static unsigned char
skip_char (Parser *, Py_UNICODE, const char *);

static PyObject *
parser_raise (Parser *, const char *);

static PyObject *
parser_raise_unexpected (Parser *, const char *);

static PyObject *
parser_raise_unterminated_string (Parser *, Py_UNICODE *);

static size_t
next_power_2 (size_t start, size_t min);

static PyObject *
jsonlib_read (PyObject *self, PyObject *args)
{
	PyObject *result = NULL, *text;
	Parser parser = {NULL};
	unsigned char use_float = 0;
	
	if (!PyArg_ParseTuple (args, "UbO", &text, &use_float, &parser.error_helper))
	{ return NULL; }
	
	parser.start = PyUnicode_AsUnicode (text);
	parser.end = parser.start + PyUnicode_GetSize (text);
	parser.index = parser.start;
	parser.use_float = use_float;
	parser.module = PyModule_GetState (self);
	
	result = parse_raw (&parser);
	skip_whitespace (&parser, NULL, NULL);
	
	if (result && parser.index != parser.end)
	{
		Py_DECREF (result);
		result = parser_raise (&parser, "extra_data");
	}
	
	if (parser.stringparse_buffer)
	{
		PyMem_Free (parser.stringparse_buffer);
	}
	
	return result;
}

static PyObject *
parse_raw (Parser *parser)
{
	Py_UNICODE c;
	
	skip_whitespace (parser, NULL, NULL);
	if (parser->index == parser->end)
	{
		return PyObject_CallMethod (parser->error_helper, "no_expression", "uk",
			parser->start, 0);
	}
	
	c = *parser->index;
	if (c == '{')
	{
		parser->got_root = 1;
		return parse_object (parser);
	}
	
	if (c == '[')
	{
		parser->got_root = 1;
		return parse_array (parser);
	}
	
	if (!parser->got_root)
	{ return parser_raise_unexpected (parser, NULL); }
	
	switch (c)
	{
	case '"':
		return parse_string (parser);
	case 't':
	case 'f':
	case 'n':
		return parse_keyword (parser);
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
		return parse_number (parser);
	default:
		break;
	}
	return parser_raise_unexpected (parser, NULL);
}

static PyObject *
parse_object (Parser *parser)
{
	PyObject *retval = NULL, *key = NULL, *value = NULL;
	Py_UNICODE *start = parser->index;
	int result;
	
	if (!skip_char (parser, '{', "object start"))
	{ goto error; }
	
	if (!skip_whitespace (parser, start, "Unterminated object."))
	{ goto error; }
	
	retval = PyDict_New ();
	if (*parser->index == '}')
	{
		if (!skip_char (parser, '}', "object end"))
		{ goto error; }
		
		return retval;
	}
	
	while (1)
	{
		key = value = NULL;
		
		if (!skip_whitespace (parser, start, "Unterminated object."))
		{ goto error; }
		
		if (*parser->index != '"')
		{
			parser_raise_unexpected (parser, "property name");
			goto error;
		}
		
		if (!(key = parse_raw (parser)))
		{ goto error; }
		
		if (!skip_whitespace (parser, start, "Unterminated object."))
		{ goto error; }
		
		if (!skip_char (parser, ':', "colon"))
		{ goto error; }
		
		if (!skip_whitespace (parser, start, "Unterminated object."))
		{ goto error; }
		
		if (!(value = parse_raw (parser)))
		{ goto error; }
		
		result = PyDict_SetItem (retval, key, value);
		Py_DECREF (key);
		Py_DECREF (value);
		key = NULL;
		value = NULL;
		if (result == -1)
		{ goto error; }
		
		if (!skip_whitespace (parser, start, "Unterminated object."))
		{ goto error; }
		
		if (*parser->index == '}')
		{
			if (!skip_char (parser, '}', "object end"))
			{ goto error; }
			
			return retval;
		}
		
		if (!skip_char (parser, ',', "comma"))
		{ goto error; }
	}
	
	return retval;
error:
	Py_XDECREF (retval);
	Py_XDECREF (key);
	Py_XDECREF (value);
	return NULL;
}

static PyObject *
parse_array (Parser *parser)
{
	PyObject *retval = NULL, *value = NULL;
	Py_UNICODE *start = parser->index;
	int result;
	
	if (!skip_char (parser, '[', "array start"))
	{ goto error; }
	
	if (!skip_whitespace (parser, start, "Unterminated array."))
	{ goto error; }
	
	retval = PyList_New (0);
	if (*parser->index == ']')
	{
		if (!skip_char (parser, ']', "object end"))
		{ goto error; }
		
		return retval;
	}
	
	while (1)
	{
		value = NULL;
		
		if (!skip_whitespace (parser, start, "Unterminated array."))
		{ goto error; }
		
		if (!(value = parse_raw (parser)))
		{ goto error; }
		
		result = PyList_Append (retval, value);
		Py_DECREF (value);
		value = NULL;
		if (result == -1)
		{ goto error; }
		
		if (!skip_whitespace (parser, start, "Unterminated array."))
		{ goto error; }
		
		if (*parser->index == ']')
		{
			if (!skip_char (parser, ']', "array end"))
			{ goto error; }
			
			return retval;
		}
		
		if (!skip_char (parser, ',', "comma"))
		{ goto error; }
	}
	
	return retval;
error:
	Py_XDECREF (retval);
	Py_XDECREF (value);
	return NULL;
}

static PyObject *
parse_string (Parser *parser)
{
	PyObject *unicode;
	int escaped = 0, fancy = 0;
	Py_UNICODE c, *start;
	size_t ii;
	
	start = parser->index;
	
	/* Fast case for empty string */
	if (start[1] == '"')
	{
		parser->index = start + 2;
		return PyUnicode_FromUnicode (NULL, 0);
	}
	
	/* Scan through for maximum character count, and to ensure the string
	 * is terminated.
	**/
	for (ii = 1; start + ii < parser->end; ii++)
	{
		c = start[ii];
		
		/* Check for illegal characters */
		if (c < 0x20)
		{
			parser->index = start + ii;
			return parser_raise_unexpected (parser, NULL);
		}
		
		/* Invalid escape codes will be caught later. */
		if (escaped)
		{ escaped = 0; }
		
		else
		{
			if (c == '\\')
			{
				fancy = 1;
				escaped = 1;
			}
			else if (c == '"')
			{ break; }
		}
	}
	
	if (start + ii >= parser->end)
	{ return parser_raise_unterminated_string (parser, start); }
	
	if (fancy)
	{
		return parse_string_full (parser, start, ii);
	}
	
	/* No fancy features, return the string directly */
	unicode = PyUnicode_FromUnicode (start + 1, ii - 1);
	if (unicode)
	{
		parser->index = start + ii + 1;
	}
	return unicode;
}

static PyObject *
parse_string_full (Parser *parser, Py_UNICODE *start, size_t max_char_count)
{
	PyObject *unicode;
	int escaped = 0;
	Py_UNICODE c, *buffer;
	size_t ii = 1, buffer_idx;
	
	/* Allocate enough to hold the worst case */
	buffer = parser->stringparse_buffer;
	if (max_char_count > parser->stringparse_buffer_size)
	{
		size_t new_size, existing_size;
		existing_size = parser->stringparse_buffer_size;
		new_size = next_power_2 (1, max_char_count);
		parser->stringparse_buffer = PyMem_Resize (buffer, Py_UNICODE, new_size);
		buffer = parser->stringparse_buffer;
		parser->stringparse_buffer_size = new_size;
	}
	
	/* Scan through the string, adding values to the buffer as
	 * appropriate.
	**/
	escaped = 0;
	buffer_idx = 0;
	
	while (1)
	{
		while (!escaped)
		{
			if (start + ii >= parser->end)
			{ parser_raise_unterminated_string (parser, start); }
			
			c = start[ii];
			if (c == '\\') { escaped = 1; }
			else if (c == '"')
			{
				unicode = PyUnicode_FromUnicode (buffer, buffer_idx);
				if (unicode)
				{ parser->index = start + max_char_count + 1; }
				
				return unicode;
			}
			else { buffer[buffer_idx++] = c; }
			ii++;
		}
		
		escaped = 0;
		if (start + ii >= parser->end)
		{ parser_raise_unterminated_string (parser, start); }
		
		c = start[ii];
		switch (c)
		{
		case '\\':
		case '"':
		case '/':
			buffer[buffer_idx++] = c;
			break;
		case 'b': buffer[buffer_idx++] = 0x08; break;
		case 'f': buffer[buffer_idx++] = 0x0C; break;
		case 'n': buffer[buffer_idx++] = 0x0A; break;
		case 'r': buffer[buffer_idx++] = 0x0D; break;
		case 't': buffer[buffer_idx++] = 0x09; break;
		case 'u':
			if (parse_unicode_escape (
				parser, start, buffer, &buffer_idx, &ii,
				max_char_count))
			{
				ii--;
				buffer_idx++;
				break;
			}
			else { return NULL; }
		default:
			return PyObject_CallMethod (
				parser->error_helper,
				"unknown_escape", "uku#",
				parser->start,
				(start - parser->start + ii - 1),
				&c, 1);
		}
		ii++;
	}
}

static int
read_4hex (Py_UNICODE *start, Py_UNICODE *retval_ptr)
{
	PyObject *py_long;
	
	py_long = PyLong_FromUnicode (start, 4, 16);
	if (!py_long) { return 0; }
	
	(*retval_ptr) = (Py_UNICODE) (PyLong_AsUnsignedLong (py_long));
	Py_DECREF (py_long);
	return 1;
}

static int
parse_unicode_escape (Parser *parser, Py_UNICODE *string_start, Py_UNICODE *buffer,
                      size_t *buffer_idx, size_t *index_ptr, size_t max_char_count)
{
	size_t remaining;
	size_t offset = *index_ptr;
	Py_UNICODE value;
	
	offset++;
	
	remaining = max_char_count - offset;
	if (remaining < 4)
	{
		PyObject_CallMethod (parser->error_helper,
			"unterminated_unicode", "uk",
			parser->start,
			(parser->index + offset - 2) - parser->start);
		return 0;
	}
	
	if (!read_4hex (string_start + offset, &value))
	{ return 0; }
	
	offset += 4;
	
	/* Check for surrogate pair */
	if (0xD800 <= value && value <= 0xDBFF)
	{
		Py_UNICODE upper = value, lower;
		
		if (remaining < 10)
		{
			PyObject_CallMethod (parser->error_helper,
				"missing_surrogate", "uk",
				parser->start,
				(parser->index + offset) - parser->start);
			return 0;
		}
		
		if (string_start[offset] != '\\' ||
		    string_start[offset + 1] != 'u')
		{
			PyObject_CallMethod (parser->error_helper,
				"missing_surrogate", "uk",
				parser->start,
				(parser->index + offset) - parser->start);
			return 0;
		}
		offset += 2;
		
		if (!read_4hex (string_start + offset, &lower))
		{ return 0; }
			
		offset += 4;
		
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
		PyObject_CallMethod (parser->error_helper,
			"reserved_code_point", "ukk",
			parser->start,
			(parser->index + offset - 6) - parser->start,
			value);
		return 0;
	}
	else
	{
		buffer[*buffer_idx] = value;
	}
	*index_ptr = offset;
	return 1;
}

static PyObject *
keyword_compare (Parser *parser, const char *expected, size_t len,
                 PyObject *retval)
{
	size_t ii, left;
	
	left = parser->end - parser->index;
	if (left >= len)
	{
		for (ii = 0; ii < len; ii++)
		{
			if (parser->index[ii] != (unsigned char)(expected[ii]))
				return NULL;
		}
		parser->index += len;
		Py_INCREF (retval);
		return retval;
	}
	return NULL;
}

static PyObject *
parse_keyword (Parser *parser)
{
	PyObject *kw = NULL;
	if ((kw = keyword_compare (parser, "true", 4, Py_True)))
		return kw;
	if ((kw = keyword_compare (parser, "false", 5, Py_False)))
		return kw;
	if ((kw = keyword_compare (parser, "null", 4, Py_None)))
		return kw;
	return parser_raise_unexpected (parser, NULL);
}

static PyObject *
parse_number (Parser *parser)
{
	PyObject *object = NULL;
	unsigned char is_float = 0, should_stop = 0, got_digit = 0,
	    leading_zero = 0, has_exponent = 0;
	Py_UNICODE *ptr;
	
	ptr = parser->index;
	
	while (ptr < parser->end)
	{
		switch (*ptr)
		{
		case '0':
			if (!got_digit)
			{
				leading_zero = 1;
			}
			else if (leading_zero && !is_float)
			{
				return parser_raise (parser, "invalid_number");
			}
			got_digit = 1;
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
				return parser_raise (parser, "invalid_number");
			}
			got_digit = 1;
			break;
		case '-':
		case '+':
			break;
		case 'e':
		case 'E':
			has_exponent = 1;
			break;
		case '.':
			is_float = 1;
			got_digit = 0;
			break;
		default:
			should_stop = 1;
		}
		if (should_stop)
		{ break; }
		ptr++;
	}
	
	if (got_digit)
	{
		if (is_float || has_exponent)
		{
			PyObject *str;
			if (!(str = PyUnicode_FromUnicode (parser->index,
			                                   ptr - parser->index)))
			{ return NULL; }
			
			if (parser->use_float)
			{
				object = PyFloat_FromString (str);
			}
			else
			{
				object = PyObject_CallFunctionObjArgs (
					parser->module->Decimal, str, NULL);
			}
			Py_DECREF (str);
		}
		
		else
		{
			object = PyLong_FromUnicode (parser->index,
			                             ptr - parser->index, 10);
		}
	}
	
	if (object == NULL)
	{
		return parser_raise (parser, "invalid_number");
	}
	
	parser->index = ptr;
	return object;
}

static unsigned char
skip_whitespace (Parser *parser, Py_UNICODE *start, const char *message)
{
	if (message && !start) { start = parser->index; }
	
	/* Don't use Py_UNICODE_ISSPACE, because it returns TRUE for
	 * codepoints that are not valid JSON whitespace.
	**/
	Py_UNICODE c;
	while (parser->index < parser->end)
	{
		c = *parser->index;
		if (!(c == '\x09' ||
		      c == '\x0A' ||
		      c == '\x0D' ||
		      c == '\x20'))
		{ return 1; }
		
		parser->index++;
	}
	
	if (message)
	{
		PyObject_CallMethod (parser->error_helper, "generic", "uks",
			parser->start, (start - parser->start),
			message);
		return 0;
	}
	return 1;
}

static unsigned char
skip_char (Parser *parser, Py_UNICODE c, const char *message)
{
	if (c != *parser->index)
	{
		parser_raise_unexpected (parser, message);
		return 0;
	}
	
	parser->index++;
	return 1;
}

static PyObject *
parser_raise (Parser *parser, const char *error_key)
{
	return PyObject_CallMethod (parser->error_helper, (char*)error_key, "uk",
		parser->start, (parser->index - parser->start));
}

static PyObject *
parser_raise_unexpected (Parser *parser, const char *message)
{
	return PyObject_CallMethod (parser->error_helper, "unexpected", "uks",
		parser->start, (parser->index - parser->start),
		message);
}

static PyObject *
parser_raise_unterminated_string (Parser *parser, Py_UNICODE *start)
{
	return PyObject_CallMethod (parser->error_helper, "unterminated_string", "uk",
		parser->start, (start - parser->start));
}

static size_t
next_power_2 (size_t start, size_t min)
{
	while (start < min) start <<= 1;
	return start;
}

/* }}} */

/* Serializer {{{ */
typedef struct _Serializer Serializer;
struct _Serializer
{
	ModuleState *module;
	
	/* Virtual implementation methods */
	unsigned char (*append_ascii) (Serializer *, const char *, const size_t);
	unsigned char (*append_unicode) (Serializer *, PyObject *);
	
	/* Per-run constant. This isn't saved in the module state
	 * because it varies based on the indentation mode.
	**/
	PyObject *colon;
	
	/* Serialization options */
	PyObject *indent;
	PyObject *on_unknown;
	PyObject *error_helper;
	unsigned char sort_keys: 1;
	unsigned char coerce_keys: 1;
	unsigned char ascii_only: 1;
};

typedef struct _BufferSerializer
{
	Serializer base;
	Py_UNICODE *buffer;
	size_t buffer_size;
	size_t buffer_max_size;
} BufferSerializer;

typedef struct _StreamSerializer
{
	Serializer base;
	PyObject *stream;
	char *encoding;
} StreamSerializer;

static const char hexdigit[] = "0123456789abcdef";
static const char INITIAL_BUFFER_SIZE = 32;

static PyObject *
jsonlib_write (PyObject *, PyObject *);

static unsigned char
serializer_run (Serializer *, PyObject *);

static unsigned char
serialize_object (Serializer *, PyObject *, unsigned int, unsigned char);

static unsigned char
serialize_mapping (Serializer *, PyObject *, unsigned int);

static unsigned char
serialize_iterator (Serializer *, PyObject *, PyObject *, unsigned int);

static unsigned char
serialize_atom (Serializer *, PyObject *);

static unsigned char
serialize_string (Serializer *, PyObject *);

static unsigned char
serialize_float (Serializer *, PyObject *);

static unsigned char
serialize_complex (Serializer *, PyObject *);

static unsigned char
serialize_decimal (Serializer *, PyObject *);

static unsigned char
serializer_is_atomic (Serializer *, PyObject *);

static unsigned char
serializer_raise (Serializer *, const char *);

static unsigned char
buffer_serializer_append_ascii (Serializer *, const char *, size_t);

static unsigned char
buffer_serializer_append_unicode (Serializer *, PyObject *);

static unsigned char
buffer_serializer_resize (BufferSerializer *, size_t delta);

static PyObject *
ascii_constant (const char *value, int len)
{
	if (len < 0)
		len = strlen (value);
	return PyUnicode_DecodeASCII (value, len, "strict");
}

static PyObject *
jsonlib_write (PyObject *self, PyObject *args)
{
	PyObject *result = NULL;
	BufferSerializer serializer = {{NULL}, NULL};
	Serializer *base = (Serializer *) &serializer;
	
	/* Parameters */
	PyObject *value;
	char *encoding;
	unsigned char sort_keys = 0,
	              ascii_only = 0,
	              coerce_keys = 0;
	
	if (!PyArg_ParseTuple(args, "OiOiizOO",
		&value,
		&sort_keys,
		&base->indent,
		&ascii_only,
		&coerce_keys,
		&encoding,
		&base->on_unknown,
		&base->error_helper))
	{ return NULL; }
	
	base->sort_keys = sort_keys;
	base->ascii_only = ascii_only;
	base->coerce_keys = coerce_keys;
	
	/* Implementation pointers */
	base->module = PyModule_GetState (self);
	base->append_ascii = buffer_serializer_append_ascii;
	base->append_unicode = buffer_serializer_append_unicode;
	
	if (!serializer_run (base, value))
	{ return NULL; } // TODO: memory leak of encoder.buffer?
	
	if (encoding)
	{
		result = PyUnicode_Encode (
			serializer.buffer, serializer.buffer_size,
			encoding, "strict");
	}
	
	else
	{
		result = PyUnicode_FromUnicode (
			serializer.buffer, serializer.buffer_size);
	}
	
	PyMem_Free (serializer.buffer);
	return result;
}

static unsigned char
serializer_run (Serializer *s, PyObject *value)
{
	const char *colon;
	unsigned char retval;
	
	/* Generate the colon constant */
	colon = s->indent == Py_None? ":" : ": ";
	if (!(s->colon = ascii_constant (colon, -1)))
	{ return 0; }
	
	/* Run, clean up, return */
	retval = serialize_object (s, value, 0, 0);
	Py_DECREF (s->colon);
	return retval;
}

static unsigned char
serialize_object (Serializer *s, PyObject *value,
                  unsigned int indent_level, unsigned char in_unknown_hook)
{
	PyObject *new_value, *iter;
	unsigned char retval;
	
	/* UserStrings need to be unwrapped. */
	if (PyObject_IsInstance (value, s->module->UserString) == 1)
	{
		// TODO: does this leak?
		value = PyObject_GetAttrString (value, "data");
	}
	
	/* Check built-in atomic types */
	if (serializer_is_atomic (s, value))
	{ return serialize_atom (s, value); }
	
	/* http://bugs.python.org/issue5945 */
	/*if (PyMapping_Check (value))*/
	if (PyObject_HasAttrString (value, "items"))
	{ return serialize_mapping (s, value, indent_level); }
	
	if ((iter = PyObject_GetIter (value)))
	{
		retval = serialize_iterator (s, iter, value, indent_level);
		Py_DECREF (iter);
		return retval;
	}
	
	if (in_unknown_hook)
	{
		PyObject_CallMethod (s->error_helper,
			"unknown_serializer",
			"O", value);
		return 0;
	}
	
	new_value = PyObject_CallFunctionObjArgs (s->on_unknown,
		value, NULL);
	if (!new_value)
	{ return 0; }
	
	retval = serialize_object (s, new_value, indent_level, 1);
	Py_DECREF (new_value);
	return retval;
}

static unsigned char
serialize_check_recursion (Serializer *s, PyObject *value)
{
	int repr_ret = Py_ReprEnter (value);
	if (repr_ret > 0)
	{ serializer_raise (s, "self_referential"); }
	
	return (repr_ret == 0);
}

static unsigned char
serializer_separators (Serializer *s, unsigned int indent_level,
                       PyObject **indent_ret, PyObject **post_indent_ret)
{
	PyObject *repeated[2], *indent = NULL, *post_indent = NULL;
	unsigned char retval = 1;
	
	*indent_ret = NULL;
	*post_indent_ret = NULL;
	if (s->indent == Py_None)
	{ return 1; }
	
	repeated[0] = PySequence_Repeat (s->indent, indent_level);
	repeated[1] = PySequence_Repeat (s->indent, indent_level + 1);
	
	if (!(repeated[0] && repeated[1]))
	{ goto error; }
	
	indent = PyUnicode_FromFormat ("\n%S", repeated[1]);
	post_indent = PyUnicode_FromFormat ("\n%S", repeated[0]);
	
	if (!(indent && post_indent))
	{ goto error; }
	
	*indent_ret = indent;
	*post_indent_ret = post_indent;
	
	goto success;
error:
	retval = 0;
	Py_XDECREF (indent);
	Py_XDECREF (post_indent);
success:
	Py_XDECREF (repeated[0]);
	Py_XDECREF (repeated[1]);
	return retval;
}

static unsigned char
serializer_get_mapping_pair (Serializer *s, PyObject *iter,
                             PyObject **key_ret, PyObject **value_ret,
                             unsigned char *error_ret)
{
	PyObject *key = NULL, *value = NULL, *pair = NULL, *new_key;
	
	*key_ret = NULL;
	*value_ret = NULL;
	
	if (!(pair = PyIter_Next (iter)))
	{ return 0; }
	
	if (!(key = PySequence_GetItem (pair, 0)))
	{ goto error; }
	
	/* Check for a valid key */
	if (PyObject_IsInstance (key, s->module->UserString) == 1)
	{
		if (!(new_key = PyObject_GetAttrString (key, "data")))
		{ goto error; }
		key = new_key;
		new_key = NULL;
	}
	
	if (!PyUnicode_Check (key))
	{
		if (!s->coerce_keys)
		{
			serializer_raise (s, "invalid_object_key");
			goto error;
		}
		
		if (!(new_key = PyObject_Str (key)))
		{ goto error; }
		key = new_key;
		new_key = NULL;
	}
	
	if (!(value = PySequence_GetItem (pair, 1)))
	{ goto error; }
	
	Py_DECREF (pair);
	*key_ret = key;
	*value_ret = value;
	*error_ret = 0;
	return 1;
	
error:
	Py_DECREF (pair);
	Py_XDECREF (key);
	Py_XDECREF (value);
	*error_ret = 1;
	return 1;
}

static unsigned char
serialize_mapping (Serializer *s, PyObject *mapping,
                   unsigned int indent_level)
{
	unsigned char retval = 1, first = 1, error;
	PyObject *indent = NULL, *post_indent = NULL, *keys = NULL,
	         *iter = NULL, *key = NULL, *value = NULL;
	
	if (!serialize_check_recursion (s, mapping))
	{ return 0; }
	
	if (!(keys = PyMapping_Items (mapping)))
	{ goto error; }
	
	if (!(iter = PyObject_GetIter (keys)))
	{ goto error; }
	
	if (!serializer_separators (s, indent_level, &indent, &post_indent))
	{ goto error; }
	
	if (!s->append_ascii (s, "{", 1))
	{ goto error; }
	
	while ((serializer_get_mapping_pair (s, iter, &key, &value, &error)))
	{
		if (error)
		{ goto error; }
		
		if (first)
		{ first = 0; }
		else if (!s->append_ascii (s, ",", 1))
		{ goto error; }
		
		if (indent && !s->append_unicode (s, indent))
		{ goto error; }
		
		if (!serialize_object (s, key, indent_level + 1, 0))
		{ goto error; }
		
		if (!s->append_ascii (s, ": ", indent? 2 : 1))
		{ goto error; }
		
		if (!serialize_object (s, value, indent_level + 1, 0))
		{ goto error; }
		
		Py_DECREF (key);
		Py_DECREF (value);
	}
	
	if (post_indent)
	{
		if (!s->append_unicode (s, post_indent))
		{ goto error; }
	}
	
	if (!s->append_ascii (s, "}", 1))
	{ goto error; }
	
	goto success;
error:
	retval = 0;
success:
	Py_XDECREF (indent);
	Py_XDECREF (post_indent);
	Py_XDECREF (keys);
	Py_XDECREF (iter);
	Py_XDECREF (key);
	Py_XDECREF (value);
	Py_ReprLeave (mapping);
	return retval;
}

static unsigned char
serialize_iterator (Serializer *s, PyObject *iter,
                    PyObject *value, unsigned int indent_level)
{
	unsigned char retval = 1, first = 1;
	PyObject *indent = NULL, *post_indent = NULL, *item = NULL;
	
	if (!serialize_check_recursion (s, value))
	{ return 0; }
	
	if (!serializer_separators (s, indent_level, &indent, &post_indent))
	{ goto error; }
	
	if (!s->append_ascii (s, "[", 1))
	{ goto error; }
	
	while ((item = PyIter_Next (iter)))
	{
		if (first)
		{ first = 0; }
		else if (!s->append_ascii (s, ",", 1))
		{ goto error; }
		
		if (indent && !s->append_unicode (s, indent))
		{ goto error; }
		
		if (!serialize_object (s, item, indent_level + 1, 0))
		{ goto error; }
		
		Py_DECREF (item);
		continue;
	}
	
	if (post_indent)
	{
		if (!s->append_unicode (s, post_indent))
		{ goto error; }
	}
	
	if (!s->append_ascii (s, "]", 1))
	{ goto error; }
	
	goto success;
error:
	retval = 0;
success:
	Py_XDECREF (indent);
	Py_XDECREF (post_indent);
	Py_XDECREF (item);
	Py_ReprLeave (value);
	return retval;
}

static unsigned char
serialize_atom (Serializer *s, PyObject *value)
{
	ModuleState *m = s->module;
	unsigned char retval;
	
	if (value == Py_True)
	{ return s->append_unicode (s, m->true_str); }
	
	if (value == Py_False)
	{ return s->append_unicode (s, m->false_str); }
	
	if (value == Py_None)
	{ return s->append_unicode (s, m->null_str); }
	
	/* Built-in types */
	if (PyUnicode_Check (value))
	{ return serialize_string (s, value); }
	
	if (PyLong_Check (value))
	{
		PyObject *str;
		if (!(str = PyObject_Str (value)))
		{ return 0; }
		retval = s->append_unicode (s, str);
		Py_DECREF (str);
		return retval;
	}
	if (PyFloat_Check (value))
	{ return serialize_float (s, value); }
	
	if (PyComplex_Check (value))
	{ return serialize_complex (s, value); }
	
	if (PyObject_IsInstance (value, m->Decimal))
	{ return serialize_decimal (s, value); }
	
	PyErr_SetString (
		PyExc_AssertionError,
		"value is atomic");
	return 0;
}

static unsigned char
serialize_string (Serializer *s, PyObject *value)
{
	// TODO
	return 1;
}

static unsigned char
serialize_float (Serializer *s, PyObject *value)
{
	PyObject *repr;
	unsigned char retval;
	double val = PyFloat_AS_DOUBLE (value);
	
	if (Py_IS_NAN (val))
	{ return serializer_raise (s, "no_nan"); }
	
	if (Py_IS_INFINITY (val))
	{
		if (val < 0)
		{ return serializer_raise (s, "no_neg_infinity"); }
		
		return serializer_raise (s, "no_infinity");
	}
	
	if (!(repr = PyObject_Repr (value)))
	{ return 0; }
	
	retval = s->append_unicode (s, repr);
	Py_DECREF (repr);
	return retval;
}

static unsigned char
serialize_complex (Serializer *s, PyObject *value)
{
	Py_complex complex = PyComplex_AsCComplex (value);
	PyObject *real, *repr = NULL;
	unsigned char retval = 1;
	
	if (complex.imag != 0)
	{ return serializer_raise (s, "no_imaginary"); }
	
	if (!(real = PyFloat_FromDouble (complex.real)))
	{ return 0; }
	
	repr = PyObject_Repr (real);
	Py_DECREF (real);
	
	if (repr)
	{ retval = s->append_unicode (s, repr); }
	
	Py_XDECREF (repr);
	return retval;
}

static unsigned char
serialize_decimal (Serializer *s, PyObject *value)
{
	PyObject *str = NULL;
	const char *error = NULL;
	unsigned char retval = 1;
	
	if (!(str = PyObject_Str (value)))
	{ return 0; }
	
	if (PyUnicode_CompareWithASCIIString (str, "Infinity") == 0)
	{ error = "no_infinity"; }
	
	else if (PyUnicode_CompareWithASCIIString (str, "-Infinity") == 0)
	{ error = "no_neg_infinity"; }
	
	else if (PyUnicode_CompareWithASCIIString (str, "NaN") == 0)
	{ error = "no_nan"; }
	
	if (error)
	{ retval = serializer_raise (s, error); }
	else
	{ retval = s->append_unicode (s, str); }
	
	Py_DECREF (str);
	return retval;
}

static unsigned char
serializer_raise (Serializer *s, const char *error_key)
{
	PyObject_CallMethod (s->error_helper, (char*)error_key, "");
	return 0;
}

static unsigned char
serializer_is_atomic (Serializer *s, PyObject *value)
{
	int is_decimal;
	
	if (value == Py_True ||
	    value == Py_False ||
	    value == Py_None ||
	    PyLong_Check (value) ||
	    PyFloat_Check (value) ||
	    PyComplex_Check (value) ||
	    PyUnicode_Check (value))
	{ return 1; }
	
	is_decimal = PyObject_IsInstance (value, s->module->Decimal);
	return (is_decimal > 0);
}

static unsigned char
buffer_serializer_append_ascii (Serializer *base,
                                const char *text,
                                size_t len)
{
	BufferSerializer *s = (BufferSerializer *) base;
	size_t ii;
	
	if (!buffer_serializer_resize (s, len))
	{ return 0; }
	
	for (ii = 0; ii < len; ii++)
	{ s->buffer[s->buffer_size++] = text[ii]; }
	
	return 1;
}

static unsigned char
buffer_serializer_append_unicode (Serializer *base, PyObject *text)
{
	size_t len;
	Py_UNICODE *raw;
	BufferSerializer *s = (BufferSerializer *) base;
	
	raw = PyUnicode_AS_UNICODE (text);
	len = PyUnicode_GET_SIZE (text);
	
	if (!buffer_serializer_resize (s, len))
	{ return 0; }
	
	memcpy (s->buffer + s->buffer_size, raw,
	        len * sizeof (Py_UNICODE));
	s->buffer_size += len;
	return 1;
}

static unsigned char
buffer_serializer_resize (BufferSerializer *s, size_t delta)
{
	size_t new_size;
	Py_UNICODE *new_buf;
	
	new_size = s->buffer_size + delta;
	if (s->buffer_max_size >= new_size)
	{ return 1; }
	
	if (!s->buffer)
	{
		new_size = (delta > INITIAL_BUFFER_SIZE? delta : INITIAL_BUFFER_SIZE);
		new_size = next_power_2 (1, new_size);
		s->buffer = PyMem_Malloc (sizeof (Py_UNICODE) * new_size);
		s->buffer_max_size = new_size;
		return 1;
	}
	
	new_size = next_power_2 (s->buffer_max_size, new_size);
	new_buf = PyMem_Realloc (s->buffer, sizeof (Py_UNICODE) * new_size);
	if (!new_buf)
	{
		PyMem_Free (s->buffer);
		return 0;
	}
	s->buffer = new_buf;
	s->buffer_max_size = new_size;
	return 1;
}
/* }}} */

/* Python module setup {{{ */
static PyMethodDef jsonlib_methods[] = {
	{"read_impl", jsonlib_read, METH_VARARGS, NULL},
	{"write_impl", jsonlib_write, METH_VARARGS, NULL},
	{NULL, NULL, 0, NULL}
};

static struct PyModuleDef jsonlib_module = {
	PyModuleDef_HEAD_INIT,
	"_jsonlib",
	NULL,
	sizeof (ModuleState),
	jsonlib_methods
};

static PyObject *
from_import (const char *module_name, const char *attr_name)
{
	PyObject *module, *attr = NULL;
	if ((module = PyImport_ImportModule (module_name)))
	{
		attr = PyObject_GetAttrString (module, attr_name);
		Py_DECREF (module);
	}
	return attr;
}

PyMODINIT_FUNC
PyInit__jsonlib (void)
{
	PyObject *module;
	ModuleState *state;
	
	/* TODO: error checking */
	module = PyModule_Create (&jsonlib_module);
	state = PyModule_GetState (module);
	
	/* External types */
	state->Decimal = from_import ("decimal", "Decimal");
	state->UserString = from_import ("collections", "UserString");
	
	/* Constant strings */
	state->true_str = ascii_constant ("true", -1);
	state->false_str = ascii_constant ("false", -1);
	state->null_str = ascii_constant ("null", -1);
	state->quote = ascii_constant ("\"", -1);
	return module;
}
/* }}} */
