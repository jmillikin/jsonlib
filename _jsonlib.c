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

/* Parser {{{ */
typedef struct _ParserModuleState
{
	PyObject *Decimal;
} ParserModuleState;

typedef struct _Parser
{
	Py_UNICODE *start, *end, *index;
	PyObject *error_helper;
	ParserModuleState *module;
	
	Py_UNICODE *stringparse_buffer;
	size_t stringparse_buffer_size;
	
	unsigned int use_float: 1;
	unsigned int got_root: 1;
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
parse_unicode_escape (Parser *);

static PyObject *
parse_keyword (Parser *);

static PyObject *
parse_number (Parser *);

static unsigned char
skip_whitespace (Parser *, Py_UNICODE *, const char *);

static unsigned char
skip_char (Parser *, Py_UNICODE, const char *);

static Py_UCS4
next_char_ord (Py_UNICODE *);

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
	PyObject *retval = NULL, *key, *value;
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
	PyObject *retval = NULL, *value;
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
			/* TODO */
			buffer[buffer_idx++] = 'u';
			break;
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
	return PyObject_CallMethod (parser->error_helper, error_key, "uk",
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

static PyMethodDef jsonlib_methods[] = {
	{"read_impl", jsonlib_read, METH_VARARGS, NULL},
	{NULL, NULL, 0, NULL}
};

static struct PyModuleDef jsonlib_module = {
	PyModuleDef_HEAD_INIT,
	"_jsonlib",
	NULL,
	sizeof (ParserModuleState),
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
	ParserModuleState *state;
	
	module = PyModule_Create (&jsonlib_module);
	state = PyModule_GetState (module);
	state->Decimal = from_import ("decimal", "Decimal");
	return module;
}
