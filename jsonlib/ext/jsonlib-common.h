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

PyObject *
jsonlib_import (const char *module_name, const char *obj_name);

PyObject *
jsonlib_str_format (const char *tmpl, PyObject *args);
