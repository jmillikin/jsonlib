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
jsonlib_get_imported_obj (const char *module_name, const char *obj_name);
