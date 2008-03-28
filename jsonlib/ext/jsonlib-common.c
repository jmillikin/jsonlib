#include "jsonlib-common.h"

PyObject *
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
