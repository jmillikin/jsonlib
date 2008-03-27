#include "jsonlib-common.h"

PyObject *
jsonlib_get_imported_obj (const char *module_name, const char *obj_name)
{
	PyObject *module, *obj = NULL;
	if ((module = PyImport_ImportModule (module_name)))
	{
		obj = PyObject_GetAttrString (module, obj_name);
		Py_DECREF (module);
	}
	return obj;
}

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