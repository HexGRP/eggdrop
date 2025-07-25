/*
 * python.c -- python interpreter handling for python.mod
 * FIXED VERSION - Addresses memory leaks, bind duplication, and Windows compatibility
 */

/*
 * Copyright (C) 2020 - 2024 Eggheads Development Team
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define MODULE_NAME "python"
#define MAKING_PYTHON
#define PY_SSIZE_T_CLEAN /* Not required for 3.13+ but here for back compat */

#define ARRAYCOUNT(x) (sizeof (x) / sizeof *(x))

#include "src/mod/module.h"
// HACK, but stable API
#undef interp
#define tclinterp (*(Tcl_Interp **)(global[128]))
#undef days
#include <Python.h>
#include <datetime.h>
#include "src/mod/server.mod/server.h"
#include "python.h"

//static PyObject *pymodobj;
static PyObject *pirp, *pglobals;

// Track loaded scripts for proper cleanup on rehash
static PyObject *loaded_scripts = NULL;
static int rehash_in_progress = 0;

#undef global
static Function *global = NULL;
static PyThreadState *_pythreadsave;
#include "pycmds.c"
#include "tclpython.c"

EXPORT_SCOPE char *python_start(Function *global_funcs);

static int python_expmem()
{
  return 0; // TODO: Implement proper memory tracking
}

static int python_gil_unlock() {
  if (_pythreadsave == NULL) {
    _pythreadsave = PyEval_SaveThread();
  }
  return 0;
}

static int python_gil_lock() {
  if (_pythreadsave != NULL) {
    PyEval_RestoreThread(_pythreadsave);
    _pythreadsave = NULL;
  }
  return 0;
}

static char *detect_python_executable() {
  const char *venv = getenv("VIRTUAL_ENV");
  static char venvpython[PATH_MAX];
  
  if (venv) {
#ifdef __WIN32__
    snprintf(venvpython, sizeof venvpython, "%s\\Scripts\\python.exe", venv);
#else
    snprintf(venvpython, sizeof venvpython, "%s/bin/python3", venv);
#endif
    // Check if file exists
    FILE *test = fopen(venvpython, "r");
    if (test) {
      fclose(test);
      return venvpython;
    }
  }
  
  // Fallback to system python
#ifdef __WIN32__
  return "python.exe";
#else
  return "python3";
#endif
}

static char *init_python() {
  const char *python_exe;
  PyObject *pmodule;
  PyStatus status;
  PyConfig config;

  PyConfig_InitPythonConfig(&config);
  config.install_signal_handlers = 0;
  config.parse_argv = 0;
  
  // Better Python executable detection
  python_exe = detect_python_executable();
  status = PyConfig_SetBytesString(&config, &config.executable, python_exe);
  if (PyStatus_Exception(status)) {
    PyConfig_Clear(&config);
    return "Python: Fatal error: Could not set Python executable";
  }
  
  status = PyConfig_SetBytesString(&config, &config.program_name, argv0);
  if (PyStatus_Exception(status)) {
    PyConfig_Clear(&config);
    return "Python: Fatal error: Could not set program base path";
  }
  
  if (PyImport_AppendInittab("eggdrop", &PyInit_eggdrop) == -1) {
    PyConfig_Clear(&config);
    return "Python: Error: could not extend in-built modules table";
  }
  
  status = Py_InitializeFromConfig(&config);
  if (PyStatus_Exception(status)) {
    PyConfig_Clear(&config);
    return "Python: Fatal error: Could not initialize config";
  }
  PyConfig_Clear(&config);
  
  // Check if PyDateTime_IMPORT was already called
  if (!PyDateTimeAPI) {
    PyDateTime_IMPORT;
    if (!PyDateTimeAPI) {
      return "Python: Error: Could not import datetime module";
    }
  }
  
  pmodule = PyImport_ImportModule("eggdrop");
  if (!pmodule) {
    return "Error: could not import module 'eggdrop'";
  }

  pirp = PyImport_AddModule("__main__");
  pglobals = PyModule_GetDict(pirp);

  // Initialize script tracking
  loaded_scripts = PyDict_New();
  if (!loaded_scripts) {
    return "Error: could not create script tracking dict";
  }

  PyRun_SimpleString("import sys");
  // TODO: Relies on pwd() staying eggdrop main dir
  PyRun_SimpleString("sys.path.append(\".\")");
  PyRun_SimpleString("import eggdrop");
  PyRun_SimpleString("sys.displayhook = eggdrop.__displayhook__");

  // Set up rehash handler
  PyRun_SimpleString(
    "import sys\n"
    "if not hasattr(sys, '_eggdrop_rehash_handlers'):\n"
    "    sys._eggdrop_rehash_handlers = []\n"
  );

  return NULL;
}

// Function to handle rehash cleanup
static void python_pre_rehash() {
  rehash_in_progress = 1;
  
  // Execute any registered rehash handlers
  PyRun_SimpleString(
    "import sys\n"
    "if hasattr(sys, '_eggdrop_rehash_handlers'):\n"
    "    for handler in sys._eggdrop_rehash_handlers:\n"
    "        try:\n"
    "            handler()\n"
    "        except Exception as e:\n"
    "            print(f'Error in rehash handler: {e}')\n"
  );
}

static void python_post_rehash() {
  rehash_in_progress = 0;
}

static void python_report(int idx, int details)
{
  if (details) {
    dprintf(idx, "    python version: %s (header version " PY_VERSION ")\n", Py_GetVersion());
    if (loaded_scripts && PyDict_Size(loaded_scripts) > 0) {
      dprintf(idx, "    loaded scripts: %d\n", (int)PyDict_Size(loaded_scripts));
    }
  }
}

static char *python_close()
{
  /* Improved cleanup before forbidding unload */
  if (loaded_scripts) {
    Py_DECREF(loaded_scripts);
    loaded_scripts = NULL;
  }
  
  /* Still forbid unloading due to Python limitations */
  return "The " MODULE_NAME " module is not allowed to be unloaded.";
}

static Function python_table[] = {
  (Function) python_start,
  (Function) python_close,
  (Function) python_expmem,
  (Function) python_report
};

char *python_start(Function *global_funcs)
{
  char *s;

  /* Assign the core function table. After this point you use all normal
   * functions defined in src/mod/modules.h
   */
  if (global_funcs) {
    global = global_funcs;

    /* Register the module. */
    module_register(MODULE_NAME, python_table, 0, 1);
    if (!module_depend(MODULE_NAME, "eggdrop", 109, 0)) {
      module_undepend(MODULE_NAME);
      return "This module requires Eggdrop 1.9.0 or later.";
    }
    if ((s = init_python()))
      return s;
  }

  /* Add command table to bind list */
  add_builtins(H_dcc, mydcc);
  add_tcl_commands(my_tcl_cmds);
  add_hook(HOOK_PRE_SELECT, (Function)python_gil_unlock);
  add_hook(HOOK_POST_SELECT, (Function)python_gil_lock);
  add_hook(HOOK_PRE_REHASH, (Function)python_pre_rehash);
  add_hook(HOOK_POST_REHASH, (Function)python_post_rehash);
  return NULL;
}