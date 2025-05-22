/*
 * python.h -- python module header file
 * UPDATED VERSION with additional function declarations
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#define PY_OK 0
#undef putserv

// Additional function declarations for improved functionality
extern PyObject *pirp, *pglobals;
extern PyObject *loaded_scripts;
extern int rehash_in_progress;

// Function prototypes for enhanced features
void python_bind_destroyed(ClientData cd);
char *detect_python_executable(void);
void add_bind_to_list(struct PythonBind *bind);
void remove_bind_from_list(struct PythonBind *bind);

// Hook constants for rehash handling
#ifndef HOOK_PRE_REHASH
#define HOOK_PRE_REHASH 100
#endif

#ifndef HOOK_POST_REHASH  
#define HOOK_POST_REHASH 101
#endif
