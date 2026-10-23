/* SPDX-License-Identifier: MIT */
#ifndef STELA_MODULE_H
#define STELA_MODULE_H
/* Module registration in Stela's images, which load no modules and run no
 * initcalls: a built-in driver's init and exit functions and its device
 * tables are registered nowhere. Linux would put them in initcall sections,
 * which reference every function a driver's init reaches, and alias its
 * device tables, which Mach-O hosts reject. An adapter that compiles a
 * module's registration includes this first; macros expand where they are
 * used, so the module's own sources then register nothing. */
#include <linux/module.h>

#undef module_init
#define module_init(fn)
#undef module_exit
#define module_exit(fn)
#undef MODULE_DEVICE_TABLE
#define MODULE_DEVICE_TABLE(type, name)
#endif
