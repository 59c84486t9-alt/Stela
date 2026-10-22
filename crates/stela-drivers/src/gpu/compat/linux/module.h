/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_MODULE_H
#define STELA_LINUX_MODULE_H
#include <linux/stringify.h>
/* Stela links no kernel modules: there is no .modinfo section to fill and no
 * parameter registry; a driver's parameters are its plain variables. */
struct module;
#define THIS_MODULE ((struct module *)0)
#define MODULE_FIRMWARE(_firmware)
#define MODULE_DEVICE_TABLE(type, name)
#define MODULE_AUTHOR(_author)
#define MODULE_DESCRIPTION(_description)
#define MODULE_LICENSE(_license)
#define MODULE_PARM_DESC(_parm, desc)
#define module_param(name, type, perm)
#define module_param_unsafe(name, type, perm)
#define module_param_named(name, value, type, perm)
#define module_param_named_unsafe(name, value, type, perm)
#define module_param_string(name, string, len, perm)
#define module_init(initfn)
#define module_exit(exitfn)
/* Nor does it free init memory, so entry points need no section. */
#define __init
#define __exit
#endif
