/* SPDX-License-Identifier: MIT */
#ifndef STELA_MODULE_H
#define STELA_MODULE_H
/* Partial helper builds erase module registration as before. Explicitly
 * selected built-in cohorts opt into typed capture after original Linux
 * declarations, retaining their actual callbacks and descriptor identities. */
#include <linux/module.h>

#if defined(STELA_LINUX_CAPTURE_REGISTRATIONS)
#include <stela/registration.h>
#else

#undef module_init
#define module_init(fn)
#undef module_exit
#define module_exit(fn)
#undef MODULE_DEVICE_TABLE
#define MODULE_DEVICE_TABLE(type, name)
#endif /* explicit registry opt-in versus partial helper builds */
#endif
