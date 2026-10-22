/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_FAULT_INJECT_H
#define STELA_LINUX_FAULT_INJECT_H
/* As linux/error-injection.h defines it without CONFIG_FUNCTION_ERROR_INJECTION. */
#define ALLOW_ERROR_INJECTION(fname, _etype)
#endif
