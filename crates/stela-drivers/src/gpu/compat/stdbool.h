/* SPDX-License-Identifier: MIT */
#ifndef STELA_STDBOOL_H
#define STELA_STDBOOL_H
/* The <stdbool.h> Stela's own headers use in its Linux environment: Linux's
 * bool, false and true. */
#include <linux/stddef.h>
#include <linux/types.h>

#define __bool_true_false_are_defined 1
#endif
