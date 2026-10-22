/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_STELA_UACCESS_H
#define _ASM_STELA_UACCESS_H
/* Linux code under Stela serves no user space, so no user pointer is valid:
 * the kernel-API's copies fail as Linux's do on a fault, copying nothing. */
unsigned long raw_copy_from_user(void *to, const void __user *from, unsigned long n);
unsigned long raw_copy_to_user(void __user *to, const void *from, unsigned long n);

#include <asm-generic/uaccess.h>
#endif
