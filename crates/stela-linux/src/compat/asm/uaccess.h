/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_STELA_UACCESS_H
#define _ASM_STELA_UACCESS_H
/* User pointers lie in the owner's clients' address spaces, which the owner's
 * services reach (kernel/usercopy.c). */
unsigned long raw_copy_from_user(void *to, const void __user *from, unsigned long n);
unsigned long raw_copy_to_user(void __user *to, const void *from, unsigned long n);

#include <asm-generic/uaccess.h>
#endif
