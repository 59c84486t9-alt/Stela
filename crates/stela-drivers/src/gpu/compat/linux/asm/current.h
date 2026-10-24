/* SPDX-License-Identifier: MIT */
#ifndef _ASM_STELA_CURRENT_H
#define _ASM_STELA_CURRENT_H
#ifndef __ASSEMBLY__
struct task_struct;
struct task_struct *stela_linux_current(void);
#define get_current() stela_linux_current()
#define current get_current()
#endif
#endif
