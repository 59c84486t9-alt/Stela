/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef STELA_LIBC_SCHED_H
#define STELA_LIBC_SCHED_H
#include <sys/cdefs.h>
__BEGIN_DECLS
int sched_yield(void);
int sched_getcpu(void);
__END_DECLS
#endif
