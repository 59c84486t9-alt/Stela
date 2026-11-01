/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_SYS_SYSINFO_H
#define STELA_LIBC_SYS_SYSINFO_H
#include <sys/cdefs.h>
__BEGIN_DECLS
/* The field lavapipe reads, in units of mem_unit bytes. */
struct sysinfo {
	unsigned long totalram;
	unsigned int mem_unit;
};
int sysinfo(struct sysinfo *info);
__END_DECLS
#endif
