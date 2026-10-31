/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_SYS_TIME_H
#define STELA_LIBC_SYS_TIME_H
#include <sys/cdefs.h>
#include <time.h>
__BEGIN_DECLS
struct timeval {
	time_t tv_sec;
	long tv_usec;
};
int gettimeofday(struct timeval *time, void *zone);
__END_DECLS
#endif
