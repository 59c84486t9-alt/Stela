/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_SYS_TIME_H
#define STELA_LIBC_SYS_TIME_H
#include <time.h>
struct timeval {
	time_t tv_sec;
	long tv_usec;
};
int gettimeofday(struct timeval *time, void *zone);
#endif
