/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_TIME_H
#define STELA_LIBC_TIME_H
#include <sys/types.h>
typedef int clockid_t;
struct timespec {
	time_t tv_sec;
	long tv_nsec;
};
struct tm {
	int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday, tm_yday, tm_isdst;
};
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID 3
#define TIME_UTC 1
#define TIMER_ABSTIME 1
int clock_gettime(clockid_t clock, struct timespec *time);
int clock_nanosleep(clockid_t clock, int flags, const struct timespec *time,
		    struct timespec *remaining);
int nanosleep(const struct timespec *time, struct timespec *remaining);
int timespec_get(struct timespec *time, int base);
time_t time(time_t *result);
struct tm *localtime_r(const time_t *time, struct tm *result);
struct tm *localtime(const time_t *time);
size_t strftime(char *buffer, size_t size, const char *format, const struct tm *time);
#endif
