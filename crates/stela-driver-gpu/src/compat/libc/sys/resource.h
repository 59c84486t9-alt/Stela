/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_SYS_RESOURCE_H
#define STELA_LIBC_SYS_RESOURCE_H
#include <sys/cdefs.h>
__BEGIN_DECLS
#define RLIMIT_DATA 2
#define RLIMIT_STACK 3
#define RLIMIT_CORE 4
#define RLIMIT_RSS 5
#define RLIMIT_NOFILE 7
#define RLIMIT_AS 9
#define PRIO_PROCESS 0
typedef unsigned long rlim_t;
struct rlimit {
	rlim_t rlim_cur, rlim_max;
};
int setpriority(int which, int who, int priority);
int getrlimit(int resource, struct rlimit *limit);
int setrlimit(int resource, const struct rlimit *limit);
__END_DECLS
#endif
