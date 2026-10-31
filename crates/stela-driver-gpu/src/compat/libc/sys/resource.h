/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_SYS_RESOURCE_H
#define STELA_LIBC_SYS_RESOURCE_H
#define RLIMIT_NOFILE 7
#define PRIO_PROCESS 0
typedef unsigned long rlim_t;
struct rlimit {
	rlim_t rlim_cur, rlim_max;
};
int setpriority(int which, int who, int priority);
int getrlimit(int resource, struct rlimit *limit);
#endif
