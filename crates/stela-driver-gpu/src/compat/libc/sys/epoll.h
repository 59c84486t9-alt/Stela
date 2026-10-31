/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_SYS_EPOLL_H
#define STELA_LIBC_SYS_EPOLL_H
#include <stdint.h>
#define EPOLL_CLOEXEC 02000000
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLLIN 1
struct epoll_event {
	uint32_t events;
	union {
		void *ptr;
		int fd;
		uint64_t u64;
	} data;
} __attribute__((packed));
int epoll_create1(int flags);
int epoll_ctl(int instance, int operation, int fd, struct epoll_event *event);
#endif
