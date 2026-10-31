/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_POLL_H
#define STELA_LIBC_POLL_H
#include <sys/cdefs.h>
__BEGIN_DECLS
struct pollfd {
	int fd;
	short events;
	short revents;
};
typedef unsigned long nfds_t;
#define POLLIN 1
#define POLLOUT 4
#define POLLERR 8
#define POLLHUP 16
#define POLLNVAL 32
int poll(struct pollfd *fds, nfds_t count, int timeout);
__END_DECLS
#endif
