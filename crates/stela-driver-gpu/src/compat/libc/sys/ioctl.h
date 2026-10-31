/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_SYS_IOCTL_H
#define STELA_LIBC_SYS_IOCTL_H
#include <sys/cdefs.h>
__BEGIN_DECLS
int ioctl(int fd, unsigned long request, ...);
__END_DECLS
#endif
