/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_ERRNO_H
#define STELA_LIBC_ERRNO_H
int *__errno_location(void);
#define errno (*__errno_location())
#define EPERM 1
#define ENOENT 2
#define ESRCH 3
#define EINTR 4
#define EIO 5
#define ENXIO 6
#define E2BIG 7
#define EBADF 9
#define EAGAIN 11
#define EWOULDBLOCK EAGAIN
#define ENOMEM 12
#define EACCES 13
#define EFAULT 14
#define EBUSY 16
#define EEXIST 17
#define ENODEV 19
#define ENOTDIR 20
#define EINVAL 22
#define EMFILE 24
#define ENOTTY 25
#define ENOSPC 28
#define ERANGE 34
#define EDEADLK 35
#define ENOSYS 38
#define EOVERFLOW 75
#define EOPNOTSUPP 95
#define ENOTSUP EOPNOTSUPP
#define ETIME 62
#define ETIMEDOUT 110
#define ECANCELED 125
#endif
