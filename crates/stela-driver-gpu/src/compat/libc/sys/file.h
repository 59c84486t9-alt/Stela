/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_SYS_FILE_H
#define STELA_LIBC_SYS_FILE_H
#include <sys/cdefs.h>
__BEGIN_DECLS
#define LOCK_SH 1
#define LOCK_EX 2
#define LOCK_NB 4
#define LOCK_UN 8
int flock(int fd, int operation);
__END_DECLS
#endif
