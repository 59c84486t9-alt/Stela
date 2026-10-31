/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_FCNTL_H
#define STELA_LIBC_FCNTL_H
#include <sys/cdefs.h>
#include <sys/types.h>
__BEGIN_DECLS
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0100
#define O_EXCL 0200
#define O_NOCTTY 0400
#define O_TRUNC 01000
#define O_APPEND 02000
#define O_NONBLOCK 04000
#define O_CLOEXEC 02000000
#define F_DUPFD 0
#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define F_SETFL 4
#define F_GETLK 5
#define F_SETLK 6
#define F_SETLKW 7
#define F_DUPFD_CLOEXEC 1030
#define FD_CLOEXEC 1
#define F_RDLCK 0
#define F_WRLCK 1
#define F_UNLCK 2
struct flock {
	short l_type, l_whence;
	off_t l_start, l_len;
	pid_t l_pid;
};
int open(const char *path, int flags, ...);
int fcntl(int fd, int command, ...);
__END_DECLS
#endif
