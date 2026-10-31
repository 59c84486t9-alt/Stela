/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_UNISTD_H
#define STELA_LIBC_UNISTD_H
#include <sys/cdefs.h>
#include <stddef.h>
#include <sys/types.h>
__BEGIN_DECLS
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#define F_OK 0
#define R_OK 4
#define W_OK 2
#define X_OK 1
#define _POSIX_TIMERS 200809L
#define _SC_PAGESIZE 30
#define _SC_NPROCESSORS_ONLN 84
#define _SC_PHYS_PAGES 85
#define _SC_GETPW_R_SIZE_MAX 70
int close(int fd);
ssize_t read(int fd, void *buffer, size_t size);
ssize_t write(int fd, const void *buffer, size_t size);
off_t lseek(int fd, off_t offset, int whence);
int dup(int fd);
int ftruncate(int fd, off_t size);
int dup2(int from, int to);
int access(const char *path, int mode);
int isatty(int fd);
int unlink(const char *path);
ssize_t readlink(const char *path, char *buffer, size_t size);
long sysconf(int name);
char *getcwd(char *path, size_t size);
int chdir(const char *path);
int link(const char *from, const char *to);
int symlink(const char *from, const char *to);
int fchown(int fd, uid_t user, gid_t group);
unsigned int alarm(unsigned int seconds);
pid_t getpid(void);
pid_t gettid(void);
uid_t getuid(void);
uid_t geteuid(void);
gid_t getgid(void);
gid_t getegid(void);
int usleep(unsigned int micros);
unsigned int sleep(unsigned int seconds);
int getpagesize(void);
__END_DECLS
#endif
