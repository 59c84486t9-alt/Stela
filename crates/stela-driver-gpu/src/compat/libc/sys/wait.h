/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_SYS_WAIT_H
#define STELA_LIBC_SYS_WAIT_H
#include <sys/cdefs.h>
#include <sys/types.h>
__BEGIN_DECLS
#define WNOHANG 1
#define WIFEXITED(status) (((status) & 0x7f) == 0)
#define WEXITSTATUS(status) (((status) >> 8) & 0xff)
#define WIFSIGNALED(status) (((status) & 0x7f) != 0)
#define WTERMSIG(status) ((status) & 0x7f)
pid_t waitpid(pid_t process, int *status, int options);
__END_DECLS
#endif
