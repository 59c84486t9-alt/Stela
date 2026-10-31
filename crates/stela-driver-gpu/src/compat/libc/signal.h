/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_SIGNAL_H
#define STELA_LIBC_SIGNAL_H
#include <sys/cdefs.h>
#include <sys/types.h>
__BEGIN_DECLS
typedef int sig_atomic_t;
typedef struct {
	unsigned long bits;
} sigset_t;
#define SIGABRT 6
#define SIGTRAP 5
#define SIGSEGV 11
#define SIGSYS 31
#define SIG_BLOCK 0
#define SIG_SETMASK 2
int sigfillset(sigset_t *set);
int sigdelset(sigset_t *set, int signal);
int pthread_sigmask(int how, const sigset_t *set, sigset_t *saved);
int sigprocmask(int how, const sigset_t *set, sigset_t *saved);
int raise(int signal);
__END_DECLS
#endif
