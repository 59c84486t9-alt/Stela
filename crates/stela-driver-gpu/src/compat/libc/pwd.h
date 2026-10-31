/* SPDX-License-Identifier: MIT */
/* What LLVM's path code names. The image has no users: a caller fails the link. */
#ifndef STELA_LIBC_PWD_H
#define STELA_LIBC_PWD_H
#include <sys/cdefs.h>
#include <stddef.h>
#include <sys/types.h>
__BEGIN_DECLS
struct passwd {
	char *pw_dir;
};
struct passwd *getpwnam(const char *name);
struct passwd *getpwuid(uid_t user);
int getpwnam_r(const char *name, struct passwd *entry, char *buffer, size_t size,
	       struct passwd **result);
int getpwuid_r(uid_t user, struct passwd *entry, char *buffer, size_t size,
	       struct passwd **result);
__END_DECLS
#endif
