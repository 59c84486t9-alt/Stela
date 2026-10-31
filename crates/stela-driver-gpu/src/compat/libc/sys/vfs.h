/* SPDX-License-Identifier: MIT */
/* What LLVM's path code names. The image has no file systems: a caller fails
 * the link. */
#ifndef STELA_LIBC_SYS_VFS_H
#define STELA_LIBC_SYS_VFS_H
#include <sys/cdefs.h>
__BEGIN_DECLS
struct statfs {
	long f_type, f_bsize, f_flags;
	unsigned long f_blocks, f_bfree, f_bavail;
};
int statfs(const char *path, struct statfs *result);
int fstatfs(int fd, struct statfs *result);
__END_DECLS
#endif
