/* SPDX-License-Identifier: MIT */
/* What LLVM's path code names. The image has no directories: a caller fails
 * the link. */
#ifndef STELA_LIBC_DIRENT_H
#define STELA_LIBC_DIRENT_H
#include <sys/cdefs.h>
#include <sys/types.h>
__BEGIN_DECLS
#define DT_UNKNOWN 0
#define DT_FIFO 1
#define DT_CHR 2
#define DT_DIR 4
#define DT_BLK 6
#define DT_REG 8
#define DT_LNK 10
#define DT_SOCK 12
typedef struct stela_libc_directory DIR;
struct dirent {
	unsigned char d_type;
	char d_name[256];
};
DIR *opendir(const char *path);
struct dirent *readdir(DIR *directory);
int closedir(DIR *directory);
__END_DECLS
#endif
