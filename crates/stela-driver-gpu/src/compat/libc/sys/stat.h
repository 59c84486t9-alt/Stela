/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_SYS_STAT_H
#define STELA_LIBC_SYS_STAT_H
#include <sys/types.h>
#include <time.h>
#define S_IFMT 0170000
#define S_IFCHR 0020000
#define S_IFDIR 0040000
#define S_IFREG 0100000
#define S_ISCHR(mode) (((mode) & S_IFMT) == S_IFCHR)
#define S_ISDIR(mode) (((mode) & S_IFMT) == S_IFDIR)
#define S_ISREG(mode) (((mode) & S_IFMT) == S_IFREG)
#define S_IRUSR 0400
#define S_IWUSR 0200
#define S_IRWXU 0700
struct stat {
	dev_t st_dev, st_rdev;
	ino_t st_ino;
	mode_t st_mode;
	nlink_t st_nlink;
	uid_t st_uid;
	gid_t st_gid;
	off_t st_size;
	blksize_t st_blksize;
	blkcnt_t st_blocks;
	struct timespec st_atim, st_mtim, st_ctim;
};
#define st_mtime st_mtim.tv_sec
int stat(const char *path, struct stat *result);
int fstat(int fd, struct stat *result);
int lstat(const char *path, struct stat *result);
int mkdir(const char *path, mode_t mode);
#endif
