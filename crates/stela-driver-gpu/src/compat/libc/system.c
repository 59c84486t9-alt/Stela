// SPDX-License-Identifier: MIT
/* The operating system LLVM's Support library expects, which nothing the image
 * runs reaches on a path that matters: there are no files, users, signals or
 * dates, so each call fails the way POSIX lets it and LLVM reports the error. */
#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

static int refused(void)
{
	errno = ENOSYS;
	return -1;
}

char *getcwd(char *path, size_t size)
{
	(void)path;
	(void)size;
	errno = ENOSYS;
	return NULL;
}

int chdir(const char *path)
{
	(void)path;
	return refused();
}

int link(const char *from, const char *to)
{
	(void)from;
	(void)to;
	return refused();
}

int symlink(const char *from, const char *to)
{
	(void)from;
	(void)to;
	return refused();
}

int fchown(int fd, uid_t user, gid_t group)
{
	(void)fd;
	(void)user;
	(void)group;
	return refused();
}

int chmod(const char *path, mode_t mode)
{
	(void)path;
	(void)mode;
	return refused();
}

int fchmod(int fd, mode_t mode)
{
	(void)fd;
	(void)mode;
	return refused();
}

mode_t umask(mode_t mask)
{
	(void)mask;
	return 0;
}

int statfs(const char *path, struct statfs *result)
{
	(void)path;
	(void)result;
	return refused();
}

int fstatfs(int fd, struct statfs *result)
{
	(void)fd;
	(void)result;
	return refused();
}

DIR *opendir(const char *path)
{
	(void)path;
	errno = ENOSYS;
	return NULL;
}

struct dirent *readdir(DIR *directory)
{
	(void)directory;
	errno = EBADF;
	return NULL;
}

int closedir(DIR *directory)
{
	(void)directory;
	errno = EBADF;
	return -1;
}

int msync(void *address, size_t size, int flags)
{
	(void)address;
	(void)size;
	(void)flags;
	return refused();
}

int setrlimit(int resource, const struct rlimit *limit)
{
	(void)resource;
	(void)limit;
	return refused();
}

int sigprocmask(int how, const sigset_t *set, sigset_t *saved)
{
	(void)how;
	(void)set;
	(void)saved;
	return refused();
}

/* No such user: POSIX's success with no entry. */
int getpwnam_r(const char *name, struct passwd *entry, char *buffer, size_t size, struct passwd **result)
{
	(void)name;
	(void)entry;
	(void)buffer;
	(void)size;
	*result = NULL;
	return 0;
}

int getpwuid_r(uid_t user, struct passwd *entry, char *buffer, size_t size, struct passwd **result)
{
	(void)user;
	(void)entry;
	(void)buffer;
	(void)size;
	*result = NULL;
	return 0;
}

struct tm *gmtime_r(const time_t *time, struct tm *result)
{
	(void)time;
	(void)result;
	errno = EOVERFLOW;
	return NULL;
}

/* Zero: the date did not fit. */
size_t strftime(char *buffer, size_t size, const char *format, const struct tm *time)
{
	(void)buffer;
	(void)size;
	(void)format;
	(void)time;
	return 0;
}
