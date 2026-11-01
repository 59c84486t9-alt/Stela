/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_SYS_MMAN_H
#define STELA_LIBC_SYS_MMAN_H
#include <sys/cdefs.h>
#include <sys/types.h>
__BEGIN_DECLS
#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_SHARED 1
#define MAP_PRIVATE 2
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_ANON MAP_ANONYMOUS
#define MAP_NORESERVE 0x4000
#define MAP_FAILED ((void *)-1)
#define MS_SYNC 4
#define MFD_CLOEXEC 1
#define MFD_ALLOW_SEALING 2
#define MADV_RANDOM 1
#define MADV_WILLNEED 3
#define MADV_DONTNEED 4
#define MADV_DONTFORK 10
void *mmap(void *address, size_t size, int protection, int flags, int fd, off_t offset);
int munmap(void *address, size_t size);
int memfd_create(const char *name, unsigned int flags);
int mprotect(void *address, size_t size, int protection);
int madvise(void *address, size_t size, int advice);
int msync(void *address, size_t size, int flags);
__END_DECLS
#endif
