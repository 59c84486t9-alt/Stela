/* SPDX-License-Identifier: MIT */
#ifndef STELA_FILE_H
#define STELA_FILE_H
#include <linux/init.h>
#include <linux/mm_types.h>
#include <linux/types.h>

/* How an owner's clients reach Linux's file-based drivers: open, ioctl
 * (file->f_op->unlocked_ioctl), close (fput) and mmap. Each client address
 * space is the owner's opaque `space`; the services copy_from_user,
 * copy_to_user, map_user and unmap_user reach into it. */
struct file;
struct inode;
struct stela_linux_mapping;

/* Releases a raw compatibility inode without VFS superblock ownership. */
void stela_linux_compat_iput(struct inode *inode);

struct file *stela_linux_reopen_unowned_path(void);

/* Opens a character device a driver registered, or returns a negative errno. */
int stela_linux_chrdev_open(dev_t device, unsigned int flags, struct file **file);

/* Closes a descriptor Linux code installed; descriptors are the owner's, one
 * table across its clients. */
void stela_linux_fd_close(int fd);

/* What a client does by descriptor, as its system calls would: each returns a
 * descriptor, or the driver's result, or a negative errno. */
int stela_linux_open(dev_t device, unsigned int flags);
int stela_linux_fd_dup(int fd);
long stela_linux_fd_device(int fd);
long stela_linux_ioctl(int fd, unsigned int request, void *argument);
/* Sleep while *word holds value, for at most `nanoseconds` (U64_MAX: no limit).
 * A client's thread is a Linux task, whose lock holders can run only if it does. */
void stela_linux_wait(const volatile unsigned int *word, unsigned int value, u64 nanoseconds);
/* Wake every sleeper of stela_linux_wait, to look at its word again. */
void stela_linux_wake(void);

/* Memory the owner holds, of physically contiguous runs of whole pages. */
struct stela_linux_run {
	u64 physical;
	u64 bytes;
};

/* A dma-buf of the runs, which must outlive it, as a descriptor; or a negative
 * errno. A driver maps it through the requester's DMA domain. */
int stela_linux_export(const struct stela_linux_run *runs, size_t count);

/* Invalidate native shared writers before zeroing a locked folio's new tail.
 * A mapped writer may have changed bytes the native owner cannot query. */
bool stela_linux_unmap_writable_folio(struct folio *folio);

/* Maps size bytes of file at offset into space at address, through the file's
 * mmap, or returns a negative errno. Pages arrive by the client's faults. */
int stela_linux_mmap(struct file *file, void *space, unsigned long address, size_t size,
		     u64 offset, bool writable, struct stela_linux_mapping **mapping);
void stela_linux_munmap(struct stela_linux_mapping *mapping);

/* stela_linux_mmap of a descriptor, writable, with every page faulted in: a
 * client that shares Stela's address space has no fault to take first. */
int stela_linux_map(int fd, void *space, unsigned long address, size_t size, u64 offset,
		    struct stela_linux_mapping **mapping);

/* Serves a client's fault at address within the mapping, which installs pages
 * through map_user; a VM_FAULT_ result. */
vm_fault_t stela_linux_fault(struct stela_linux_mapping *mapping, unsigned long address,
			     bool write);

/* Whether a fault at address put a page back, as drivers answer NOPAGE. */
bool stela_linux_refault(struct stela_linux_mapping *mapping, unsigned long address, bool write);
#endif
