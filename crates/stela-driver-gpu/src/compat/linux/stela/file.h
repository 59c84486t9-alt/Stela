/* SPDX-License-Identifier: MIT */
#ifndef STELA_FILE_H
#define STELA_FILE_H
#include <linux/mm_types.h>
#include <linux/types.h>

/* How an owner's clients reach Linux's file-based drivers: open, ioctl
 * (file->f_op->unlocked_ioctl), close (fput) and mmap. Each client address
 * space is the owner's opaque `space`; the services copy_from_user,
 * copy_to_user, map_user and unmap_user reach into it. */
struct file;
struct stela_linux_mapping;

/* Opens a character device a driver registered, or returns a negative errno. */
int stela_linux_chrdev_open(dev_t device, unsigned int flags, struct file **file);

/* Closes a descriptor Linux code installed; descriptors are the owner's, one
 * table across its clients. */
void stela_linux_fd_close(int fd);

/* Maps size bytes of file at offset into space at address, through the file's
 * mmap, or returns a negative errno. Pages arrive by the client's faults. */
int stela_linux_mmap(struct file *file, void *space, unsigned long address, size_t size,
		     u64 offset, bool writable, struct stela_linux_mapping **mapping);
void stela_linux_munmap(struct stela_linux_mapping *mapping);

/* Serves a client's fault at address within the mapping, which installs pages
 * through map_user; a VM_FAULT_ result. */
vm_fault_t stela_linux_fault(struct stela_linux_mapping *mapping, unsigned long address,
			     bool write);
#endif
