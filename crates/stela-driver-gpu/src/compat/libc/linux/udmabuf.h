/* SPDX-License-Identifier: MIT */
/* The stride this device gives llvmpipe, by the kernel's names. */
#ifndef STELA_LIBC_LINUX_UDMABUF_H
#define STELA_LIBC_LINUX_UDMABUF_H
#include <linux/ioctl.h>
#include <linux/types.h>

#define UDMABUF_FLAGS_CLOEXEC 0x01

struct udmabuf_create {
	__u32 memfd;
	__u32 flags;
	__u64 offset;
	__u64 size;
};

#define UDMABUF_CREATE _IOW('u', 0x42, struct udmabuf_create)

#endif
