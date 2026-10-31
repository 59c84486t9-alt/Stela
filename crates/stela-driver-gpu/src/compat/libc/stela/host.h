/* SPDX-License-Identifier: MIT */
/* What the C library needs of the host, which Rust supplies (`mesa::libc`). */
#ifndef STELA_LIBC_HOST_H
#define STELA_LIBC_HOST_H
#include <sys/cdefs.h>
#include <stddef.h>
#include <stdint.h>
__BEGIN_DECLS

/* Allocation from the host's heap, of exactly the size and alignment given back. */
void *stela_libc_allocate(size_t size, size_t alignment);
void stela_libc_release(void *pointer, size_t size, size_t alignment);
/* One line or part of one for the host's log. */
void stela_libc_log(const char *text, size_t size);
_Noreturn void stela_libc_fatal(const char *message);
/* Monotonic nanoseconds. */
uint64_t stela_libc_now_ns(void);
/* This host processor or Mesa thread, below STELA_LIBC_CORES. */
unsigned int stela_libc_core(void);
#define STELA_LIBC_PROCESSORS 256
#define STELA_LIBC_THREADS 16
#define STELA_LIBC_CORES (STELA_LIBC_PROCESSORS + STELA_LIBC_THREADS)
/* Run body(argument) as a thread on its own stack, with stela_libc_core()
 * answering core for it; 0 or a negative errno. */
int stela_libc_thread_start(void (*body)(void *), void *argument, unsigned int core);
/* Wait while *word holds value, until the deadline in stela_libc_now_ns()'s
 * nanoseconds; UINT64_MAX is no deadline. It may return early. */
void stela_libc_wait(const volatile unsigned int *word, unsigned int value, uint64_t deadline);
/* Tell whoever waits on a word that was changed. */
void stela_libc_wake(const volatile unsigned int *word);

/* What a process does with DRM's files, on Linux's own descriptors. Each runs
 * in the Linux environment and returns a negative errno on failure. */
int stela_libc_drm_open(unsigned int minor);
int stela_libc_drm_close(int fd);
int stela_libc_drm_dup(int fd);
/* The descriptor's device number. */
long stela_libc_drm_rdev(int fd);
/* `argument` is in-process. */
int stela_libc_drm_ioctl(int fd, unsigned long request, void *argument);
/* A pointer, or a negative errno. Every page is mapped on return. */
void *stela_libc_drm_mmap(int fd, uint64_t offset, size_t size);
/* Whether the address came from `stela_libc_drm_mmap`. */
int stela_libc_drm_munmap(void *address, size_t size);
/* The render nodes' count, and one's PCI location and IDs. */
unsigned int stela_libc_drm_devices(void);
struct stela_libc_drm_device {
	uint16_t segment, vendor, device, subsystem_vendor, subsystem_device;
	uint8_t bus, slot, function, revision;
};
void stela_libc_drm_device(unsigned int index, struct stela_libc_drm_device *device);
__END_DECLS
#endif
