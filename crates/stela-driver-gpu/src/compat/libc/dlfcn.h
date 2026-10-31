/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_DLFCN_H
#define STELA_LIBC_DLFCN_H
#include <sys/cdefs.h>
__BEGIN_DECLS
#define RTLD_LAZY 1
#define RTLD_NOW 2
#define RTLD_LOCAL 0
#define RTLD_DEFAULT ((void *)0)
typedef struct {
	const char *dli_fname;
	void *dli_fbase;
	const char *dli_sname;
	void *dli_saddr;
} Dl_info;
/* The image is linked whole, so nothing loads and nothing can be found. */
void *dlopen(const char *file, int flags);
void *dlsym(void *handle, const char *name);
int dlclose(void *handle);
const char *dlerror(void);
int dladdr(const void *address, Dl_info *info);
__END_DECLS
#endif
