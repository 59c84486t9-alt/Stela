// SPDX-License-Identifier: MIT
/* Kernel services Stela does not provide yet. */
#include <linux/io.h>
#include <linux/rcupdate.h>
#include <linux/workqueue.h>
#include <stela/linux.h>
#include <unsupported.h>

/* Mapping system memory needs its owner, which Linux code under Stela does
 * not have yet: memremap maps nothing, Linux's answer when a mapping fails. */
void *memremap(resource_size_t offset, size_t size, unsigned long flags)
{
	(void)offset;
	(void)size;
	(void)flags;
	stela_linux_unsupported("memremap");
	return NULL;
}
/* Nothing memremap returned can reach it. */
STELA_UNSUPPORTED(void, memunmap, void *)

/* Workqueues that run their work in softirq context. */
STELA_UNSUPPORTED_OBJECT(struct workqueue_struct *, system_bh_wq);
STELA_UNSUPPORTED_OBJECT(struct workqueue_struct *, system_bh_highpri_wq);
