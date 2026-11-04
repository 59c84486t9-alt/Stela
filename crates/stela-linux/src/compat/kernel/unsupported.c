// SPDX-License-Identifier: MIT
/* Kernel services Stela does not provide yet. */
#include <linux/folio_batch.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/platform_device.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/swap.h>
#include <linux/workqueue.h>
#include <stela/linux.h>
#include <unsupported.h>

/* Pages behind shmem files and shmem-backed GEM objects, which swap and
 * nouveau's TTM objects never need: TTM allocates pages from its own pool and
 * Stela never reclaims them. */
STELA_UNSUPPORTED(struct folio *, shmem_read_folio_gfp, struct address_space *, pgoff_t, gfp_t)
STELA_UNSUPPORTED(struct page *, shmem_read_mapping_page_gfp, struct address_space *, pgoff_t,
		  gfp_t)
STELA_UNSUPPORTED(void, shmem_truncate_range, struct inode *, loff_t, uoff_t)
struct swap_iocb;
STELA_UNSUPPORTED(int, shmem_writeout, struct folio *, struct swap_iocb **, struct list_head *)
STELA_UNSUPPORTED(bool, folio_clear_dirty_for_io, struct folio *)
/* Transparent huge mappings of shmem-backed objects. */
STELA_UNSUPPORTED(unsigned long, mm_get_unmapped_area, struct file *, unsigned long,
		  unsigned long, unsigned long, unsigned long)
/* debugfs's seq_file operations, which no file opens: Stela has no debugfs. */
STELA_UNSUPPORTED(int, single_open, struct file *, int (*)(struct seq_file *, void *), void *)
STELA_UNSUPPORTED(int, single_release, struct inode *, struct file *)
STELA_UNSUPPORTED(ssize_t, seq_read, struct file *, char __user *, size_t, loff_t *)
STELA_UNSUPPORTED(loff_t, seq_lseek, struct file *, loff_t, int)
/* Platform devices, of which only HDMI audio codecs reach DRM. */
STELA_UNSUPPORTED(void, platform_device_unregister, struct platform_device *)

/* Workqueues that run their work in softirq context. */
STELA_UNSUPPORTED_OBJECT(struct workqueue_struct *, system_bh_wq);
STELA_UNSUPPORTED_OBJECT(struct workqueue_struct *, system_bh_highpri_wq);
