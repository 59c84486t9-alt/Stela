// SPDX-License-Identifier: MIT
/* Original VMA offset/tag bookkeeping only. Local drm_file objects are opaque
 * identity tokens for this library fixture, not opened files or credentials.
 * All queried page spans are representable; a native mmap caller must validate
 * its real process and VMA arithmetic before entering this kernel-only API. */
#include <linux/errno.h>
#include <linux/string.h>
#include <drm/drm_file.h>
#include <drm/drm_vma_manager.h>
#include <stela/linux.h>
#include <stela/test.h>

static void offsets(void)
{
	struct drm_vma_offset_manager manager;
	struct drm_vma_offset_node a, b, c;
	memset(&manager, 0, sizeof(manager));
	drm_vma_node_reset(&a);
	drm_vma_node_reset(&b);
	drm_vma_node_reset(&c);
	drm_vma_offset_manager_init(&manager, 1024, 64);
	assert(!drm_vma_offset_add(&manager, &a, 8));
	assert(!drm_vma_offset_add(&manager, &b, 4));
	assert(drm_vma_node_start(&a) == 1024 && drm_vma_node_size(&a) == 8);
	assert(drm_vma_node_offset_addr(&a) == 1024ULL << PAGE_SHIFT);
	assert(drm_vma_node_start(&b) == 1032 && drm_vma_node_size(&b) == 4);
	stela_test_allocations_begin(true);
	/* Adding an existing node is idempotent even with a different size. */
	assert(!drm_vma_offset_add(&manager, &a, 64));
	struct stela_test_allocations attempts = stela_test_allocations_end();
	assert(!attempts.heap && !attempts.heap_try && !attempts.pages);
	assert(drm_vma_node_size(&a) == 8);
	assert(drm_vma_offset_add(&manager, &c, 65) == -ENOSPC);
	assert(!drm_vma_node_start(&c) && !drm_vma_node_size(&c));

	drm_vma_offset_lock_lookup(&manager);
	assert(drm_vma_offset_lookup_locked(&manager, 1024, 8) == &a);
	assert(drm_vma_offset_lookup_locked(&manager, 1026, 6) == &a);
	assert(!drm_vma_offset_lookup_locked(&manager, 1026, 7));
	assert(drm_vma_offset_exact_lookup_locked(&manager, 1024, 8) == &a);
	assert(!drm_vma_offset_exact_lookup_locked(&manager, 1026, 1));
	assert(drm_vma_offset_exact_lookup_locked(&manager, 1032, 4) == &b);
	assert(!drm_vma_offset_lookup_locked(&manager, 1023, 1));
	assert(!drm_vma_offset_lookup_locked(&manager, 1036, 1));
	drm_vma_offset_unlock_lookup(&manager);
	drm_vma_offset_remove(&manager, &a);
	assert(!drm_vma_node_start(&a) && !drm_vma_node_size(&a));
	drm_vma_offset_remove(&manager, &a);
	assert(!drm_vma_offset_add(&manager, &c, 4));
	/* Original BEST-fit chooses the reclaimed eight-page hole. */
	assert(drm_vma_node_start(&c) == 1024);
	drm_vma_offset_remove(&manager, &b);
	drm_vma_offset_remove(&manager, &c);
	drm_vma_offset_manager_destroy(&manager);
}

static void permissions(void)
{
	struct drm_file files[3] = {0};
	struct drm_vma_offset_manager manager;
	struct drm_vma_offset_node node;
	memset(&manager, 0, sizeof(manager));
	drm_vma_node_reset(&node);
	drm_vma_offset_manager_init(&manager, 2048, 16);
	assert(!drm_vma_node_is_allowed(&node, files));
	assert(drm_vma_node_verify_access(&node, files) == -EACCES);
	assert(!drm_vma_node_allow(&node, files));
	assert(!drm_vma_node_allow(&node, files));
	assert(!drm_vma_node_allow_once(&node, files + 1));
	assert(!drm_vma_node_allow_once(&node, files + 1));
	assert(drm_vma_node_is_allowed(&node, files));
	assert(drm_vma_node_is_allowed(&node, files + 1));
	assert(!drm_vma_node_is_allowed(&node, files + 2));
	assert(!drm_vma_node_verify_access(&node, files));

	stela_test_allocations_begin(true);
	/* The original preallocation can fail while a known tag still succeeds.
	 * A genuinely new tag must retain ENOMEM and acquire no permission. */
	assert(!drm_vma_node_allow(&node, files));
	assert(!drm_vma_node_allow_once(&node, files + 1));
	assert(drm_vma_node_allow(&node, files + 2) == -ENOMEM);
	assert(drm_vma_node_allow_once(&node, files + 2) == -ENOMEM);
	struct stela_test_allocations attempts = stela_test_allocations_end();
	assert(attempts.heap == 4 && !attempts.heap_try && !attempts.pages);
	assert(!drm_vma_node_is_allowed(&node, files + 2));
	assert(!drm_vma_offset_add(&manager, &node, 4));
	drm_vma_offset_remove(&manager, &node);
	assert(drm_vma_node_is_allowed(&node, files));
	assert(drm_vma_node_is_allowed(&node, files + 1));
	drm_vma_node_revoke(&node, files);
	drm_vma_node_revoke(&node, files);
	assert(drm_vma_node_is_allowed(&node, files));
	drm_vma_node_revoke(&node, files);
	assert(!drm_vma_node_is_allowed(&node, files));
	drm_vma_node_revoke(&node, files + 1);
	assert(!drm_vma_node_is_allowed(&node, files + 1));
	drm_vma_node_revoke(&node, files + 1);
	drm_vma_node_revoke(&node, files + 2);
	assert(RB_EMPTY_ROOT(&node.vm_files));
	drm_vma_offset_manager_destroy(&manager);
}

int main(void)
{
	stela_linux_enter(&stela_linux_bare);
	offsets();
	permissions();
	stela_linux_exit();
	printf("Linux DRM VMA: actual offset/best-fit/lookups, tag counts, once grants, OOM and revocation\n");
	return 0;
}
