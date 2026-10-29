/* SPDX-License-Identifier: MIT */
#ifndef STELA_PAGE_H
#define STELA_PAGE_H
#include <linux/types.h>

/* One retained, permanently mapped, contiguous RAM reservation. A generation
 * is nonzero and strictly newer than every successfully registered catalog.
 * The 4 KiB page count and both bases are immutable until unregister succeeds.
 * The reservation alone grants no ownership of its ordinary heap/metadata
 * bytes: only successful page allocations publish live Linux descriptors. */
struct stela_linux_page_reservation {
	u64 generation;
	u64 physical_base;
	void *cpu_base;
	size_t page_count;
};

/* A successful allocation transfers one platform pin. The pin retains its
 * mapping and immutable physical list until release. It must contain exactly
 * 2^order consecutive 4 KiB pages, aligned to that extent in CPU and physical
 * space, at the corresponding offset of the registered reservation. It must
 * exclude every ordinary heap/metadata allocation and all other live pins.
 * Invalid output is refused and its pin retired without publishing pages. */
struct stela_linux_page_allocation {
	void *pin;
	void *cpu_base;
	const u64 *physical_pages;
	size_t page_count;
};

struct stela_linux_page_ops {
	/* Pure request preflight, before allocation/retirement activity. Zero
	 * admits this exact context and request, negative errno refuses it. */
	int (*validate)(void *context, u32 gfp, unsigned int order, bool atomic);
	/* Zero transfers the output pin; a negative errno transfers nothing and
	 * leaves output empty. GFP is the original Linux bit mask. atomic means
	 * the serialized context cannot sleep, including RCU callbacks. Refuse
	 * unsupported requirements with -EOPNOTSUPP, exhaustion with -ENOMEM.
	 * Callbacks may inspect context or probe try_enter, but may not invoke
	 * Linux services, enqueue Linux work or alter the owner, preemption count
	 * or simulated IRQ state. */
	int (*allocate)(void *context, u32 gfp, unsigned int order, bool atomic,
			struct stela_linux_page_allocation *allocation);
	/* Invoked once at checked quiescence, never from atomic context. Logical
	 * retirement queues pins allocation-free until finish/owner exit. */
	void (*release)(void *context, void *pin);
};

/* Call inside a quiescent entered Linux owner. Registration copies the input;
 * callback code/context and the reservation must remain retained until a
 * successful unregister. Register is fallible and publishes nothing on error.
 * Unregister drains retired pins, returns -EBUSY for live payloads, and rejects
 * a stale generation. A failed unregister relinquishes no lifetime. */
int stela_linux_page_catalog_register(const struct stela_linux_page_reservation *reservation,
				     const struct stela_linux_page_ops *ops, void *context);
int stela_linux_page_catalog_unregister(u64 generation);
/* Immutable multi-extent admission into the SAME canonical descriptor owner.
 * Every entry has the same generation and satisfies the actual retained WB
 * reservation contract above. Entries are sorted by physical_base, with no
 * physical or CPU overlap; sparse guard pages are not entries. Descriptors
 * remain stable until full retirement. Adding/growing extents while registered
 * is refused, including adjacent PFNs: no escaped descriptor is reallocated.
 * This explicit immutable contract is not dynamic sparse-memory admission. */
int stela_linux_page_catalog_register_extents(
    const struct stela_linux_page_reservation *extents, size_t extent_count,
    const struct stela_linux_page_ops *ops, void *context);
void stela_linux_pages_finish(void);
/* Explicit bounded service diagnostic, not GPU or native-IRQ qualification.
 * Requires quiescent entry; owns and retires only its temporary allocations. */
int stela_linux_page_catalog_verify(u64 generation);

/* Pinned-header classifiers for an ordinary RAM provider. Basic accepts only
 * ZERO/COMP/NOWARN/NOMEMALLOC, reclaim/IO/FS permissions and configuration-inert
 * ACCOUNT. Blocking tests DIRECT_RECLAIM; a provider must also check !atomic.
 * These queries are pure and require no entered owner. __GFP_NOFAIL is always
 * explicitly unsupported by this fallible service: it is reported to the
 * owner (`stela_linux_unsupported`) and returns NULL. */
bool stela_linux_page_request_basic(u32 gfp);
/* Separate policy: requires RECLAIMABLE and otherwise the same basic flags.
 * A real provider may explicitly opt in to Linux's permitted unmovable RAM
 * fallback. No placement, migration, reclaim-progress or atomic grant follows. */
bool stela_linux_page_request_reclaimable(u32 gfp);
bool stela_linux_page_request_blocking(u32 gfp);
#endif
