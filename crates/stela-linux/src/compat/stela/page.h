/* SPDX-License-Identifier: MIT */
#ifndef STELA_PAGE_H
#define STELA_PAGE_H
#include <linux/types.h>
struct stela_linux_owner;
/* Pure current-owner/quiescence check; no entry, callback or ownership change. */
int stela_linux_page_owner_context(const struct stela_linux_owner *expected);

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

/* Separate versioned table: never append/read a tail on the original ops.
 * Readiness is a nonblocking observation of this exact retained pin's actual
 * ownership fences. False retains it and all descriptor allocation markers;
 * it does not mean release completed. It may not allocate, reenter Linux,
 * change current/preemption/IRQ state or transfer any pin ownership. */
#define STELA_LINUX_PAGE_OPS_V2 2U
struct stela_linux_page_ops_v2 {
    u32 version;
    u32 bytes;
    struct stela_linux_page_ops ordinary;
    bool (*release_ready)(void *context, void *pin);
};

/* Call inside a quiescent entered Linux owner. Registration copies the input;
 * callback code/context and the reservation must remain retained until a
 * successful unregister. Register is fallible and publishes nothing on error.
 * Unregister drains ready retired pins, returns -EBUSY for live payloads or
 * pins still awaiting owner acknowledgment, and rejects
 * a stale generation. A failed unregister relinquishes no lifetime. */
int stela_linux_page_catalog_register(const struct stela_linux_page_reservation *reservation,
				     const struct stela_linux_page_ops *ops, void *context);
int stela_linux_page_catalog_unregister(u64 generation);
/* Irreversible whole-kernel retention for the original initial resource caches.
 * Requires the same quiescent entered owner; no payload/current is granted.
 * Ordinary task/object references still require their original final release. */
int stela_linux_page_catalog_retain_kernel(u64 generation);
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
int stela_linux_page_catalog_register_extents_v2(
    const struct stela_linux_page_reservation *extents, size_t extent_count,
    const struct stela_linux_page_ops_v2 *ops, void *context);
/* Annotated immutable inventory, versioned separately from earlier records.
 * RuntimeStack coverage stays reserved after every unpublished admission is
 * cancelled; ordinary GFP allocation cannot consume it. Payload ownership
 * remains in the caller's actual cold pin. No C stack is lent by these APIs. */
#define STELA_LINUX_PAGE_INVENTORY_V3 3U
#define STELA_LINUX_PAGE_ORDINARY 0U
#define STELA_LINUX_PAGE_RUNTIME_STACK 1U
struct stela_linux_page_extent_v3 {
    struct stela_linux_page_reservation reservation;
    u32 kind;
    u32 reserved;
};
struct stela_linux_page_inventory_v3 {
    u32 version;
    u32 bytes;
    const struct stela_linux_page_extent_v3 *extents;
    size_t count;
};
int stela_linux_page_catalog_register_annotated(
    const struct stela_linux_page_inventory_v3 *inventory,
    const struct stela_linux_page_ops_v2 *ops, void *context);

/* Private descriptor reservation only: no payload pin/refcount transfer and
 * no page/address return. The caller retains actual allocation/mapping/cold
 * ownership through cancellation or permanent quarantine. All calls require
 * the serialized quiescent entered owner. Headers admit tails before use. */
#define STELA_LINUX_STACK_ADMISSION_V1 1U
struct stela_linux_stack_admission_v1 {
    u32 version;
    u32 bytes;
    u64 generation;
    void *cpu_base;
    const u64 *physical_pages;
    size_t page_count;
};
struct stela_linux_stack_ticket_v1 {
    u32 version;
    u32 bytes;
    u64 generation;
    size_t record;
    u64 nonce;
};
int stela_linux_page_stack_admit(
    const struct stela_linux_stack_admission_v1 *request,
    struct stela_linux_stack_ticket_v1 *ticket);
int stela_linux_page_stack_cancel(const struct stela_linux_stack_ticket_v1 *ticket);
/* Private original-child descriptor lease ABI. The actual affine Rust native
 * pin remains the payload owner. actual_child is opaque source factory identity,
 * never a task/current constructor; caller proves actual copy_process custody.
 * Lend creates the real original noncompound THREAD_SIZE page allocation. It
 * does not zero/reseed already-prepared native frame bytes. Ordinary original
 * free_thread_stack/__free_pages performs logical release, preserving markers.
 * Cancel is ONLY unpublished and refuses every published descriptor graph. */
struct stela_linux_owner;
int stela_linux_page_stack_source_context(const struct stela_linux_owner *expected);
int stela_linux_page_stack_lend(const struct stela_linux_stack_ticket_v1 *ticket,
                              const void *actual_child, void **cpu_base);
/* Bounded real-current/IF0 source validation. No sleep/allocation/publication. */
int stela_linux_page_stack_prepare_publish(
    const struct stela_linux_stack_ticket_v1 *ticket, const void *actual_child);
/* Source nofail commit after nativeDormant accepted, before source PID/tasklist
 * publication. Corruption traps and retains; no ordinary refusal/cleanup. */
void stela_linux_page_stack_publish(const struct stela_linux_stack_ticket_v1 *ticket,
                                 const void *actual_child);
/* Private unsafe retirement boundary. Real process source reaper already
 * joined final task/stack/page/alias/RCU and actual native successor receipts.
 * Every outstanding descriptor/DMA ref independently refuses removal. This
 * never frees the Rust physical pin or authorizes native stack reseeding. */
int stela_linux_page_stack_retire(const struct stela_linux_stack_ticket_v1 *ticket,
                               const void *actual_child);


void stela_linux_pages_finish(void);
/* Entered serialized owner only. Pin one live aligned physical page's actual
 * provider allocation before exposing it to DMA. NULL transfers nothing.
 * Each non-NULL token prevents allocation/descriptor/provider retirement even
 * after Linux logically frees all its pages; release it only after successful
 * device quiescence and domain unmap. An uncertain map/unmap must keep it.
 * Tokens can repeat for pages belonging to the same allocation; every success
 * requires exactly one unpin. Unpin does not invoke the provider or allocate. */
void *stela_linux_page_dma_pin(u64 physical);
void stela_linux_page_dma_unpin(void *pin);
/* Opaque affine allocation ref plus its original provider pin and exact CPU
 * page. The Rust producer binds the original Context/generation and clones
 * that Pin's actual PinnedPages before any caller can expose a mapping. */
struct stela_linux_mapping_page { void *record, *provider_pin, *cpu_page; };
int stela_linux_page_mapping_pin(u64 generation, const void *context,
 const struct stela_linux_owner *owner, u64 physical, struct stela_linux_mapping_page *);
int stela_linux_page_mapping_unpin(u64 generation, const void *context,
 const struct stela_linux_owner *owner, void *record);
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
