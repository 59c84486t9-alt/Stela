// SPDX-License-Identifier: GPL-2.0
/* Raw Linux pages backed by an explicitly retained platform reservation.
 * Descriptors follow PFNs, including across adjacent allocation boundaries.
 * Allocation records and live/run metadata are separate from struct page:
 * drivers retain the union fields Linux gives them. No native IRQ, userspace
 * mapping, page-cache, reclaim or DMA-domain ownership is inferred here. */
#include <linux/errno.h>
#include <linux/build_bug.h>
#include <linux/gfp.h>
#include <linux/irqflags.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/poison.h>
#include <linux/preempt.h>
#include <linux/string.h>
#include <stela/linux.h>
#include <stela/page.h>

#define NO_INDEX SIZE_MAX

/* HVO's masked tail encoding additionally requires a globally aligned
 * vmemmap. This catalog uses the pinned configuration's direct head encoding. */
static_assert(!IS_ENABLED(CONFIG_HUGETLB_PAGE_OPTIMIZE_VMEMMAP));

struct page_state {
	size_t allocation;
	size_t run_first;
	unsigned int run_order;
	bool live;
	bool compound;
};

/* At most one pin per reservation page. Reserving a record before calling the
 * platform also permits allocation-free rollback of malformed provider output
 * that cannot be associated with any valid PFN. */
struct allocation_record {
	void *pin;
	size_t first;
	size_t count;
	size_t live;
	size_t next;
};

static struct {
	struct stela_linux_page_reservation reservation;
	struct stela_linux_page_ops ops;
	void *context;
	struct page *pages;
	struct page_state *state;
	struct allocation_record *allocations;
	size_t free_records;
	size_t retired;
	size_t live_pages;
} catalog;
static u64 last_generation;
static bool in_callback;

#ifdef STELA_LINUX_PAGE_TEST
static size_t metadata_fail_after = NO_INDEX;
static size_t metadata_live;
#endif

static void *allocate_metadata(size_t size, size_t align)
{
#ifdef STELA_LINUX_PAGE_TEST
	if (metadata_fail_after != NO_INDEX) {
		if (!metadata_fail_after)
			return NULL;
		metadata_fail_after--;
	}
#endif
	void *object = stela_linux_heap_alloc(size, align);
#ifdef STELA_LINUX_PAGE_TEST
	if (object)
		metadata_live++;
#endif
	return object;
}

static void free_metadata(void *object, size_t size, size_t align)
{
#ifdef STELA_LINUX_PAGE_TEST
	if (!metadata_live)
		__builtin_trap();
	metadata_live--;
#endif
	stela_linux_heap_free(object, size, align);
}

static void require_context(void)
{
	(void)stela_linux_owner();
	if (in_callback)
		__builtin_trap();
}

static void require_quiescence(void)
{
	require_context();
	if (!stela_linux_quiescent())
		__builtin_trap();
}

static void require_catalog(void)
{
	require_context();
	if (!catalog.pages)
		__builtin_trap();
}

bool stela_linux_page_request_basic(u32 gfp)
{
	gfp_t allowed = __GFP_ZERO | __GFP_COMP | __GFP_NOWARN | __GFP_NOMEMALLOC |
		__GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM | __GFP_IO | __GFP_FS;
	if (!IS_ENABLED(CONFIG_MEMCG))
		allowed |= __GFP_ACCOUNT;
	return !(gfp & ~(__force u32)allowed);
}

bool stela_linux_page_request_blocking(u32 gfp)
{
	return gfpflags_allow_blocking((__force gfp_t)gfp);
}

static void initialize_page(struct page *page)
{
	memset(page, 0, sizeof(*page));
	INIT_LIST_HEAD(&page->lru);
	atomic_set(&page->_mapcount, -1);
	set_page_count(page, 0);
}

int stela_linux_page_catalog_register(const struct stela_linux_page_reservation *reservation,
				     const struct stela_linux_page_ops *ops, void *context)
{
	require_quiescence();
	if (catalog.pages)
		return -EBUSY;
	if (!reservation || !ops || !ops->validate || !ops->allocate || !ops->release ||
	    !reservation->generation || reservation->generation <= last_generation ||
	    !reservation->cpu_base || !reservation->page_count ||
	    ((unsigned long)reservation->cpu_base & ~PAGE_MASK) ||
	    (reservation->physical_base & (PAGE_SIZE - 1)) ||
	    reservation->page_count > (size_t)SSIZE_MAX / PAGE_SIZE ||
	    reservation->page_count > (ULONG_MAX - (unsigned long)reservation->cpu_base) / PAGE_SIZE ||
	    reservation->page_count > (U64_MAX - reservation->physical_base) / PAGE_SIZE ||
	    reservation->page_count > (size_t)SSIZE_MAX / sizeof(struct page) ||
	    reservation->page_count > (size_t)SSIZE_MAX / sizeof(struct page_state) ||
	    reservation->page_count > (size_t)SSIZE_MAX / sizeof(struct allocation_record))
		return -EINVAL;
	size_t count = reservation->page_count;
	struct page *pages = allocate_metadata(count * sizeof(*pages), __alignof__(*pages));
	if (!pages)
		return -ENOMEM;
	struct page_state *state = allocate_metadata(count * sizeof(*state), __alignof__(*state));
	if (!state) {
		free_metadata(pages, count * sizeof(*pages), __alignof__(*pages));
		return -ENOMEM;
	}
	struct allocation_record *allocations = allocate_metadata(count * sizeof(*allocations),
								__alignof__(*allocations));
	if (!allocations) {
		free_metadata(state, count * sizeof(*state), __alignof__(*state));
		free_metadata(pages, count * sizeof(*pages), __alignof__(*pages));
		return -ENOMEM;
	}
	for (size_t i = 0; i < count; i++) {
		initialize_page(pages + i);
		state[i].allocation = NO_INDEX;
		allocations[i].next = i + 1 < count ? i + 1 : NO_INDEX;
	}
	catalog.reservation = *reservation;
	catalog.ops = *ops;
	catalog.context = context;
	catalog.pages = pages;
	catalog.state = state;
	catalog.allocations = allocations;
	catalog.free_records = 0;
	catalog.retired = NO_INDEX;
	last_generation = reservation->generation;
	return 0;
}

static size_t page_index(const struct page *page)
{
	require_catalog();
	unsigned long address = (unsigned long)page;
	unsigned long base = (unsigned long)catalog.pages;
	size_t bytes = catalog.reservation.page_count * sizeof(*catalog.pages);
	if (address < base || address - base >= bytes ||
	    (address - base) % sizeof(*catalog.pages))
		__builtin_trap();
	size_t index = (address - base) / sizeof(*catalog.pages);
	if (!catalog.state[index].live)
		__builtin_trap();
	return index;
}

static size_t physical_index(phys_addr_t address)
{
	require_catalog();
	u64 base = catalog.reservation.physical_base;
	u64 bytes = (u64)catalog.reservation.page_count * PAGE_SIZE;
	if (address < base || address - base >= bytes)
		__builtin_trap();
	size_t index = (size_t)((address - base) >> PAGE_SHIFT);
	if (!catalog.state[index].live)
		__builtin_trap();
	return index;
}

struct page *pfn_to_page(unsigned long pfn)
{
	if (pfn > (U64_MAX >> PAGE_SHIFT))
		__builtin_trap();
	return catalog.pages + physical_index((phys_addr_t)pfn << PAGE_SHIFT);
}

unsigned long page_to_pfn(const struct page *page)
{
	size_t index = page_index(page);
	return (unsigned long)(catalog.reservation.physical_base >> PAGE_SHIFT) + index;
}

unsigned long __phys_addr(unsigned long address)
{
	require_catalog();
	unsigned long base = (unsigned long)catalog.reservation.cpu_base;
	size_t bytes = catalog.reservation.page_count * PAGE_SIZE;
	if (address < base || address - base >= bytes)
		__builtin_trap();
	size_t offset = address - base;
	if (!catalog.state[offset >> PAGE_SHIFT].live)
		__builtin_trap();
	return (unsigned long)catalog.reservation.physical_base + offset;
}

void *__phys_to_virt(phys_addr_t address)
{
	size_t index = physical_index(address);
	size_t offset = (index << PAGE_SHIFT) + (size_t)(address & (PAGE_SIZE - 1));
	return (u8 *)catalog.reservation.cpu_base + offset;
}

/* The callback may call ordinary native services, but cannot change Linux's
 * borrowed execution state. The single execution lock protects this catalog. */
static void check_callback(const struct stela_linux_owner *owner, int nesting,
			   unsigned long flags)
{
	if (stela_linux_owner() != owner || preempt_count() != nesting ||
	    arch_local_save_flags() != flags)
		__builtin_trap();
}

static void recycle_record(size_t index)
{
	catalog.allocations[index] = (struct allocation_record){.next = catalog.free_records};
	catalog.free_records = index;
}

static void queue_record(size_t index)
{
	struct allocation_record *record = catalog.allocations + index;
	if (!record->pin || record->live)
		__builtin_trap();
	record->next = catalog.retired;
	catalog.retired = index;
}

void stela_linux_pages_finish(void)
{
	require_quiescence();
	if (!catalog.pages)
		return;
	const struct stela_linux_owner *owner = stela_linux_owner();
	while (catalog.retired != NO_INDEX) {
		size_t index = catalog.retired;
		struct allocation_record *record = catalog.allocations + index;
		catalog.retired = record->next;
		if (!record->pin || record->live)
			__builtin_trap();
		in_callback = true;
		catalog.ops.release(catalog.context, record->pin);
		in_callback = false;
		check_callback(owner, 0, ARCH_IRQ_ENABLED);
		for (size_t i = 0; i < record->count; i++) {
			struct page_state *state = catalog.state + record->first + i;
			if (state->live || state->allocation != index)
				__builtin_trap();
			state->allocation = NO_INDEX;
		}
		recycle_record(index);
	}
}

int stela_linux_page_catalog_unregister(u64 generation)
{
	require_quiescence();
	if (!catalog.pages || catalog.reservation.generation != generation)
		return -EINVAL;
	stela_linux_pages_finish();
	if (catalog.live_pages)
		return -EBUSY;
	size_t count = catalog.reservation.page_count;
	free_metadata(catalog.allocations, count * sizeof(*catalog.allocations),
		      __alignof__(*catalog.allocations));
	free_metadata(catalog.state, count * sizeof(*catalog.state), __alignof__(*catalog.state));
	free_metadata(catalog.pages, count * sizeof(*catalog.pages), __alignof__(*catalog.pages));
	memset(&catalog, 0, sizeof(catalog));
	return 0;
}

static bool overlaps(unsigned long start, size_t bytes, const void *object, size_t size)
{
	unsigned long address = (unsigned long)object;
	return start <= address ? address - start < bytes : start - address < size;
}

static bool validate_allocation(const struct stela_linux_page_allocation *allocation,
				unsigned int order, size_t *first)
{
	size_t count = (size_t)1 << order;
	size_t bytes = count << PAGE_SHIFT;
	u64 base = catalog.reservation.physical_base;
	unsigned long cpu = (unsigned long)allocation->cpu_base;
	if (!allocation->pin || !allocation->cpu_base || !allocation->physical_pages ||
	    allocation->page_count != count || (cpu & (bytes - 1)))
		return false;
	u64 physical = allocation->physical_pages[0];
	if (physical < base || (physical & (bytes - 1)))
		return false;
	u64 offset = physical - base;
	if (offset >= (u64)catalog.reservation.page_count * PAGE_SIZE)
		return false;
	size_t index = (size_t)(offset >> PAGE_SHIFT);
	if (count > catalog.reservation.page_count - index ||
	    cpu != (unsigned long)catalog.reservation.cpu_base + (unsigned long)offset)
		return false;
	size_t total = catalog.reservation.page_count;
	if (overlaps(cpu, bytes, catalog.pages, total * sizeof(*catalog.pages)) ||
	    overlaps(cpu, bytes, catalog.state, total * sizeof(*catalog.state)) ||
	    overlaps(cpu, bytes, catalog.allocations, total * sizeof(*catalog.allocations)))
		return false;
	for (size_t i = 0; i < count; i++) {
		if (allocation->physical_pages[i] != physical + (u64)i * PAGE_SIZE ||
		    catalog.state[index + i].allocation != NO_INDEX)
			return false;
	}
	*first = index;
	return true;
}

struct page *__alloc_pages_noprof(gfp_t gfp, unsigned int order, int preferred_nid,
				nodemask_t *nodemask)
{
	require_context();
	if (gfp & __GFP_NOFAIL) {
		stela_linux_unsupported("page allocation with __GFP_NOFAIL");
		return NULL;
	}
	if (!catalog.pages || order > MAX_PAGE_ORDER ||
	    (preferred_nid != NUMA_NO_NODE && preferred_nid != 0) ||
	    (nodemask && !node_isset(0, *nodemask)))
		return NULL;
	bool atomic = !stela_linux_quiescent();
	const struct stela_linux_owner *owner = stela_linux_owner();
	int nesting = preempt_count();
	unsigned long flags = arch_local_save_flags();
	in_callback = true;
	int error = catalog.ops.validate(catalog.context, (__force u32)gfp, order, atomic);
	in_callback = false;
	check_callback(owner, nesting, flags);
	if (error) {
		if (error > 0)
			__builtin_trap();
		if (error == -EOPNOTSUPP)
			stela_linux_unsupported("native page allocation request");
		return NULL;
	}
	if (!atomic)
		stela_linux_pages_finish();
	if (catalog.free_records == NO_INDEX)
		return NULL;
	size_t record_index = catalog.free_records;
	struct allocation_record *record = catalog.allocations + record_index;
	catalog.free_records = record->next;
	*record = (struct allocation_record){0};
	struct stela_linux_page_allocation allocation = {0};
	in_callback = true;
	error = catalog.ops.allocate(catalog.context, (__force u32)gfp, order, atomic, &allocation);
	in_callback = false;
	check_callback(owner, nesting, flags);
	if (error) {
		if (error > 0 || allocation.pin || allocation.cpu_base ||
		    allocation.physical_pages || allocation.page_count)
			__builtin_trap();
		recycle_record(record_index);
		if (error == -EOPNOTSUPP)
			stela_linux_unsupported("native page allocation request");
		return NULL;
	}
	if (!allocation.pin)
		__builtin_trap();
	record->pin = allocation.pin;
	size_t first;
	if (!validate_allocation(&allocation, order, &first)) {
		queue_record(record_index);
		if (!atomic)
			stela_linux_pages_finish();
		return NULL;
	}
	size_t count = (size_t)1 << order;
	record->first = first;
	record->count = count;
	record->live = count;
	for (size_t i = 0; i < count; i++) {
		initialize_page(catalog.pages + first + i);
		catalog.state[first + i] = (struct page_state){
			.allocation = record_index, .run_first = first,
			.run_order = order, .live = true,
		};
	}
	catalog.live_pages += count;
	struct page *page = catalog.pages + first;
	set_page_count(page, 1);
	if (gfp & __GFP_ZERO)
		memset(allocation.cpu_base, 0, count << PAGE_SHIFT);
	if (order && (gfp & __GFP_COMP))
		prep_compound_page(page, order);
	return page;
}

struct folio *__folio_alloc_noprof(gfp_t gfp, unsigned int order, int preferred_nid,
				  nodemask_t *nodemask)
{
	struct folio *folio = (struct folio *)__alloc_pages_noprof(gfp | __GFP_COMP, order,
								preferred_nid, nodemask);
	if (folio && order)
		folio_set_large_rmappable(folio);
	return folio;
}

unsigned long get_free_pages_noprof(gfp_t gfp, unsigned int order)
{
	struct page *page = alloc_pages_noprof(gfp & ~__GFP_HIGHMEM, order);
	return page ? (unsigned long)page_address(page) : 0;
}

unsigned long get_zeroed_page_noprof(gfp_t gfp)
{
	return get_free_pages_noprof(gfp | __GFP_ZERO, 0);
}

/* Validate one logical run before changing its count or descriptors. The
 * platform pin may cover additional runs after split_page or partial release. */
static size_t run_index(struct page *page, unsigned int order)
{
	size_t first = page_index(page);
	struct page_state *state = catalog.state + first;
	if (order > MAX_PAGE_ORDER || state->run_first != first || state->run_order != order ||
	    PageTail(page) || !!PageHead(page) != state->compound ||
	    (state->compound && compound_order(page) != order))
		__builtin_trap();
	size_t count = (size_t)1 << order;
	if (count > catalog.reservation.page_count - first)
		__builtin_trap();
	for (size_t i = 0; i < count; i++) {
		struct page *part = page + i;
		struct page_state *item = state + i;
		if (!item->live || item->allocation != state->allocation || item->run_first != first ||
		    item->run_order != order || item->compound != state->compound ||
		    (i && (page_ref_count(part) || !!PageTail(part) != state->compound ||
			   (state->compound && compound_head(part) != page))) ||
		    atomic_read(&part->_mapcount) != -1)
			__builtin_trap();
	}
	return first;
}

void prep_compound_page(struct page *page, unsigned int order)
{
	size_t first = run_index(page, order);
	if (!order || PageHead(page) || page_ref_count(page) <= 0)
		__builtin_trap();
	size_t count = (size_t)1 << order;
	__SetPageHead(page);
	for (size_t i = 1; i < count; i++) {
		struct page *tail = page + i;
		tail->mapping = TAIL_MAPPING;
		set_compound_head(tail, page, order);
		set_page_private(tail, 0);
	}
	/* Pinned Linux mm/internal.h's compound initialization. These are real
	 * struct-folio fields over the first tail descriptors, not a side map. */
	struct folio *folio = (struct folio *)page;
	folio->_flags_1 = (folio->_flags_1 & ~0xffUL) | order;
#ifdef NR_PAGES_IN_LARGE_FOLIO
	folio->_nr_pages = 1U << order;
#endif
	atomic_set(&folio->_large_mapcount, -1);
	atomic_set(&folio->_nr_pages_mapped, 0);
	if (IS_ENABLED(CONFIG_MM_ID)) {
		folio->_mm_ids = 0;
		folio->_mm_id_mapcount[0] = -1;
		folio->_mm_id_mapcount[1] = -1;
	}
	atomic_set(&folio->_entire_mapcount, -1);
	atomic_set(&folio->_pincount, 0);
	if (order > 1)
		INIT_LIST_HEAD(&folio->_deferred_list);
	for (size_t i = 0; i < count; i++)
		catalog.state[first + i].compound = true;
}

void split_page(struct page *page, unsigned int order)
{
	size_t first = run_index(page, order);
	if (PageHead(page) || page_ref_count(page) <= 0)
		__builtin_trap();
	size_t count = (size_t)1 << order;
	for (size_t i = 0; i < count; i++) {
		if (i)
			set_page_count(page + i, 1);
		catalog.state[first + i].run_first = first + i;
		catalog.state[first + i].run_order = 0;
	}
}

static void retire_pages(size_t first, size_t count)
{
	size_t allocation = catalog.state[first].allocation;
	struct allocation_record *record = catalog.allocations + allocation;
	if (record->live < count || catalog.live_pages < count)
		__builtin_trap();
	for (size_t i = 0; i < count; i++) {
		if (!catalog.state[first + i].live || catalog.state[first + i].allocation != allocation)
			__builtin_trap();
		struct page *page = catalog.pages + first + i;
		bool compound = catalog.state[first + i].compound;
		bool head = !PageTail(page);
		unsigned long flags = page->flags.f;
		if (compound && first + i == catalog.state[first + i].run_first + 1)
			flags &= ~PAGE_FLAGS_SECOND;
		if ((flags & PAGE_FLAGS_CHECK_AT_FREE) || atomic_read(&page->_mapcount) != -1 ||
		    ((head || !compound) && page->mapping))
			__builtin_trap();
		if (compound && head) {
			struct folio *folio = (struct folio *)page;
			if (atomic_read(&folio->_large_mapcount) != -1 ||
			    atomic_read(&folio->_nr_pages_mapped) ||
			    atomic_read(&folio->_entire_mapcount) != -1 ||
			    atomic_read(&folio->_pincount) ||
			    (folio_order(folio) > 1 && !list_empty(&folio->_deferred_list)))
				__builtin_trap();
		}
	}
	for (size_t i = 0; i < count; i++) {
		catalog.state[first + i].live = false;
		initialize_page(catalog.pages + first + i);
	}
	record->live -= count;
	catalog.live_pages -= count;
	if (!record->live)
		queue_record(allocation);
}

void __free_pages(struct page *page, unsigned int order)
{
	if (!page)
		__builtin_trap();
	size_t first = run_index(page, order);
	if (page_ref_count(page) <= 0)
		__builtin_trap();
	bool compound = PageHead(page);
	if (put_page_testzero(page)) {
		retire_pages(first, (size_t)1 << order);
	} else if (!compound && order) {
		/* Linux drops noncompound tails even if a speculative reference
		 * retains the head; the eventual put_page frees only that head. */
		catalog.state[first].run_order = 0;
		retire_pages(first + 1, ((size_t)1 << order) - 1);
	}
}

void free_pages(unsigned long address, unsigned int order)
{
	require_context();
	if (!address)
		return;
	if (address & ~PAGE_MASK)
		__builtin_trap();
	__free_pages(virt_to_page(address), order);
}

void __folio_put(struct folio *folio)
{
	struct page *page = &folio->page;
	size_t first = page_index(page);
	struct page_state *state = catalog.state + first;
	unsigned int order = state->compound ? state->run_order : 0;
	if (page_ref_count(page) || PageTail(page) ||
	    !!PageHead(page) != state->compound || folio_order(folio) != order ||
	    folio_test_lru(folio) || folio_test_swapcache(folio) ||
	    folio_test_slab(folio) || folio_test_large_kmalloc(folio) || folio->mapping)
		__builtin_trap();
	/* Raw alloc_pages ownership only: no page-cache, userspace, slab or
	 * zone-device cleanup is silently discarded. A noncompound high-order
	 * allocation intentionally loses only its first page here, as Linux does. */
	if (state->compound)
		(void)run_index(page, order);
	else if (atomic_read(&page->_mapcount) != -1)
		__builtin_trap();
	retire_pages(first, (size_t)1 << order);
}

static bool verify_extent(struct page *page, unsigned int order)
{
	size_t count = (size_t)1 << order;
	u8 *cpu = page_address(page);
	unsigned long pfn = page_to_pfn(page);
	bool correct = pfn_to_page(pfn) == page && virt_to_page(cpu) == page;
	for (size_t i = 0; i < count; i++) {
		correct &= page_to_pfn(page + i) == pfn + i;
		correct &= page_address(page + i) == cpu + i * PAGE_SIZE;
	}
	for (size_t i = 0; i < count * PAGE_SIZE; i++)
		correct &= READ_ONCE(cpu[i]) == 0;
	size_t last = count * PAGE_SIZE - 1;
	WRITE_ONCE(cpu[0], 0x95);
	WRITE_ONCE(cpu[last], 0x6a);
	correct &= READ_ONCE(cpu[0]) == 0x95 && READ_ONCE(cpu[last]) == 0x6a;
	phys_addr_t physical = page_to_phys(page);
	correct &= __pa(cpu + last) == physical + last;
	correct &= __va(physical + last) == cpu + last;
	return correct;
}

int stela_linux_page_catalog_verify(u64 generation)
{
	require_quiescence();
	if (!catalog.pages || catalog.reservation.generation != generation)
		return -EINVAL;
	struct page *page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
		return -ENOMEM;
	bool correct = verify_extent(page, 0) && page_ref_count(page) == 1;
	get_page(page);
	correct &= page_ref_count(page) == 2;
	__free_page(page);
	correct &= page_ref_count(page) == 1;
	put_page(page);
	stela_linux_pages_finish();
	if (!correct)
		return -EIO;
	struct folio *folio = folio_alloc(GFP_KERNEL | __GFP_ZERO, 2);
	if (!folio)
		return -ENOMEM;
	page = &folio->page;
	correct = verify_extent(page, 2) && folio_order(folio) == 2 &&
		folio_test_large_rmappable(folio);
	for (size_t i = 1; i < 4; i++)
		correct &= PageTail(page + i) && compound_head(page + i) == page;
	get_page(page + 3);
	correct &= page_ref_count(page) == 2;
	__free_pages(page, 2);
	correct &= page_ref_count(page) == 1;
	put_page(page + 3);
	stela_linux_pages_finish();
	if (!correct)
		return -EIO;
	page = alloc_pages(GFP_KERNEL | __GFP_ZERO, 2);
	if (!page)
		return -ENOMEM;
	correct = verify_extent(page, 2) && !PageHead(page);
	split_page(page, 2);
	for (size_t i = 0; i < 4; i++) {
		correct &= page_ref_count(page + i) == 1 && !PageTail(page + i);
		__free_page(page + i);
	}
	stela_linux_pages_finish();
	if (!correct)
		return -EIO;
	page = alloc_pages(GFP_KERNEL | __GFP_ZERO, 2);
	if (!page)
		return -ENOMEM;
	correct = verify_extent(page, 2) && !PageHead(page);
	get_page(page);
	__free_pages(page, 2);
	correct &= page_ref_count(page) == 1;
	put_page(page);
	stela_linux_pages_finish();
	return correct ? 0 : -EIO;
}

#ifdef STELA_LINUX_PAGE_TEST
#include <linux/bottom_half.h>
#include <linux/rcupdate.h>
#include <linux/scatterlist.h>
#include <stela/test.h>

#define TEST_PAGES 16UL
#define TEST_PHYSICAL 0x23000000ULL

enum output_fault {
	OUTPUT_VALID,
	OUTPUT_WRONG_COUNT,
	OUTPUT_NONCONTIGUOUS,
	OUTPUT_CPU_OFFSET,
	OUTPUT_OUTSIDE,
	OUTPUT_OVERLAP,
};

struct test_pin {
	bool active;
	size_t first;
	size_t count;
	u64 physical[TEST_PAGES];
};

struct test_provider {
	u8 *cpu;
	bool used[TEST_PAGES];
	struct test_pin pins[TEST_PAGES];
	enum output_fault fault;
	unsigned int allocations;
	unsigned int releases;
	unsigned int validations;
	unsigned int unsupported;
	u32 seen_gfp;
	unsigned int seen_order;
	bool seen_atomic;
	bool refuse_atomic;
	bool exhausted;
	u64 overlap_physical;
};

static struct test_provider fixture;

static int test_validate(void *context, u32 gfp, unsigned int order, bool atomic)
{
	struct test_provider *provider = context;
	assert(!stela_linux_try_enter(&stela_linux_bare));
	provider->validations++;
	provider->seen_gfp = gfp;
	provider->seen_order = order;
	provider->seen_atomic = atomic;
	if (!stela_linux_page_request_basic(gfp) || (provider->refuse_atomic && atomic))
		return -EOPNOTSUPP;
	return 0;
}

static int test_allocate(void *context, u32 gfp, unsigned int order, bool atomic,
			 struct stela_linux_page_allocation *allocation)
{
	struct test_provider *provider = context;
	assert(provider->seen_gfp == gfp && provider->seen_order == order &&
	       provider->seen_atomic == atomic);
	provider->allocations++;
	if (provider->exhausted || order > 4)
		return -ENOMEM;
	size_t count = (size_t)1 << order;
	size_t first = TEST_PAGES;
	for (size_t i = 0; i + count <= TEST_PAGES; i += count) {
		bool available = true;
		for (size_t j = 0; j < count; j++)
			available &= !provider->used[i + j];
		if (available) {
			first = i;
			break;
		}
	}
	if (first == TEST_PAGES)
		return -ENOMEM;
	struct test_pin *pin = NULL;
	for (size_t i = 0; i < TEST_PAGES; i++) {
		if (!provider->pins[i].active) {
			pin = provider->pins + i;
			break;
		}
	}
	assert(pin);
	*pin = (struct test_pin){.active = true, .first = first, .count = count};
	for (size_t i = 0; i < count; i++) {
		provider->used[first + i] = true;
		pin->physical[i] = TEST_PHYSICAL + (u64)(first + i) * PAGE_SIZE;
	}
	/* The provider need not zero plain pages. ZERO must be enforced by the
	 * service before it publishes the payload. */
	memset(provider->cpu + first * PAGE_SIZE, 0xa7, count * PAGE_SIZE);
	*allocation = (struct stela_linux_page_allocation){
		.pin = pin, .cpu_base = provider->cpu + first * PAGE_SIZE,
		.physical_pages = pin->physical, .page_count = count,
	};
	switch (provider->fault) {
	case OUTPUT_VALID:
		break;
	case OUTPUT_WRONG_COUNT:
		allocation->page_count++;
		break;
	case OUTPUT_NONCONTIGUOUS:
		assert(count > 1);
		pin->physical[1] += PAGE_SIZE;
		break;
	case OUTPUT_CPU_OFFSET:
		allocation->cpu_base = (u8 *)allocation->cpu_base + PAGE_SIZE;
		break;
	case OUTPUT_OUTSIDE:
		pin->physical[0] = TEST_PHYSICAL - PAGE_SIZE;
		break;
	case OUTPUT_OVERLAP:
		assert(provider->overlap_physical);
		/* The deliberately wrong returned range must not alter the real
		 * pin's lifetime or the earlier pin's payload. */
		pin->physical[0] = provider->overlap_physical;
		allocation->cpu_base = provider->cpu +
			(size_t)(pin->physical[0] - TEST_PHYSICAL);
		break;
	}
	return 0;
}

static void test_release(void *context, void *token)
{
	struct test_provider *provider = context;
	struct test_pin *pin = token;
	assert(stela_linux_quiescent() && !stela_linux_try_enter(&stela_linux_bare));
	assert(pin->active);
	for (size_t i = 0; i < pin->count; i++) {
		assert(provider->used[pin->first + i]);
		provider->used[pin->first + i] = false;
	}
	pin->active = false;
	provider->releases++;
}

static void test_unsupported(void *context, const char *operation)
{
	struct test_provider *provider = context;
	assert(operation && *operation);
	provider->unsupported++;
}

static const struct stela_linux_page_ops test_ops = {
	.validate = test_validate, .allocate = test_allocate, .release = test_release,
};

static struct page *trap_page;

static void dead_descriptor(void)
{
	(void)page_to_pfn(trap_page);
}

static void unowned_physical(void)
{
	(void)pfn_to_page((TEST_PHYSICAL >> PAGE_SHIFT) + TEST_PAGES - 1);
}

static void unowned_virtual(void)
{
	(void)__pa(fixture.cpu + (TEST_PAGES - 1) * PAGE_SIZE);
}

static void interior_descriptor(void)
{
	(void)page_to_pfn((struct page *)((u8 *)trap_page + 1));
}

static void wrong_free_order(void)
{
	__free_pages(trap_page, 1);
}

static void null_free(void)
{
	__free_page(NULL);
}

static void free_compound_tail(void)
{
	__free_page(trap_page + 1);
}

static void split_compound(void)
{
	split_page(trap_page, 2);
}

static void finish_atomic(void)
{
	local_bh_disable();
	stela_linux_pages_finish();
}

static void register_atomic(void)
{
	local_bh_disable();
	(void)stela_linux_page_catalog_register(&catalog.reservation, &test_ops, &fixture);
}

static void mapped_free(void)
{
	trap_page->mapping = (struct address_space *)fixture.cpu;
	__free_page(trap_page);
}

static int unbalanced_validate(void *context, u32 gfp, unsigned int order, bool atomic)
{
	(void)context;
	(void)gfp;
	(void)order;
	(void)atomic;
	local_irq_disable();
	return 0;
}

static void unbalanced_callback(void)
{
	catalog.ops.validate = unbalanced_validate;
	(void)alloc_page(GFP_KERNEL);
}

static int reentrant_validate(void *context, u32 gfp, unsigned int order, bool atomic)
{
	(void)context;
	(void)gfp;
	(void)order;
	(void)atomic;
	(void)pfn_to_page(TEST_PHYSICAL >> PAGE_SHIFT);
	return 0;
}

static void reentrant_callback(void)
{
	catalog.ops.validate = reentrant_validate;
	(void)alloc_page(GFP_KERNEL);
}

static void noncompound_head_put(void)
{
	struct page *page = alloc_pages(GFP_KERNEL, 2);
	assert(page && !PageHead(page));
	unsigned long pfn = page_to_pfn(page);
	unsigned int releases = fixture.releases;
	put_page(page);
	/* Linux put_page on a noncompound high-order head does not retire its
	 * tail pages. Keep their backing and expose the leaked ownership. */
	for (size_t i = 1; i < 4; i++)
		assert(page_to_pfn(page + i) == pfn + i);
	assert(stela_linux_page_catalog_unregister(1) == -EBUSY);
	assert(fixture.releases == releases);
	(void)page_to_pfn(page);
}

struct page_callback {
	struct rcu_head head;
	struct page *page;
};

static void retire_callback(struct rcu_head *head)
{
	struct page_callback *callback = container_of(head, struct page_callback, head);
	assert(in_serving_softirq() && !stela_linux_quiescent());
	__free_page(callback->page);
}

static void refusal_and_rollback(void)
{
	unsigned int allocations = fixture.allocations;
	unsigned int reports = fixture.unsupported;
	assert(!alloc_page(GFP_KERNEL | __GFP_DMA));
	assert(fixture.unsupported == reports + 1 && fixture.allocations == allocations);
	assert(!alloc_page(GFP_KERNEL | __GFP_NOFAIL));
	assert(fixture.unsupported == reports + 2 && fixture.allocations == allocations);
	fixture.refuse_atomic = true;
	local_bh_disable();
	assert(!alloc_page(GFP_NOWAIT));
	assert(fixture.seen_atomic && fixture.seen_gfp == (__force u32)GFP_NOWAIT);
	local_bh_enable();
	assert(fixture.unsupported == reports + 3 && fixture.allocations == allocations);
	fixture.refuse_atomic = false;
	fixture.exhausted = true;
	assert(!alloc_page(GFP_KERNEL));
	assert(fixture.unsupported == reports + 3);
	fixture.exhausted = false;
	assert(!__alloc_pages_noprof(GFP_KERNEL, MAX_PAGE_ORDER + 1, 0, NULL));
	assert(!__alloc_pages_noprof(GFP_KERNEL, 0, 1, NULL));
	nodemask_t empty = NODE_MASK_NONE;
	assert(!__alloc_pages_noprof(GFP_KERNEL, 0, 0, &empty));
	for (enum output_fault fault = OUTPUT_WRONG_COUNT; fault <= OUTPUT_OUTSIDE; fault++) {
		fixture.fault = fault;
		unsigned int releases = fixture.releases;
		assert(!alloc_pages(GFP_KERNEL | __GFP_ZERO, 1));
		assert(fixture.releases == releases + 1 && !catalog.live_pages);
	}
	fixture.fault = OUTPUT_VALID;
	struct page *page = alloc_page(GFP_KERNEL);
	assert(page);
	fixture.overlap_physical = page_to_phys(page);
	fixture.fault = OUTPUT_OVERLAP;
	assert(!alloc_page(GFP_KERNEL));
	assert(page_ref_count(page) == 1);
	fixture.fault = OUTPUT_VALID;
	__free_page(page);
	stela_linux_pages_finish();
	fixture.overlap_physical = 0;
	fixture.fault = OUTPUT_WRONG_COUNT;
	unsigned int releases = fixture.releases;
	local_bh_disable();
	assert(!alloc_page(GFP_NOWAIT));
	assert(fixture.releases == releases);
	local_bh_enable();
	stela_linux_pages_finish();
	assert(fixture.releases == releases + 1);
	fixture.fault = OUTPUT_VALID;
	local_bh_disable();
	page = alloc_page(GFP_NOWAIT);
	assert(page && fixture.seen_atomic);
	__free_page(page);
	local_bh_enable();
	stela_linux_pages_finish();
}

static void adjacency_and_retirement(void)
{
	struct page *first = alloc_page(GFP_KERNEL | __GFP_ZERO);
	struct page *second = alloc_page(GFP_KERNEL | __GFP_ZERO);
	assert(first && second && second == first + 1);
	assert(page_to_pfn(second) == page_to_pfn(first) + 1);
	struct scatterlist sg = {0};
	sg_mark_end(&sg);
	sg_set_page(&sg, first, 2 * PAGE_SIZE, 0);
	struct sg_page_iter iterator = {.sg = &sg, .sg_pgoffset = 1};
	assert(sg_page_iter_page(&iterator) == second);
	u64 physical = page_to_phys(second);
	assert(__pa((u8 *)page_address(second) + 37) == physical + 37);
	assert(__va(physical + 37) == (u8 *)page_address(second) + 37);
	trap_page = first;
	assert(stela_test_traps(interior_descriptor));
	assert(stela_test_traps(wrong_free_order));
	assert(stela_test_traps(null_free));
	free_pages(0, 0);
	assert(stela_test_traps(mapped_free));
	assert(stela_test_traps(unowned_physical));
	assert(stela_test_traps(unowned_virtual));
	assert(stela_test_traps(finish_atomic));
	assert(stela_test_traps(register_atomic));
	assert(stela_test_traps(unbalanced_callback));
	assert(stela_test_traps(reentrant_callback));
	assert(stela_linux_page_catalog_unregister(1) == -EBUSY);
	unsigned int releases = fixture.releases;
	local_bh_disable();
	__free_page(first);
	assert(stela_test_traps(dead_descriptor));
	__free_page(second);
	assert(fixture.releases == releases);
	local_bh_enable();
	stela_linux_exit();
	assert(fixture.releases == releases + 2);
}

static void compound_and_split(void)
{
	assert(stela_test_traps(noncompound_head_put));
	trap_page = alloc_pages(GFP_KERNEL | __GFP_ZERO | __GFP_COMP, 2);
	assert(trap_page && PageHead(trap_page) && compound_order(trap_page) == 2);
	assert(stela_test_traps(free_compound_tail));
	assert(stela_test_traps(split_compound));
	get_page(trap_page + 3);
	assert(page_ref_count(trap_page) == 2);
	__free_pages(trap_page, 2);
	assert(page_ref_count(trap_page) == 1 && page_to_phys(trap_page + 3));
	put_page(trap_page + 3);
	assert(stela_test_traps(dead_descriptor));
	stela_linux_pages_finish();
	struct page *page = alloc_pages(GFP_KERNEL, 2);
	assert(page && !PageHead(page));
	split_page(page, 2);
	for (size_t i = 0; i < 4; i++) {
		assert(page_ref_count(page + i) == 1 && !PageTail(page + i));
		__free_page(page + i);
	}
	stela_linux_pages_finish();
	page = alloc_pages(GFP_KERNEL, 2);
	assert(page);
	get_page(page);
	__free_pages(page, 2);
	assert(page_ref_count(page) == 1);
	trap_page = page + 1;
	assert(stela_test_traps(dead_descriptor));
	put_page(page);
	stela_linux_pages_finish();
	struct folio *folio = folio_alloc(GFP_KERNEL, 1);
	assert(folio && folio_order(folio) == 1 && folio_test_large_rmappable(folio));
	folio_get(folio);
	assert(folio_ref_count(folio) == 2);
	folio_put_refs(folio, 2);
	stela_linux_pages_finish();
	unsigned long address = get_zeroed_page(GFP_KERNEL);
	assert(address && *(u8 *)address == 0);
	free_page(address);
	address = __get_free_pages(GFP_KERNEL | __GFP_HIGHMEM, 1);
	assert(address && !(fixture.seen_gfp & (__force u32)__GFP_HIGHMEM));
	free_pages(address, 1);
	stela_linux_pages_finish();
	struct page_callback callback = {.page = alloc_page(GFP_KERNEL)};
	assert(callback.page);
	unsigned int releases = fixture.releases;
	call_rcu(&callback.head, retire_callback);
	stela_linux_exit();
	assert(fixture.releases == releases + 1);
}

static void capacity(void)
{
	struct page *pages[TEST_PAGES];
	for (size_t i = 0; i < TEST_PAGES; i++) {
		pages[i] = alloc_page(GFP_KERNEL);
		assert(pages[i]);
	}
	unsigned int allocations = fixture.allocations;
	assert(!alloc_page(GFP_KERNEL) && fixture.allocations == allocations);
	unsigned int releases = fixture.releases;
	local_bh_disable();
	for (size_t i = 0; i < TEST_PAGES; i++)
		__free_page(pages[i]);
	assert(fixture.releases == releases);
	local_bh_enable();
	/* A subsequent sleeping request drains earlier retired pins before
	 * requesting more platform backing. */
	struct page *page = alloc_page(GFP_KERNEL);
	assert(page && fixture.releases == releases + TEST_PAGES);
	__free_page(page);
	stela_linux_pages_finish();
}

int main(void)
{
	assert(stela_linux_page_request_basic((__force u32)(GFP_KERNEL | __GFP_ZERO | __GFP_COMP)));
	assert(stela_linux_page_request_basic((__force u32)GFP_KERNEL_ACCOUNT));
	assert(!stela_linux_page_request_basic((__force u32)(GFP_KERNEL | __GFP_MOVABLE)));
	assert(!stela_linux_page_request_basic((__force u32)(GFP_KERNEL | __GFP_HIGH)));
	assert(!stela_linux_page_request_basic(0x80000000U));
	assert(stela_linux_page_request_blocking((__force u32)GFP_KERNEL));
	assert(!stela_linux_page_request_blocking((__force u32)GFP_NOWAIT));
	fixture.cpu = aligned_alloc(TEST_PAGES * PAGE_SIZE, TEST_PAGES * PAGE_SIZE);
	assert(fixture.cpu);
	const struct stela_linux_services services = {.unsupported = test_unsupported};
	const struct stela_linux_owner owner = {.services = &services, .context = &fixture};
	struct stela_linux_page_reservation reservation = {
		.generation = 1, .physical_base = TEST_PHYSICAL, .cpu_base = fixture.cpu,
		.page_count = TEST_PAGES,
	};
	assert(stela_linux_try_enter(&owner));
	assert(!stela_linux_try_enter(&stela_linux_bare));
	assert(!alloc_page(GFP_KERNEL));
	struct stela_linux_page_reservation invalid = reservation;
	invalid.page_count = SIZE_MAX;
	assert(stela_linux_page_catalog_register(&invalid, &test_ops, &fixture) == -EINVAL);
	invalid = reservation;
	invalid.generation = 0;
	assert(stela_linux_page_catalog_register(&invalid, &test_ops, &fixture) == -EINVAL);
	for (size_t i = 0; i < 3; i++) {
		metadata_fail_after = i;
		assert(stela_linux_page_catalog_register(&reservation, &test_ops, &fixture) == -ENOMEM);
		assert(!metadata_live && !catalog.pages);
	}
	metadata_fail_after = NO_INDEX;
	assert(!stela_linux_page_catalog_register(&reservation, &test_ops, &fixture));
	assert(stela_linux_page_catalog_register(&reservation, &test_ops, &fixture) == -EBUSY);
	assert(stela_linux_page_catalog_verify(2) == -EINVAL);
	assert(!stela_linux_page_catalog_verify(1));
	refusal_and_rollback();
	adjacency_and_retirement();
	stela_linux_enter(&owner);
	compound_and_split();
	stela_linux_enter(&owner);
	capacity();
	assert(!catalog.live_pages);
	assert(!stela_linux_page_catalog_unregister(1));
	assert(stela_linux_page_catalog_register(&reservation, &test_ops, &fixture) == -EINVAL);
	reservation.generation = 2;
	assert(!stela_linux_page_catalog_register(&reservation, &test_ops, &fixture));
	assert(stela_linux_page_catalog_unregister(1) == -EINVAL);
	assert(!stela_linux_page_catalog_unregister(2));
	assert(!metadata_live);
	stela_linux_exit();
	assert(fixture.allocations == fixture.releases + 1); /* One deliberate ENOMEM. */
	for (size_t i = 0; i < TEST_PAGES; i++)
		assert(!fixture.used[i] && !fixture.pins[i].active);
	free(fixture.cpu);
	printf("Linux page catalog: ownership, PFNs, rollback, compound, split and deferred retirement passed\n");
	return 0;
}
#endif
