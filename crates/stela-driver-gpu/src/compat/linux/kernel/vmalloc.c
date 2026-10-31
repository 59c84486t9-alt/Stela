// SPDX-License-Identifier: MIT
/* Linux's virtually contiguous memory, with the interface of Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 mm/vmalloc.c. Linux code under
 * Stela owns no address space, so the owner maps the pages (map_pages); this
 * keeps which pages back each mapping, for vmalloc_to_page and vfree. */
#include <linux/mm.h>
#include <linux/overflow.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <stela/linux.h>

struct area {
	struct rb_node node;
	const void *address;
	unsigned int count;
	/* vmalloc's pages are its own; vmap's stay its caller's. */
	bool owns_pages;
	struct page *pages[];
};

static struct rb_root areas = RB_ROOT;

static int area_order(const void *key, const struct rb_node *node)
{
	const struct area *area = rb_entry(node, struct area, node);
	const char *address = key, *start = area->address;

	if (address < start)
		return -1;
	return address < start + ((size_t)area->count << PAGE_SHIFT) ? 0 : 1;
}

static bool area_less(struct rb_node *node, const struct rb_node *other)
{
	return rb_entry(node, struct area, node)->address <
	       rb_entry(other, struct area, node)->address;
}

static struct area *area_of(const void *address)
{
	struct rb_node *node = rb_find(address, &areas, area_order);
	return node ? rb_entry(node, struct area, node) : NULL;
}

/* Maps area's pages and records the mapping, or leaves nothing mapped. */
static void *map_area(struct area *area)
{
	const struct stela_linux_owner *owner = stela_linux_owner();
	if (!owner->services->map_pages) {
		stela_linux_unsupported("mapping pages");
		return NULL;
	}
	u64 *physical = kmalloc_array(area->count, sizeof(*physical), GFP_KERNEL);
	if (!physical)
		return NULL;
	for (unsigned int i = 0; i < area->count; i++)
		physical[i] = page_to_phys(area->pages[i]);
	void *address = owner->services->map_pages(owner->context, physical, area->count);
	kfree(physical);
	if (address) {
		area->address = address;
		rb_add(&area->node, &areas, area_less);
	}
	return address;
}

static struct area *new_area(unsigned int count, bool owns_pages)
{
	struct area *area = kmalloc(struct_size(area, pages, count), GFP_KERNEL);
	if (area) {
		area->count = count;
		area->owns_pages = owns_pages;
	}
	return area;
}

static void free_pages_of(struct area *area, unsigned int count)
{
	while (count)
		__free_page(area->pages[--count]);
}

void *__vmalloc_noprof(unsigned long size, gfp_t gfp_mask)
{
	unsigned long count = PAGE_ALIGN(size) >> PAGE_SHIFT;

	if (!count || count > UINT_MAX)
		return NULL;
	struct area *area = new_area((unsigned int)count, true);
	if (!area)
		return NULL;
	for (unsigned int i = 0; i < count; i++) {
		area->pages[i] = alloc_page(gfp_mask);
		if (!area->pages[i]) {
			free_pages_of(area, i);
			kfree(area);
			return NULL;
		}
	}
	void *address = map_area(area);
	if (!address) {
		free_pages_of(area, area->count);
		kfree(area);
	}
	return address;
}

void *vmalloc_noprof(unsigned long size)
{
	return __vmalloc_noprof(size, GFP_KERNEL);
}

void *vzalloc_noprof(unsigned long size)
{
	return __vmalloc_noprof(size, GFP_KERNEL | __GFP_ZERO);
}

void *vmap(struct page **pages, unsigned int count, unsigned long flags, pgprot_t prot)
{
	(void)flags;
	if (pgprot_val(prot) != pgprot_val(PAGE_KERNEL)) {
		stela_linux_unsupported("vmap with another protection");
		return NULL;
	}
	struct area *area = new_area(count, false);
	if (!area)
		return NULL;
	memcpy(area->pages, pages, count * sizeof(*pages));
	void *address = map_area(area);
	if (!address)
		kfree(area);
	return address;
}

static void unmap(const void *address, bool owns_pages)
{
	if (!address)
		return;
	struct area *area = area_of(address);
	if (WARN_ON(!area || area->address != address || area->owns_pages != owns_pages))
		return;
	const struct stela_linux_owner *owner = stela_linux_owner();
	rb_erase(&area->node, &areas);
	owner->services->unmap_pages(owner->context, (void *)address, area->count);
	if (owns_pages)
		free_pages_of(area, area->count);
	kfree(area);
}

void vfree(const void *address)
{
	unmap(address, true);
}

void vunmap(const void *address)
{
	unmap(address, false);
}

bool is_vmalloc_addr(const void *x)
{
	return area_of(x);
}

struct page *vmalloc_to_page(const void *address)
{
	struct area *area = area_of(address);
	if (!area)
		return NULL;
	return area->pages[((const char *)address - (const char *)area->address) >> PAGE_SHIFT];
}

/* As mm/slub.c does: slab first, without its warnings or retries when the
 * request is large, then pages that need not be contiguous. */
void *__kvmalloc_node_noprof(DECL_KMALLOC_PARAMS(size, b, token), unsigned long align,
			     gfp_t flags, int node)
{
	(void)node;
	if (WARN_ON_ONCE(align > PAGE_SIZE))
		return NULL;
	if (align <= ARCH_KMALLOC_MINALIGN) {
		gfp_t attempt = flags;
		if (size > PAGE_SIZE) {
			attempt |= __GFP_NOWARN;
			if (!(attempt & __GFP_RETRY_MAYFAIL))
				attempt |= __GFP_NORETRY;
			attempt &= ~__GFP_NOFAIL;
		}
		void *object = __kmalloc_noprof(PASS_TOKEN_PARAMS(size, token), attempt);
		if (object || size <= PAGE_SIZE)
			return object;
	}
	if (!gfpflags_allow_blocking(flags) || WARN_ON_ONCE(size > INT_MAX))
		return NULL;
	return __vmalloc_noprof(size, flags);
}

void *kvrealloc_node_align_noprof(const void *object, DECL_TOKEN_PARAMS(size, token),
				  unsigned long align, gfp_t flags, int node)
{
	if (!is_vmalloc_addr(object)) {
		void *resized = krealloc_node_align_noprof(object, PASS_TOKEN_PARAMS(size, token),
							   align, flags | __GFP_NOWARN, node);
		if (resized)
			return resized;
	}
	void *fresh = __kvmalloc_node_noprof(PASS_KMALLOC_PARAMS(size, NULL, token), align, flags,
					     node);
	if (!fresh || !object)
		return fresh;
	const struct area *area = area_of(object);
	size_t old_size = area ? (size_t)area->count << PAGE_SHIFT : ksize(object);
	memcpy(fresh, object, min(old_size, size));
	kvfree(object);
	return fresh;
}

#ifdef STELA_LINUX_VMALLOC_TEST
#include <stela/page.h>
#include <stela/test.h>

#define PAGES 8UL
#define PHYSICAL 0x40000000ULL

static u8 memory[PAGES * PAGE_SIZE] __aligned(PAGE_SIZE);
static size_t next_page;
static u64 pin_physical[PAGES];
static unsigned int released;
static bool exhausted;

static int validate(void *context, u32 gfp, unsigned int order, bool atomic)
{
	(void)context;
	(void)atomic;
	return !order && stela_linux_page_request_basic(gfp) ? 0 : -EOPNOTSUPP;
}

static int allocate(void *context, u32 gfp, unsigned int order, bool atomic,
		    struct stela_linux_page_allocation *allocation)
{
	(void)context;
	(void)gfp;
	(void)order;
	(void)atomic;
	if (exhausted || next_page == PAGES)
		return -ENOMEM;
	size_t page = next_page++;
	pin_physical[page] = PHYSICAL + page * PAGE_SIZE;
	*allocation = (struct stela_linux_page_allocation){
		.pin = &pin_physical[page],
		.cpu_base = memory + page * PAGE_SIZE,
		.physical_pages = &pin_physical[page],
		.page_count = 1,
	};
	return 0;
}

static void release(void *context, void *pin)
{
	(void)context;
	(void)pin;
	released++;
}

static const struct stela_linux_page_ops ops = {
	.validate = validate,
	.allocate = allocate,
	.release = release,
};

static u8 alias[2 * PAGE_SIZE];
static bool aliasing;

/* The pages are contiguous here, so the window already maps them; a second
 * mapping of them lies elsewhere, as the owner's would. */
static void *map_pages(void *context, const u64 *physical, size_t count)
{
	(void)context;
	for (size_t i = 1; i < count; i++)
		assert(physical[i] == physical[0] + i * PAGE_SIZE);
	return aliasing ? alias : memory + (physical[0] - PHYSICAL);
}

static unsigned int unmapped;

static void unmap_pages(void *context, void *address, size_t count)
{
	(void)context;
	(void)address;
	unmapped += (unsigned int)count;
}

static void unsupported(void *context, const char *operation)
{
	(void)context;
	assert(!strcmp(operation, "vmap with another protection"));
}

static const struct stela_linux_services services = {
	.map_pages = map_pages,
	.unmap_pages = unmap_pages,
	.unsupported = unsupported,
};
static const struct stela_linux_owner owner = {.services = &services};

int main(void)
{
	stela_linux_enter(&owner);
	const struct stela_linux_page_reservation reservation = {
		.generation = 1, .physical_base = PHYSICAL, .cpu_base = memory, .page_count = PAGES};
	assert(!stela_linux_page_catalog_register(&reservation, &ops, NULL));

	u8 *zeroed = vzalloc(2 * PAGE_SIZE - 1);
	assert(zeroed == memory && !zeroed[PAGE_SIZE + 5] && is_vmalloc_addr(zeroed + PAGE_SIZE));
	assert(!is_vmalloc_addr(zeroed + 2 * PAGE_SIZE) && !is_vmalloc_addr(&next_page));
	struct page *second = vmalloc_to_page(zeroed + PAGE_SIZE + 5);
	assert(page_to_phys(second) == PHYSICAL + PAGE_SIZE);
	assert(!vmalloc_to_page(&next_page));

	struct page *pages[] = {vmalloc_to_page(zeroed), second};
	aliasing = true;
	u8 *again = vmap(pages, 2, VM_MAP, PAGE_KERNEL);
	aliasing = false;
	assert(again == alias && vmalloc_to_page(again + PAGE_SIZE) == second);
	vunmap(again);
	assert(unmapped == 2 && is_vmalloc_addr(zeroed));
	assert(!vmap(pages, 2, VM_MAP, PAGE_NONE));

	/* A request the pages cannot cover undoes what it allocated. */
	exhausted = false;
	next_page = PAGES - 1;
	assert(!vmalloc(2 * PAGE_SIZE));
	next_page = 2;

	/* Small requests stay in slab; kvfree frees either kind. */
	void *small = kvmalloc(32, GFP_KERNEL);
	assert(small && !is_vmalloc_addr(small));
	kvfree(small);
	void *large = vmalloc(PAGE_SIZE);
	assert(is_vmalloc_addr(large));
	kvfree(large);
	vfree(NULL);
	vfree(zeroed);
	assert(unmapped == 5);

	/* A slab object keeps its bytes when it grows. */
	u8 *grown = kvmalloc(16, GFP_KERNEL);
	grown[15] = 0x5a;
	u8 *resized = kvrealloc(grown, 32, GFP_KERNEL);
	assert(resized && !is_vmalloc_addr(resized) && resized[15] == 0x5a);
	kvfree(resized);
	stela_linux_exit();
	printf("Linux vmalloc over the owner's page mappings passed\n");
	return 0;
}
#endif
