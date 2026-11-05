/* SPDX-License-Identifier: MIT */
#ifndef STELA_PAGE_TEST_H
#define STELA_PAGE_TEST_H
/* A few real pages behind Linux's page allocator, for hosted tests of code that
 * needs struct pages. Pages are never reused. */
#include <linux/mm.h>
#include <stela/page.h>
#include <stela/test.h>

#define STELA_TEST_PAGES 8UL
#define STELA_TEST_PHYSICAL 0x36000000ULL

static u8 *stela_test_memory;
static u64 stela_test_physical[STELA_TEST_PAGES];
static size_t stela_test_used;

static int stela_test_validate_pages(void *context, u32 gfp, unsigned int order, bool atomic)
{
	(void)context;
	(void)gfp;
	(void)atomic;
	return stela_test_used + (1UL << order) <= STELA_TEST_PAGES ? 0 : -ENOMEM;
}

static int stela_test_allocate_pages(void *context, u32 gfp, unsigned int order, bool atomic,
				     struct stela_linux_page_allocation *result)
{
	assert(!stela_test_validate_pages(context, gfp, order, atomic));
	size_t count = 1UL << order, first = stela_test_used;

	for (size_t i = 0; i < count; i++)
		stela_test_physical[first + i] = STELA_TEST_PHYSICAL + (u64)(first + i) * PAGE_SIZE;
	*result = (struct stela_linux_page_allocation){
		.pin = stela_test_physical + first,
		.cpu_base = stela_test_memory + first * PAGE_SIZE,
		.physical_pages = stela_test_physical + first,
		.page_count = count,
	};
	stela_test_used += count;
	return 0;
}

static void stela_test_release_pages(void *context, void *pin)
{
	(void)context;
	(void)pin;
}

static inline void stela_test_register_pages(void)
{
	size_t bytes = STELA_TEST_PAGES * PAGE_SIZE;

	stela_test_memory = aligned_alloc(bytes, bytes);
	assert(stela_test_memory);
	const struct stela_linux_page_reservation reservation = {
		.generation = 1,
		.physical_base = STELA_TEST_PHYSICAL,
		.cpu_base = stela_test_memory,
		.page_count = STELA_TEST_PAGES,
	};
	const struct stela_linux_page_ops pages = {
		.validate = stela_test_validate_pages,
		.allocate = stela_test_allocate_pages,
		.release = stela_test_release_pages,
	};
	assert(!stela_linux_page_catalog_register(&reservation, &pages, NULL));
}
#endif
