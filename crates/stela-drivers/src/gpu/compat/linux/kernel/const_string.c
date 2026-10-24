// SPDX-License-Identifier: GPL-2.0
/* Owned constant-string adapters following Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 mm/util.c and lib/kasprintf.c
 * (the latter Copyright (C) 1991, 1992 Linus Torvalds).
 * The actual image owner classifies pointers. These functions create no image,
 * root, heap provenance, pointer registry or fallback classifier. */
#include <linux/slab.h>
#include <linux/sprintf.h>
#include <linux/string.h>
#include <stela/linux.h>

const char *kstrdup_const(const char *string, gfp_t flags)
{
	if (stela_linux_is_rodata(string))
		return string;
	return kstrdup(string, flags);
}

void kfree_const(const void *pointer)
{
	/* Registration's ongoing admission contract supplies the complete stable
	 * borrowed-name coverage, and a negative free requires separately proven
	 * live canonical-heap ownership. False alone never grants that ownership.
	 * Keep the query even for NULL/sentinels: an absent binding must trap. */
	if (!stela_linux_is_rodata(pointer))
		kfree(pointer);
}

const char *kvasprintf_const(gfp_t flags, const char *format, va_list arguments)
{
	if (!strchr(format, '%'))
		return kstrdup_const(format, flags);
	if (!strcmp(format, "%s"))
		return kstrdup_const(va_arg(arguments, const char *), flags);
	return kvasprintf(flags, format, arguments);
}

#ifdef STELA_LINUX_CONST_STRING_TEST
#include <linux/minmax.h>
#include <stela/test.h>

/* Explicit unit classifier only. These identified arrays have static C
 * lifetime; this fixture supplies no actual immutable-image, page-permission,
 * relocated EFI, hardware or native-root authority. Production instead
 * imports stela_linux_is_rodata from Rust's permanent registered consumer. */
static const char literal[] = "borrowed-literal";
static const char plain_format[] = "plain-format";
static const char empty_literal[] = "";
static const struct {
	const char *base;
	size_t bytes;
} fixture_strings[] = {
	{literal, sizeof(literal)},
	{plain_format, sizeof(plain_format)},
	{empty_literal, sizeof(empty_literal)},
};

static bool fixture_registered;
static size_t queries;

bool stela_linux_is_rodata(const void *pointer)
{
	if (!fixture_registered)
		__builtin_trap();
	queries++;
	unsigned long address = (unsigned long)pointer;
	for (size_t i = 0; i < ARRAY_SIZE(fixture_strings); i++) {
		unsigned long base = (unsigned long)fixture_strings[i].base;
		if (address >= base && address - base < fixture_strings[i].bytes)
			return true;
	}
	return false;
}

/* Real bounded hosted RAM behind the canonical heap callbacks. Failure is
 * injected at acquisition, not by replacing kstrdup/kfree/kvasprintf. This TU
 * defines its required stela/test.c services so the alternative host-heap
 * archive object is not pulled into the executable under normal linking. */
struct heap_record {
	void *pointer;
	size_t size;
	size_t align;
};

static struct heap_record heap_records[32];
static size_t fail_after = SIZE_MAX;
static size_t attempts;
static size_t allocations;
static size_t releases;
static size_t live;

/* This independent libc-backed model admits no nonblocking allocations. It
 * supplies the ABI's truthful absent capability without pulling test.c's
 * alternative heap object into this executable. */
bool stela_linux_heap_try_available(void)
{
	return false;
}

void *stela_linux_heap_try_alloc(size_t size, size_t align)
{
	(void)size;
	(void)align;
	__builtin_trap();
}

void *stela_linux_heap_alloc(size_t size, size_t align)
{
	attempts++;
	if (!fail_after)
		return NULL;
	if (fail_after != SIZE_MAX)
		fail_after--;
	struct heap_record *record = NULL;
	for (size_t i = 0; i < ARRAY_SIZE(heap_records); i++) {
		if (!heap_records[i].pointer) {
			record = heap_records + i;
			break;
		}
	}
	if (!record)
		return NULL;
	size_t actual_align = max_t(size_t, align, sizeof(void *));
	assert(actual_align && !(actual_align & (actual_align - 1)));
	assert(size && size <= SIZE_MAX - actual_align + 1);
	void *pointer = aligned_alloc(actual_align, (size + actual_align - 1) & ~(actual_align - 1));
	if (!pointer)
		return NULL;
	memset(pointer, 0, size);
	*record = (struct heap_record){.pointer = pointer, .size = size, .align = align};
	allocations++;
	live++;
	return pointer;
}

void stela_linux_heap_free(void *pointer, size_t size, size_t align)
{
	for (size_t i = 0; i < ARRAY_SIZE(heap_records); i++) {
		struct heap_record *record = heap_records + i;
		if (record->pointer != pointer)
			continue;
		assert(live && record->size == size && record->align == align);
		memset(pointer, 0xd3, size);
		free(pointer);
		*record = (struct heap_record){0};
		releases++;
		live--;
		return;
	}
	assert(false);
}

__noreturn void stela_test_fail(const char *file, int line, const char *condition)
{
	printf("%s:%d: assertion failed: %s\n", file, line, condition);
	__builtin_trap();
}

static __printf(2, 3) const char *format_const(gfp_t flags, const char *format, ...)
{
	va_list arguments;
	va_start(arguments, format);
	const char *result = kvasprintf_const(flags, format, arguments);
	va_end(arguments);
	return result;
}

static void borrow_and_copy(void)
{
	size_t before = attempts;
	fail_after = 0;
	const char *borrowed = kstrdup_const(literal, GFP_KERNEL);
	assert(borrowed == literal && attempts == before);
	assert(kstrdup_const(literal + 9, GFP_ATOMIC) == literal + 9);
	assert(kstrdup_const(empty_literal, GFP_KERNEL) == empty_literal);
	kfree_const(borrowed);
	kfree_const(literal + sizeof(literal) - 1);
	assert(attempts == before && !live && !releases);
	fail_after = SIZE_MAX;
	char stack[] = "mutable-stack";
	const char *copy = kstrdup_const(stack, GFP_KERNEL);
	assert(copy && copy != stack && !strcmp(copy, stack));
	stack[0] = 'M';
	assert(!strcmp(copy, "mutable-stack"));
	kfree_const(copy);
	char *heap = kstrdup("mutable-heap", GFP_KERNEL);
	assert(heap);
	copy = kstrdup_const(heap, GFP_KERNEL);
	assert(copy && copy != heap && !strcmp(copy, heap));
	heap[0] = 'M';
	assert(!strcmp(copy, "mutable-heap"));
	kfree_const(heap);
	kfree_const(copy);
	before = attempts;
	size_t before_queries = queries;
	assert(!kstrdup_const(NULL, GFP_KERNEL));
	kfree_const(NULL);
	kfree_const(ZERO_SIZE_PTR);
	assert(attempts == before && queries == before_queries + 3 && !live);
}

static void formatting(void)
{
	size_t before = attempts;
	const char *(*volatile format_any)(gfp_t, const char *, ...) = format_const;
	assert(format_any(GFP_KERNEL, plain_format) == plain_format);
	assert(format_const(GFP_KERNEL, "%s", literal) == literal);
	assert(format_const(GFP_KERNEL, "%s", empty_literal) == empty_literal);
	/* Exact %s takes the duplication path; NULL stays NULL, unlike the
	 * ordinary formatter's (null) spelling in a compound format. */
	assert(!format_const(GFP_KERNEL, "%s", (const char *)NULL));
	assert(attempts == before);
	char stack_format[] = "mutable-format";
	const char *copy = format_any(GFP_KERNEL, stack_format);
	assert(copy && copy != stack_format && !strcmp(copy, stack_format));
	stack_format[0] = 'M';
	assert(!strcmp(copy, "mutable-format"));
	kfree_const(copy);
	char stack_value[] = "mutable-value";
	copy = format_const(GFP_KERNEL, "%s", stack_value);
	assert(copy && copy != stack_value && !strcmp(copy, stack_value));
	kfree_const(copy);
	copy = format_const(GFP_KERNEL, "%s:%u:%#08x", literal, 7U, 1U);
	assert(copy && copy != literal && !strcmp(copy, "borrowed-literal:7:0x000001"));
	kfree_const(copy);
	copy = format_const(GFP_KERNEL, "value%%");
	assert(copy && !strcmp(copy, "value%"));
	kfree_const(copy);
	copy = format_const(GFP_KERNEL, "%s:%u", (const char *)NULL, 1U);
	assert(copy && !strcmp(copy, "(null):1"));
	kfree_const(copy);
	assert(!live);
}

static void allocation_failures(void)
{
	char stack[] = "failure-preserves-input";
	const char expected[] = "failure-preserves-input";
	const char *(*volatile format_from_stack)(gfp_t, const char *, ...) = format_const;
	size_t before = attempts;
	size_t before_allocations = allocations;
	size_t before_releases = releases;
	fail_after = 0;
	assert(!kstrdup_const(stack, GFP_KERNEL));
	assert(!format_const(GFP_KERNEL, "%s", stack));
	assert(!format_from_stack(GFP_KERNEL, stack));
	assert(!format_const(GFP_KERNEL, "formatted-%u", 7U));
	assert(attempts == before + 4 && allocations == before_allocations);
	assert(releases == before_releases && !live && !strcmp(stack, expected));
	assert(kstrdup_const(literal, GFP_KERNEL) == literal);
	assert(format_const(GFP_KERNEL, "%s", literal) == literal);
	assert(attempts == before + 4);
	fail_after = SIZE_MAX;
	const char *recovered = format_const(GFP_KERNEL, "formatted-%u", 7U);
	assert(recovered && !strcmp(recovered, "formatted-7"));
	kfree_const(recovered);
	assert(!live);
}

int main(int argc, char **argv)
{
	/* Optional negative-control execution must stop at the unbound query.
	 * It tests this explicit fixture, not Rust or a real image authority. */
	if (argc == 2 && !strcmp(argv[1], "--missing-registration")) {
		const char *unbound = kstrdup_const(literal, GFP_KERNEL);
		(void)unbound;
		return 2;
	}
	assert(argc == 1);
	fixture_registered = true;
	stela_linux_enter(&stela_linux_bare);
	borrow_and_copy();
	formatting();
	allocation_failures();
	assert(!live && allocations && allocations == releases);
	assert(!strcmp(literal, "borrowed-literal") && !strcmp(plain_format, "plain-format"));
	stela_linux_exit();
	printf("Linux const strings: unit borrow/copy/free/format and allocation failures passed\n");
	return 0;
}
#endif
