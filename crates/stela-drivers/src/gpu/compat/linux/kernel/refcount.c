// SPDX-License-Identifier: GPL-2.0
/* Owned saturation diagnostic following Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 lib/refcount.c.
 * Public refcount atomics remain unchanged; mutex-taking operations need the
 * real shared lock owner and are not supplied by this unit. */
#include <linux/bug.h>
#include <linux/printk.h>
#include <linux/refcount.h>
#include <stela/linux.h>

void refcount_warn_saturate(refcount_t *reference, enum refcount_saturation_type type)
{
	(void)stela_linux_owner();
	/* Saturation deliberately leaks the object rather than enabling an
	 * erroneous final release. Each source warning class reports once. */
	refcount_set(reference, REFCOUNT_SATURATED);
	switch (type) {
	case REFCOUNT_ADD_NOT_ZERO_OVF:
		WARN_ONCE(1, "refcount_t: saturated; leaking memory.\n");
		break;
	case REFCOUNT_ADD_OVF:
		WARN_ONCE(1, "refcount_t: saturated; leaking memory.\n");
		break;
	case REFCOUNT_ADD_UAF:
		WARN_ONCE(1, "refcount_t: addition on 0; use-after-free.\n");
		break;
	case REFCOUNT_SUB_UAF:
		WARN_ONCE(1, "refcount_t: underflow; use-after-free.\n");
		break;
	case REFCOUNT_DEC_LEAK:
		WARN_ONCE(1, "refcount_t: decrement hit 0; leaking memory.\n");
		break;
	default:
		WARN_ONCE(1, "refcount_t: unknown saturation event!?.\n");
		break;
	}
}

#ifdef STELA_LINUX_REFCOUNT_TEST
#include <stela/test.h>

static unsigned int warnings;

static void warning(void *context, const char *file, int line, const char *condition)
{
	(void)context;
	assert(file && line > 0 && condition);
	warnings++;
}

int main(void)
{
	const struct stela_linux_services services = {.warn = warning};
	const struct stela_linux_owner owner = {.services = &services};
	stela_linux_enter(&owner);
	refcount_t reference = REFCOUNT_INIT(1);
	refcount_inc(&reference);
	assert(refcount_read(&reference) == 2);
	assert(!refcount_dec_and_test(&reference) && refcount_read(&reference) == 1);
	assert(refcount_dec_and_test(&reference) && !refcount_read(&reference));
	for (unsigned int i = 0; i <= (unsigned int)REFCOUNT_DEC_LEAK; i++) {
		unsigned int before = warnings;
		refcount_set(&reference, 7);
		refcount_warn_saturate(&reference, (enum refcount_saturation_type)i);
		assert(refcount_read(&reference) == (unsigned int)REFCOUNT_SATURATED);
		assert(warnings == before + 1);
		refcount_warn_saturate(&reference, (enum refcount_saturation_type)i);
		assert(warnings == before + 1);
	}
	assert(!refcount_dec_and_test(&reference));
	assert(refcount_read(&reference) == (unsigned int)REFCOUNT_SATURATED);
	unsigned int before = warnings;
	refcount_warn_saturate(&reference, (enum refcount_saturation_type)99);
	assert(warnings == before + 1);
	refcount_warn_saturate(&reference, (enum refcount_saturation_type)99);
	assert(warnings == before + 1);
	refcount_set(&reference, 0);
	refcount_inc(&reference);
	assert(refcount_read(&reference) == (unsigned int)REFCOUNT_SATURATED);
	stela_linux_exit();
	printf("Linux refcount: real transitions, warning classes and saturation passed\n");
	return 0;
}
#endif
