// SPDX-License-Identifier: GPL-2.0-or-later
/* Bounded module-parameter operations for the entered serialized Linux owner.
 * Behavioral reference: Linux 7.2.12 kernel/params.c, Copyright (C) 2001
 * Rusty Russell, and lib/kstrtox.c. Keep the public operation ABI and use
 * Stela's canonical parser/formatter/heap. No sysfs, module loader, security
 * dispatch or pre-allocator command-line lifetime is supplied by this unit. */
#include <asm/page.h>
#include <linux/errno.h>
#include <linux/kstrtox.h>
#include <linux/limits.h>
#include <linux/moduleparam.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/sprintf.h>
#include <linux/string.h>
#include <stela/linux.h>

#define PARAM_STRING_LIMIT 1024UL

/* The public getter contract supplies a full page, including its terminator. */
static_assert(PAGE_SIZE == 4096);

/* Unlike kmalloc's header, this ledger identifies only copies this service
 * owns. A static default, external string or unknown pointer is never freed.
 * The list and canonical heap survive owner exit; callers stop all readers
 * before replacement/unload and do not use the target after its free callback. */
struct parameter_string {
	struct parameter_string *next;
	char value[];
};

static struct parameter_string *owned_strings;

#ifdef STELA_LINUX_PARAMS_TEST
static bool fail_string_allocation;
static size_t string_allocations;
static size_t string_releases;
#endif

static struct parameter_string *allocate_string(size_t length)
{
#ifdef STELA_LINUX_PARAMS_TEST
	if (fail_string_allocation)
		return NULL;
#endif
	struct parameter_string *string = kmalloc(sizeof(*string) + length + 1, GFP_KERNEL);
#ifdef STELA_LINUX_PARAMS_TEST
	if (string)
		string_allocations++;
#endif
	return string;
}

static void release_string(const char *value)
{
	struct parameter_string **link = &owned_strings;
	while (*link) {
		struct parameter_string *string = *link;
		if (string->value != value) {
			link = &string->next;
			continue;
		}
		*link = string->next;
		kfree(string);
#ifdef STELA_LINUX_PARAMS_TEST
		string_releases++;
#endif
		return;
	}
}

static int unsigned_value(const char *value, unsigned long long maximum,
			  unsigned long long *result)
{
	if (!value)
		return -EINVAL;
	unsigned long long parsed;
	int error = kstrtoull(value, 0, &parsed);
	if (error)
		return error;
	if (parsed > maximum)
		return -ERANGE;
	*result = parsed;
	return 0;
}

int param_set_int(const char *value, const struct kernel_param *parameter)
{
	(void)stela_linux_owner();
	if (!value)
		return -EINVAL;
	bool negative = value[0] == '-';
	/* Linux's negative branch calls _kstrtoull, which cannot skip a second
	 * plus sign. The shared public kstrtoull permits one leading plus. */
	if (negative && value[1] == '+')
		return -EINVAL;
	unsigned long long magnitude;
	unsigned long long negative_limit = (unsigned long long)INT_MAX + 1;
	int error = unsigned_value(value + negative, negative ? negative_limit : INT_MAX, &magnitude);
	if (error)
		return error;
	int parsed = negative ? (magnitude == negative_limit ? INT_MIN : -(int)magnitude) :
				(int)magnitude;
	*(int *)parameter->arg = parsed;
	return 0;
}

int param_get_int(char *buffer, const struct kernel_param *parameter)
{
	(void)stela_linux_owner();
	return scnprintf(buffer, PAGE_SIZE, "%i\n", *(int *)parameter->arg);
}

int param_set_uint(const char *value, const struct kernel_param *parameter)
{
	(void)stela_linux_owner();
	unsigned long long parsed;
	int error = unsigned_value(value, UINT_MAX, &parsed);
	if (!error)
		*(unsigned int *)parameter->arg = (unsigned int)parsed;
	return error;
}

int param_get_uint(char *buffer, const struct kernel_param *parameter)
{
	(void)stela_linux_owner();
	return scnprintf(buffer, PAGE_SIZE, "%u\n", *(unsigned int *)parameter->arg);
}

int param_set_hexint(const char *value, const struct kernel_param *parameter)
{
	return param_set_uint(value, parameter);
}

int param_get_hexint(char *buffer, const struct kernel_param *parameter)
{
	(void)stela_linux_owner();
	return scnprintf(buffer, PAGE_SIZE, "%#08x\n", *(unsigned int *)parameter->arg);
}

int param_set_ullong(const char *value, const struct kernel_param *parameter)
{
	(void)stela_linux_owner();
	return unsigned_value(value, ULLONG_MAX, parameter->arg);
}

int param_get_ullong(char *buffer, const struct kernel_param *parameter)
{
	(void)stela_linux_owner();
	return scnprintf(buffer, PAGE_SIZE, "%llu\n", *(unsigned long long *)parameter->arg);
}

/* Pinned kstrtobool checks initials, not complete words or suffixes. */
static int boolean_value(const char *value, bool *result)
{
	if (!value) {
		*result = true;
		return 0;
	}
	switch (value[0]) {
	case 'e': case 'E': case 'y': case 'Y': case 't': case 'T': case '1':
		*result = true;
		return 0;
	case 'd': case 'D': case 'n': case 'N': case 'f': case 'F': case '0':
		*result = false;
		return 0;
	case 'o': case 'O':
		if (value[1] == 'n' || value[1] == 'N') {
			*result = true;
			return 0;
		}
		if (value[1] == 'f' || value[1] == 'F') {
			*result = false;
			return 0;
		}
		break;
	default:
		break;
	}
	return -EINVAL;
}

int param_set_bool(const char *value, const struct kernel_param *parameter)
{
	(void)stela_linux_owner();
	return boolean_value(value, parameter->arg);
}

int param_get_bool(char *buffer, const struct kernel_param *parameter)
{
	(void)stela_linux_owner();
	return scnprintf(buffer, PAGE_SIZE, "%c\n", *(bool *)parameter->arg ? 'Y' : 'N');
}

int param_set_bint(const char *value, const struct kernel_param *parameter)
{
	(void)stela_linux_owner();
	bool parsed;
	int error = boolean_value(value, &parsed);
	if (!error)
		*(int *)parameter->arg = parsed;
	return error;
}

int param_set_charp(const char *value, const struct kernel_param *parameter)
{
	(void)stela_linux_owner();
	if (!value)
		return -EINVAL;
	size_t length = strnlen(value, PARAM_STRING_LIMIT + 1);
	if (length > PARAM_STRING_LIMIT) {
		pr_err("%s: string parameter too long\n", parameter->name);
		return -ENOSPC;
	}
	/* Entered Linux execution has an available canonical heap. No pre-heap
	 * phase or borrowed command-line lifetime may be inferred here. */
	if (!stela_linux_quiescent()) {
		stela_linux_unsupported("module charp allocation context");
		return -EOPNOTSUPP;
	}
	struct parameter_string *string = allocate_string(length);
	if (!string)
		return -ENOMEM;
	memcpy(string->value, value, length + 1);
	string->next = owned_strings;
	owned_strings = string;
	char **target = parameter->arg;
	release_string(*target);
	*target = string->value;
	return 0;
}

int param_get_charp(char *buffer, const struct kernel_param *parameter)
{
	(void)stela_linux_owner();
	return scnprintf(buffer, PAGE_SIZE, "%s\n", *(char **)parameter->arg);
}

void param_free_charp(void *argument)
{
	(void)stela_linux_owner();
	/* As upstream, do not overwrite the module's (now retired) target. */
	release_string(*(char **)argument);
}

int param_set_copystring(const char *value, const struct kernel_param *parameter)
{
	(void)stela_linux_owner();
	if (!value)
		return -EINVAL;
	const struct kparam_string *string = parameter->str;
	size_t length = strnlen(value, string->maxlen);
	if (length == string->maxlen) {
		pr_err("%s: string doesn't fit in %u chars.\n", parameter->name, string->maxlen - 1);
		return -ENOSPC;
	}
	memcpy(string->string, value, length + 1);
	return 0;
}

int param_get_string(char *buffer, const struct kernel_param *parameter)
{
	(void)stela_linux_owner();
	return scnprintf(buffer, PAGE_SIZE, "%s\n", parameter->str->string);
}

const struct kernel_param_ops param_ops_bool = {
	.flags = KERNEL_PARAM_OPS_FL_NOARG, .set = param_set_bool, .get = param_get_bool,
};
const struct kernel_param_ops param_ops_bint = {
	.flags = KERNEL_PARAM_OPS_FL_NOARG, .set = param_set_bint, .get = param_get_int,
};
const struct kernel_param_ops param_ops_int = {.set = param_set_int, .get = param_get_int};
const struct kernel_param_ops param_ops_uint = {.set = param_set_uint, .get = param_get_uint};
const struct kernel_param_ops param_ops_hexint = {.set = param_set_hexint, .get = param_get_hexint};
const struct kernel_param_ops param_ops_ullong = {.set = param_set_ullong, .get = param_get_ullong};
const struct kernel_param_ops param_ops_charp = {
	.set = param_set_charp, .get = param_get_charp, .free = param_free_charp,
};
const struct kernel_param_ops param_ops_string = {.set = param_set_copystring, .get = param_get_string};

#ifdef STELA_LINUX_PARAMS_TEST
#include <linux/bottom_half.h>
#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <stela/test.h>

static unsigned int refusals;

static void unsupported(void *context, const char *operation)
{
	assert(context == &refusals && !strcmp(operation, "module charp allocation context"));
	refusals++;
}

static void expect_text(const struct kernel_param_ops *ops, const struct kernel_param *parameter,
			const char *expected)
{
	char buffer[PAGE_SIZE + 1];
	memset(buffer, 0xc9, sizeof(buffer));
	int length = ops->get(buffer, parameter);
	assert(length == (int)strlen(expected) && !strcmp(buffer, expected));
	assert((u8)buffer[length + 1] == 0xc9 && (u8)buffer[PAGE_SIZE] == 0xc9);
}

static void numeric_values(void)
{
	const struct {
		const char *text;
		int error;
		int value;
	} signed_cases[] = {
		{"0", 0, 0}, {"-0", 0, 0}, {"+0", 0, 0}, {"010", 0, 8},
		{"-010", 0, -8}, {"0Xff\n", 0, 255}, {"-0x10", 0, -16},
		{"2147483647", 0, INT_MAX}, {"-2147483648\n", 0, INT_MIN},
		{"2147483648", -ERANGE, 0}, {"-2147483649", -ERANGE, 0},
		{"9223372036854775808", -ERANGE, 0},
		{"-9223372036854775809", -ERANGE, 0},
		{"18446744073709551616bad", -ERANGE, 0},
		{"2147483648bad", -EINVAL, 0}, {"-2147483649bad", -EINVAL, 0},
		{"", -EINVAL, 0}, {"+", -EINVAL, 0}, {"-", -EINVAL, 0},
		{"-+1", -EINVAL, 0}, {"--1", -EINVAL, 0}, {"0x", -EINVAL, 0},
		{"08", -EINVAL, 0}, {" 1", -EINVAL, 0}, {"1 ", -EINVAL, 0},
		{"1\n\n", -EINVAL, 0}, {NULL, -EINVAL, 0},
	};
	struct { int before, value, after; } integer = {.before = 0x45321, .after = 0x12345};
	struct kernel_param parameter = {.name = "integer", .ops = &param_ops_int, .arg = &integer.value};
	for (size_t i = 0; i < ARRAY_SIZE(signed_cases); i++) {
		integer.value = 771;
		assert(param_ops_int.set(signed_cases[i].text, &parameter) == signed_cases[i].error);
		assert(integer.value == (signed_cases[i].error ? 771 : signed_cases[i].value));
		assert(integer.before == 0x45321 && integer.after == 0x12345);
	}
	integer.value = INT_MIN;
	expect_text(&param_ops_int, &parameter, "-2147483648\n");
	const struct {
		const char *text;
		int error;
		unsigned int value;
	} unsigned_cases[] = {
		{"0", 0, 0}, {"+010", 0, 8}, {"0xABCDEF", 0, 0xabcdef},
		{"4294967295\n", 0, UINT_MAX}, {"0xffffffff", 0, UINT_MAX},
		{"4294967296", -ERANGE, 0}, {"0x100000000", -ERANGE, 0},
		{"18446744073709551616bad", -ERANGE, 0},
		{"4294967296bad", -EINVAL, 0}, {"-0", -EINVAL, 0}, {"-1", -EINVAL, 0},
		{"+", -EINVAL, 0}, {"", -EINVAL, 0}, {"09", -EINVAL, 0},
		{"0xg", -EINVAL, 0}, {"1\n2", -EINVAL, 0}, {NULL, -EINVAL, 0},
	};
	unsigned int number;
	parameter.arg = &number;
	const struct kernel_param_ops *const ops[] = {&param_ops_uint, &param_ops_hexint};
	for (size_t j = 0; j < ARRAY_SIZE(ops); j++) {
		for (size_t i = 0; i < ARRAY_SIZE(unsigned_cases); i++) {
			number = 991;
			assert(ops[j]->set(unsigned_cases[i].text, &parameter) == unsigned_cases[i].error);
			assert(number == (unsigned_cases[i].error ? 991 : unsigned_cases[i].value));
		}
	}
	number = UINT_MAX;
	expect_text(&param_ops_uint, &parameter, "4294967295\n");
	expect_text(&param_ops_hexint, &parameter, "0xffffffff\n");
	number = 0;
	expect_text(&param_ops_hexint, &parameter, "0x000000\n");
	number = 1;
	expect_text(&param_ops_hexint, &parameter, "0x000001\n");
	unsigned long long wide = 997;
	parameter.arg = &wide;
	assert(!param_ops_ullong.set("18446744073709551615\n", &parameter) && wide == ULLONG_MAX);
	expect_text(&param_ops_ullong, &parameter, "18446744073709551615\n");
	assert(param_ops_ullong.set("18446744073709551616", &parameter) == -ERANGE);
	assert(wide == ULLONG_MAX);
	assert(param_ops_ullong.set("-1", &parameter) == -EINVAL && wide == ULLONG_MAX);
	assert(param_ops_ullong.set("+0x", &parameter) == -EINVAL && wide == ULLONG_MAX);
	assert(!param_ops_ullong.set("+01777777777777777777777", &parameter) && wide == ULLONG_MAX);
	assert(!param_ops_ullong.set("+0Xff", &parameter) && wide == 255);
}

static void boolean_values(void)
{
	const char *const true_values[] = {
		NULL, "1", "1garbage", "e", "Enable", "y", "Yes", "t", "True", "on", "ON-more",
	};
	const char *const false_values[] = {
		"0", "0\nmore", "d", "Disable", "n", "No", "f", "False", "of", "OFF-more",
	};
	const char *const invalid_values[] = {"", "o", "ox", "+1", "2", " true", "\n"};
	struct { u8 before; bool value; u8 after; } boolean = {.before = 0x51, .after = 0x92};
	struct kernel_param parameter = {.name = "boolean", .ops = &param_ops_bool, .arg = &boolean.value};
	for (size_t i = 0; i < ARRAY_SIZE(true_values); i++) {
		boolean.value = false;
		assert(!param_ops_bool.set(true_values[i], &parameter) && boolean.value);
		assert(boolean.before == 0x51 && boolean.after == 0x92);
	}
	expect_text(&param_ops_bool, &parameter, "Y\n");
	for (size_t i = 0; i < ARRAY_SIZE(false_values); i++) {
		boolean.value = true;
		assert(!param_ops_bool.set(false_values[i], &parameter) && !boolean.value);
		assert(boolean.before == 0x51 && boolean.after == 0x92);
	}
	expect_text(&param_ops_bool, &parameter, "N\n");
	for (size_t i = 0; i < ARRAY_SIZE(invalid_values); i++) {
		boolean.value = true;
		assert(param_ops_bool.set(invalid_values[i], &parameter) == -EINVAL && boolean.value);
	}
	struct { int before, value, after; } bint = {.before = 0x12345, .after = 0x54321};
	parameter.arg = &bint.value;
	for (size_t i = 0; i < ARRAY_SIZE(true_values); i++) {
		bint.value = 0x7f7f7f7f;
		assert(!param_ops_bint.set(true_values[i], &parameter) && bint.value == 1);
		assert(bint.before == 0x12345 && bint.after == 0x54321);
	}
	expect_text(&param_ops_bint, &parameter, "1\n");
	for (size_t i = 0; i < ARRAY_SIZE(false_values); i++) {
		bint.value = 0x7f7f7f7f;
		assert(!param_ops_bint.set(false_values[i], &parameter) && bint.value == 0);
	}
	expect_text(&param_ops_bint, &parameter, "0\n");
	for (size_t i = 0; i < ARRAY_SIZE(invalid_values); i++) {
		bint.value = -781;
		assert(param_ops_bint.set(invalid_values[i], &parameter) == -EINVAL && bint.value == -781);
	}
	assert(param_ops_bool.flags == KERNEL_PARAM_OPS_FL_NOARG);
	assert(param_ops_bint.flags == KERNEL_PARAM_OPS_FL_NOARG);
	const struct kernel_param_ops *const scalar_ops[] = {
		&param_ops_int, &param_ops_uint, &param_ops_hexint, &param_ops_ullong,
		&param_ops_string, &param_ops_charp,
	};
	for (size_t i = 0; i < ARRAY_SIZE(scalar_ops); i++)
		assert(!scalar_ops[i]->flags);
	assert(!param_ops_bool.free && !param_ops_bint.free && !param_ops_string.free);
}

static void fixed_strings(void)
{
	struct { u8 before; char value[5]; u8 after; } storage = {.before = 0x81, .after = 0x36};
	const struct kparam_string string = {.maxlen = sizeof(storage.value), .string = storage.value};
	struct kernel_param parameter = {.name = "fixed", .ops = &param_ops_string, .str = &string};
	memset(storage.value, 0x74, sizeof(storage.value));
	assert(!param_ops_string.set("abcd", &parameter));
	expect_text(&param_ops_string, &parameter, "abcd\n");
	assert(param_ops_string.set("abcde", &parameter) == -ENOSPC);
	assert(!memcmp(storage.value, "abcd", 5));
	assert(storage.before == 0x81 && storage.after == 0x36);
	assert(param_ops_string.set(NULL, &parameter) == -EINVAL);
	assert(!param_ops_string.set("\n", &parameter));
	expect_text(&param_ops_string, &parameter, "\n\n");
	assert(!param_ops_string.set("", &parameter));
	expect_text(&param_ops_string, &parameter, "\n");
	char single = 'x';
	const struct kparam_string one = {.maxlen = 1, .string = &single};
	parameter.str = &one;
	assert(param_ops_string.set("x", &parameter) == -ENOSPC && single == 'x');
	assert(!param_ops_string.set("", &parameter) && !single);
	const struct kparam_string zero = {.maxlen = 0, .string = &single};
	parameter.str = &zero;
	assert(param_ops_string.set("", &parameter) == -ENOSPC && !single);
	char large[PAGE_SIZE + 32];
	memset(large, 'z', sizeof(large));
	large[sizeof(large) - 1] = '\0';
	const struct kparam_string huge = {.maxlen = sizeof(large), .string = large};
	parameter.str = &huge;
	char output[PAGE_SIZE + 1];
	memset(output, 0x6a, sizeof(output));
	assert(param_ops_string.get(output, &parameter) == (int)PAGE_SIZE - 1);
	for (size_t i = 0; i < PAGE_SIZE - 1; i++)
		assert(output[i] == 'z');
	assert(!output[PAGE_SIZE - 1] && output[PAGE_SIZE] == 0x6a);
}

static void pointer_strings(const struct stela_linux_owner *owner)
{
	char *target = "borrowed-default";
	char *borrowed = target;
	struct kernel_param parameter = {.name = "pointer", .ops = &param_ops_charp, .arg = &target};
	assert(param_ops_charp.free == param_free_charp);
	expect_text(&param_ops_charp, &parameter, "borrowed-default\n");
	param_ops_charp.free(&target);
	assert(target == borrowed && !owned_strings && !string_releases);
	char mutable[] = "copied-input";
	assert(!param_ops_charp.set(mutable, &parameter));
	assert(target != mutable && !strcmp(target, mutable));
	mutable[0] = 'x';
	expect_text(&param_ops_charp, &parameter, "copied-input\n");
	char *previous = target;
	size_t allocations = string_allocations;
	size_t releases = string_releases;
	fail_string_allocation = true;
	assert(param_ops_charp.set("failure", &parameter) == -ENOMEM);
	fail_string_allocation = false;
	assert(target == previous && !strcmp(target, "copied-input"));
	assert(string_allocations == allocations && string_releases == releases);
	assert(param_ops_charp.set(NULL, &parameter) == -EINVAL && target == previous);
	assert(!param_ops_charp.set(target + 7, &parameter));
	expect_text(&param_ops_charp, &parameter, "input\n");
	assert(string_allocations == allocations + 1 && string_releases == releases + 1);
	/* Owned bytes are not borrowed from a temporary Linux execution owner. */
	stela_linux_exit();
	stela_linux_enter(&stela_linux_bare);
	expect_text(&param_ops_charp, &parameter, "input\n");
	assert(!param_ops_charp.set("next-owner", &parameter));
	stela_linux_exit();
	stela_linux_enter(owner);
	expect_text(&param_ops_charp, &parameter, "next-owner\n");
	char long_value[PARAM_STRING_LIMIT + 2];
	memset(long_value, 'a', sizeof(long_value));
	long_value[sizeof(long_value) - 1] = '\0';
	previous = target;
	allocations = string_allocations;
	assert(param_ops_charp.set(long_value, &parameter) == -ENOSPC && target == previous);
	assert(string_allocations == allocations);
	long_value[PARAM_STRING_LIMIT] = '\0';
	assert(!param_ops_charp.set(long_value, &parameter));
	assert(strlen(target) == PARAM_STRING_LIMIT);
	char output[PAGE_SIZE];
	assert(param_ops_charp.get(output, &parameter) == (int)PARAM_STRING_LIMIT + 1);
	assert(output[PARAM_STRING_LIMIT] == '\n' && !output[PARAM_STRING_LIMIT + 1]);
	char *other = "other-borrowed";
	struct kernel_param second = {.name = "second", .ops = &param_ops_charp, .arg = &other};
	assert(!param_ops_charp.set("second-owned", &second));
	previous = target;
	param_ops_charp.free(&target); /* Non-head ledger removal. */
	assert(target == previous);
	param_ops_charp.free(&target); /* Already removed; do not double free. */
	expect_text(&param_ops_charp, &second, "second-owned\n");
	param_ops_charp.free(&other);
	assert(!owned_strings && string_allocations == string_releases);
	target = NULL;
	param_ops_charp.free(&target);
	expect_text(&param_ops_charp, &parameter, "(null)\n");
	assert(!param_ops_charp.set("", &parameter));
	expect_text(&param_ops_charp, &parameter, "\n");
	param_ops_charp.free(&target);
	assert(!owned_strings && string_allocations == string_releases);
}

static void charp_contexts(void)
{
	char *target = "context-default";
	struct kernel_param parameter = {.name = "context", .ops = &param_ops_charp, .arg = &target};
	for (unsigned int context = 0; context < 4; context++) {
		unsigned long irq = 0;
		switch (context) {
		case 0: preempt_disable(); break;
		case 1: rcu_read_lock(); break;
		case 2: local_bh_disable(); break;
		case 3: irq = arch_local_irq_save(); break;
		}
		unsigned int before = refusals;
		size_t allocations = string_allocations;
		assert(param_ops_charp.set("refused", &parameter) == -EOPNOTSUPP);
		assert(refusals == before + 1 && string_allocations == allocations);
		expect_text(&param_ops_charp, &parameter, "context-default\n");
		switch (context) {
		case 0: preempt_enable(); break;
		case 1: rcu_read_unlock(); break;
		case 2: local_bh_enable(); break;
		case 3: arch_local_irq_restore(irq); break;
		}
	}
	param_ops_charp.free(&target);
	assert(!owned_strings && string_allocations == string_releases);
}

static void outside_owner(void)
{
	int value = 1;
	struct kernel_param parameter = {.arg = &value};
	(void)param_ops_int.set("2", &parameter);
}

static void strict_context(void)
{
	char *value = "literal";
	struct kernel_param parameter = {.arg = &value};
	stela_linux_enter(&stela_linux_bare);
	rcu_read_lock();
	(void)param_ops_charp.set("strict", &parameter);
}

int main(void)
{
	const struct stela_linux_services services = {.unsupported = unsupported};
	const struct stela_linux_owner owner = {.services = &services, .context = &refusals};
	stela_linux_enter(&owner);
	numeric_values();
	boolean_values();
	fixed_strings();
	pointer_strings(&owner);
	charp_contexts();
	assert(!owned_strings && string_allocations == string_releases && refusals == 4);
	stela_linux_exit();
	assert(stela_test_traps(outside_owner));
	assert(stela_test_traps(strict_context));
	printf("Linux parameters: typed grammar, text, bounded strings and owned teardown passed\n");
	return 0;
}
#endif
