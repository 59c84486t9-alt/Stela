// SPDX-License-Identifier: MIT
/* Hosted ABI/dispatch fixtures; deterministic bytes are test inputs, not
 * entropy or a native IRQ/CPU qualification. Link the actual common archive. */
#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <linux/random.h>
#include <linux/string.h>
#include <stela/linux.h>
#include <stela/test.h>

struct fixture {
	size_t bytes, calls, next;
	const u32 *words;
	size_t word_count, word_index;
};

static void bytes(void *opaque, void *output, size_t size)
{
	struct fixture *fixture = opaque;
	assert(output && size);
	fixture->bytes += size;
	fixture->calls++;
	if (fixture->words) {
		assert(size == sizeof(u32) && fixture->word_index < fixture->word_count);
		u32 value = fixture->words[fixture->word_index++];
		memcpy(output, &value, sizeof(value));
		return;
	}
	u8 *data = output;
	for (size_t i = 0; i < size; i++)
		data[i] = (u8)fixture->next++;
}

static void streams_and_atomic_state(void)
{
	struct fixture fixture = {};
	const struct stela_linux_services services = {.random_bytes = bytes};
	const struct stela_linux_owner owner = {.services = &services, .context = &fixture};
	stela_linux_enter(&owner);
	get_random_bytes(NULL, 0);
	assert(!fixture.calls && !fixture.bytes);
	assert(get_random_u8() == 0);
	assert(get_random_u16() == 0x0201);
	assert(get_random_u32() == 0x06050403);
	assert(get_random_u64() == 0x0e0d0c0b0a090807ULL);
	assert(fixture.bytes == 15 && fixture.calls == 4);
	u8 output[15];
	memset(output, 0xa5, sizeof(output));
	get_random_bytes(output + 1, 13);
	assert(output[0] == 0xa5 && output[14] == 0xa5);
	for (size_t i = 1; i < 14; i++)
		assert(output[i] == 14 + i);
	unsigned long flags;
	raw_local_irq_save(flags);
	preempt_count_add(2);
	int count = preempt_count();
	get_random_bytes(output + 1, 13);
	assert(preempt_count() == count && irqs_disabled());
	preempt_count_sub(2);
	raw_local_irq_restore(flags);
	assert(!preempt_count() && !irqs_disabled());
	u8 large[4097];
	get_random_bytes(large, sizeof(large));
	assert(fixture.bytes == 15 + 13 + 13 + sizeof(large));
	assert(fixture.calls == 7);
	stela_linux_exit();
}

static void bounded_sampling(void)
{
	const struct { u32 ceil, first, second, expected; size_t draws; } cases[] = {
		{0, 0x12345678, 0, 0x12345678, 1},
		{1, 0xffffffff, 0, 0, 1},
		{3, 0, 0xffffffff, 2, 2},
		{0x80000001, 0, 0xffffffff, 0x80000000, 2},
		{0xffffffff, 0xffffffff, 0, 0xfffffffe, 1},
	};
	for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
		u32 words[] = {cases[i].first, cases[i].second};
		struct fixture fixture = {.words = words, .word_count = ARRAY_SIZE(words)};
		const struct stela_linux_services services = {.random_bytes = bytes};
		const struct stela_linux_owner owner = {.services = &services, .context = &fixture};
		stela_linux_enter(&owner);
		assert(__get_random_u32_below(cases[i].ceil) == cases[i].expected);
		assert(fixture.word_index == cases[i].draws);
		stela_linux_exit();
	}
}

static u8 refused_output[8];
static void unchanged(void)
{
	for (size_t i = 0; i < sizeof(refused_output); i++)
		assert(refused_output[i] == 0xa5);
}
static void returning_log(void *context, int level, const char *message)
{
	(void)context; (void)level; (void)message;
	unchanged();
}
static void witness_log(void *context, int level, const char *message)
{
	returning_log(context, level, message);
	stela_test_witness_passed();
}
static void no_owner(void) { get_random_bytes(refused_output, sizeof(refused_output)); }
static void no_service(void)
{
	const struct stela_linux_services services = {.log = returning_log};
	const struct stela_linux_owner owner = {.services = &services};
	stela_linux_enter(&owner);
	get_random_bytes(refused_output, sizeof(refused_output));
}
static void no_service_witness(void)
{
	const struct stela_linux_services services = {.log = witness_log};
	const struct stela_linux_owner owner = {.services = &services};
	stela_linux_enter(&owner);
	get_random_bytes(refused_output, sizeof(refused_output));
}
static void null_output(void)
{
	struct fixture fixture = {};
	const struct stela_linux_services services = {.random_bytes = bytes};
	const struct stela_linux_owner owner = {.services = &services, .context = &fixture};
	stela_linux_enter(&owner);
	get_random_bytes(NULL, 1);
}
static void reenter(void *context, void *output, size_t size)
{
	(void)context; (void)output; (void)size;
	const struct stela_linux_owner *owner = stela_linux_owner();
	stela_linux_exit();
	stela_linux_enter(owner);
}
static void changed_lease(void)
{
	const struct stela_linux_services services = {.random_bytes = reenter};
	const struct stela_linux_owner owner = {.services = &services};
	stela_linux_enter(&owner);
	get_random_bytes(refused_output, sizeof(refused_output));
}
static void change_count(void *context, void *output, size_t size)
{
	(void)context; (void)output; (void)size;
	preempt_count_add(1);
}
static void changed_atomic(void)
{
	const struct stela_linux_services services = {.random_bytes = change_count};
	const struct stela_linux_owner owner = {.services = &services};
	stela_linux_enter(&owner);
	get_random_bytes(refused_output, sizeof(refused_output));
}

int main(void)
{
	streams_and_atomic_state();
	bounded_sampling();
	memset(refused_output, 0xa5, sizeof(refused_output));
	assert(stela_test_traps(no_owner));
	assert(stela_test_traps(no_service));
	assert(stela_test_witnessed(no_service_witness));
	assert(stela_test_traps(null_output));
	assert(stela_test_traps(changed_lease));
	assert(stela_test_traps(changed_atomic));
	printf("Linux random: owner dispatch, scalar/rejection bounds, atomic-state retention and missing-service output proof passed\n");
	return 0;
}