// SPDX-License-Identifier: MIT
/* Linux's tick count. As x86's linker script does, jiffies names
 * jiffies_64's low word, which on LP64 is all of it. The platform's timer
 * interrupt advances the word at HZ once its owner binds it to the clock, as
 * Linux's tick does, without running Linux code; until then it holds
 * INITIAL_JIFFIES. */
#include <linux/jiffies.h>

u64 jiffies_64 __cacheline_aligned_in_smp = INITIAL_JIFFIES;
extern unsigned long volatile jiffies __attribute__((alias("jiffies_64")));

#ifdef STELA_LINUX_JIFFIES_TEST
#include <linux/ratelimit.h>
#include <stela/linux.h>
#include <stela/test.h>

static unsigned int messages;

static void log_message(void *context, int level, const char *message)
{
	(void)context;
	assert(level == LOGLEVEL_WARNING && strstr(message, "callbacks suppressed"));
	messages++;
}

int main(void)
{
	assert(jiffies == INITIAL_JIFFIES && get_jiffies_64() == INITIAL_JIFFIES);
	WRITE_ONCE(jiffies_64, INITIAL_JIFFIES + 1);
	assert(jiffies == INITIAL_JIFFIES + 1);
	const struct stela_linux_services services = {.log = log_message};
	const struct stela_linux_owner owner = {.services = &services};
	stela_linux_enter(&owner);
	/* Two calls per tenth of a second; the tick moves the window. */
	DEFINE_RATELIMIT_STATE(state, HZ / 10, 2);
	assert(__ratelimit(&state) && __ratelimit(&state));
	assert(!__ratelimit(&state) && !__ratelimit(&state));
	WRITE_ONCE(jiffies_64, jiffies_64 + HZ / 10 - 1);
	assert(!__ratelimit(&state) && !messages);
	WRITE_ONCE(jiffies_64, jiffies_64 + 2);
	assert(__ratelimit(&state) && messages == 1);
	assert(__ratelimit(&state) && !__ratelimit(&state));
	stela_linux_exit();
	printf("Linux jiffies: one tick word under both names and tick-driven rate limits passed\n");
	return 0;
}
#endif
