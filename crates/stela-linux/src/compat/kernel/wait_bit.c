// SPDX-License-Identifier: MIT
/* Linux's bit and variable waits, following Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 kernel/sched/wait_bit.c: waiters
 * on a bit or a variable share a queue hashed from its address, and each
 * wake reaches only the waiters for its own bit or variable. */
#include <linux/hash.h>
#include <linux/jiffies.h>
#include <linux/sched/signal.h>
#include <linux/wait_bit.h>

#define WAIT_TABLE_BITS 8
#define WAIT_TABLE_SIZE (1 << WAIT_TABLE_BITS)

static wait_queue_head_t bit_wait_table[WAIT_TABLE_SIZE] __cacheline_aligned;
static bool table_ready;

void wait_bit_init(void)
{
	for (int i = 0; i < WAIT_TABLE_SIZE; i++)
		init_waitqueue_head(bit_wait_table + i);
	table_ready = true;
}

/* Linux initializes the table at boot; here its first user does, which the
 * one context running Linux code serializes. */
static wait_queue_head_t *table_entry(unsigned long hash)
{
	if (!table_ready)
		wait_bit_init();
	return bit_wait_table + hash;
}

wait_queue_head_t *bit_waitqueue(unsigned long *word, int bit)
{
	const int shift = BITS_PER_LONG == 32 ? 5 : 6;
	unsigned long val = (unsigned long)word << shift | (unsigned long)bit;
	return table_entry(hash_long(val, WAIT_TABLE_BITS));
}

wait_queue_head_t *__var_waitqueue(void *p)
{
	return table_entry(hash_ptr(p, WAIT_TABLE_BITS));
}

/* The waking key when it names the entry's own bit or variable. */
struct wait_bit_key *__var_wake_key(struct wait_queue_entry *wq_entry, void *arg)
{
	struct wait_bit_key *key = arg;
	struct wait_bit_queue_entry *wbq_entry =
		container_of(wq_entry, struct wait_bit_queue_entry, wq_entry);
	if (wbq_entry->key.flags != key->flags || wbq_entry->key.bit_nr != key->bit_nr)
		return NULL;
	return key;
}

int wake_bit_function(struct wait_queue_entry *wq_entry, unsigned mode, int sync, void *arg)
{
	struct wait_bit_key *key = __var_wake_key(wq_entry, arg);
	if (!key || test_bit(key->bit_nr, key->flags))
		return 0;
	return autoremove_wake_function(wq_entry, mode, sync, key);
}

static int var_wake_function(struct wait_queue_entry *wq_entry, unsigned mode, int sync,
			     void *arg)
{
	struct wait_bit_key *key = __var_wake_key(wq_entry, arg);
	if (!key)
		return 0;
	return autoremove_wake_function(wq_entry, mode, sync, key);
}

int __wait_on_bit(struct wait_queue_head *wq_head, struct wait_bit_queue_entry *wbq_entry,
		  wait_bit_action_f *action, unsigned mode)
{
	int ret = 0;
	do {
		prepare_to_wait(wq_head, &wbq_entry->wq_entry, (int)mode);
		if (test_bit(wbq_entry->key.bit_nr, wbq_entry->key.flags))
			ret = action(&wbq_entry->key, (int)mode);
	} while (test_bit_acquire(wbq_entry->key.bit_nr, wbq_entry->key.flags) && !ret);
	finish_wait(wq_head, &wbq_entry->wq_entry);
	return ret;
}

int out_of_line_wait_on_bit(unsigned long *word, int bit, wait_bit_action_f *action,
			    unsigned mode)
{
	DEFINE_WAIT_BIT(wq_entry, word, bit);
	return __wait_on_bit(bit_waitqueue(word, bit), &wq_entry, action, mode);
}

int out_of_line_wait_on_bit_timeout(unsigned long *word, int bit, wait_bit_action_f *action,
				    unsigned mode, unsigned long timeout)
{
	DEFINE_WAIT_BIT(wq_entry, word, bit);
	wq_entry.key.timeout = jiffies + timeout;
	return __wait_on_bit(bit_waitqueue(word, bit), &wq_entry, action, mode);
}

int __wait_on_bit_lock(struct wait_queue_head *wq_head, struct wait_bit_queue_entry *wbq_entry,
		       wait_bit_action_f *action, unsigned mode)
{
	int ret = 0;
	for (;;) {
		prepare_to_wait_exclusive(wq_head, &wbq_entry->wq_entry, (int)mode);
		if (test_bit(wbq_entry->key.bit_nr, wbq_entry->key.flags)) {
			ret = action(&wbq_entry->key, (int)mode);
			if (ret)
				finish_wait(wq_head, &wbq_entry->wq_entry);
		}
		if (!test_and_set_bit(wbq_entry->key.bit_nr, wbq_entry->key.flags)) {
			if (!ret)
				finish_wait(wq_head, &wbq_entry->wq_entry);
			return 0;
		}
		if (ret)
			return ret;
	}
}

int out_of_line_wait_on_bit_lock(unsigned long *word, int bit, wait_bit_action_f *action,
				 unsigned mode)
{
	DEFINE_WAIT_BIT(wq_entry, word, bit);
	return __wait_on_bit_lock(bit_waitqueue(word, bit), &wq_entry, action, mode);
}

void __wake_up_bit(struct wait_queue_head *wq_head, unsigned long *word, int bit)
{
	struct wait_bit_key key = __WAIT_BIT_KEY_INITIALIZER(word, bit);
	if (waitqueue_active(wq_head))
		__wake_up(wq_head, (unsigned int)TASK_NORMAL, 1, &key);
}

void wake_up_bit(unsigned long *word, int bit)
{
	__wake_up_bit(bit_waitqueue(word, bit), word, bit);
}

void init_wait_var_entry(struct wait_bit_queue_entry *wbq_entry, void *var, int flags)
{
	*wbq_entry = (struct wait_bit_queue_entry){
		.key = {.flags = var, .bit_nr = -1},
		.wq_entry = {
			.flags = (unsigned int)flags,
			.private = current,
			.func = var_wake_function,
			.entry = LIST_HEAD_INIT(wbq_entry->wq_entry.entry),
		},
	};
}

void wake_up_var(void *var)
{
	__wake_up_bit(__var_waitqueue(var), var, -1);
}

int bit_wait(struct wait_bit_key *word, int mode)
{
	(void)word;
	schedule();
	return signal_pending_state((unsigned int)mode, current) ? -EINTR : 0;
}

int bit_wait_io(struct wait_bit_key *word, int mode)
{
	(void)word;
	io_schedule();
	return signal_pending_state((unsigned int)mode, current) ? -EINTR : 0;
}

int bit_wait_timeout(struct wait_bit_key *word, int mode)
{
	unsigned long now = READ_ONCE(jiffies);
	if (time_after_eq(now, word->timeout))
		return -EAGAIN;
	schedule_timeout((long)(word->timeout - now));
	return signal_pending_state((unsigned int)mode, current) ? -EINTR : 0;
}
