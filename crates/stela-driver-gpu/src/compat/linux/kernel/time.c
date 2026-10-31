// SPDX-License-Identifier: MIT
/* Linux's clock and waits, on the running owner's monotonic clock and delay.
 * Sleeps last at least as long as Linux's and may end at the requested
 * maximum; busy waits are atomic delays. */
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/preempt.h>
#include <linux/timekeeping.h>
#include <stela/linux.h>

static void delay_us(u64 minimum, u64 maximum, bool atomic)
{
	const struct stela_linux_owner *owner = stela_linux_owner();
	/* Sleeping in a read-side, IRQ-disabled or callback section cannot
	 * provide a valid grace period or preserve its nonblocking contract. */
	if (!atomic && !stela_linux_quiescent())
		__builtin_trap();
	if (!owner->services->delay_us)
		__builtin_trap();
	owner->services->delay_us(owner->context, minimum, maximum, atomic);
}

ktime_t ktime_get(void)
{
	const struct stela_linux_owner *owner = stela_linux_owner();
	if (!owner->services->now_ns)
		__builtin_trap();
	return owner->services->now_ns(owner->context);
}

/* At least msecs, as Linux sleeps whole jiffies; HZ is 1000. */
void msleep(unsigned int msecs)
{
	delay_us((u64)msecs * USEC_PER_MSEC, ((u64)msecs + 1) * USEC_PER_MSEC, false);
}

void usleep_range_state(unsigned long min, unsigned long max, unsigned int state)
{
	(void)state;
	delay_us(min, max, false);
}

void __udelay(unsigned long usecs)
{
	delay_us(usecs, usecs, true);
}

void __ndelay(unsigned long nsecs)
{
	u64 usecs = DIV_ROUND_UP((u64)nsecs, NSEC_PER_USEC);
	delay_us(usecs, usecs, true);
}

/* xloops is microseconds scaled by 2^32 / USEC_PER_SEC, rounded up. */
void __const_udelay(unsigned long xloops)
{
	u64 usecs = DIV_ROUND_UP((u64)xloops * USEC_PER_SEC, 1ULL << 32);
	delay_us(usecs, usecs, true);
}

unsigned long __msecs_to_jiffies(const unsigned int m)
{
	return m > jiffies_to_msecs(MAX_JIFFY_OFFSET) ? MAX_JIFFY_OFFSET : _msecs_to_jiffies(m);
}

u64 nsecs_to_jiffies64(u64 n)
{
	return div_u64(n, NSEC_PER_SEC / HZ);
}

unsigned long nsecs_to_jiffies(u64 n)
{
	return (unsigned long)nsecs_to_jiffies64(n);
}

struct timespec64 ns_to_timespec64(s64 nsec)
{
	s32 remainder;
	s64 seconds = div_s64_rem(nsec, NSEC_PER_SEC, &remainder);

	if (remainder < 0) {
		seconds--;
		remainder += NSEC_PER_SEC;
	}
	return (struct timespec64){.tv_sec = seconds, .tv_nsec = remainder};
}

unsigned long __usecs_to_jiffies(const unsigned int u)
{
	return u > jiffies_to_usecs(MAX_JIFFY_OFFSET) ? MAX_JIFFY_OFFSET : _usecs_to_jiffies(u);
}
