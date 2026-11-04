// SPDX-License-Identifier: MIT
/* Clock reads from the retained owner, independent of timer delivery. */
#include <linux/errno.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/timekeeping.h>
#include <stela/linux.h>
#include <stela/time.h>

ktime_t ktime_get(void)
{
	const struct stela_linux_owner *owner = stela_linux_owner();
	if (!owner->services->now_ns)
		__builtin_trap();
	return owner->services->now_ns(owner->context);
}

int stela_linux_boottime_ns(s64 *now)
{
	const struct stela_linux_owner *owner = stela_linux_owner();
	s64 sample = KTIME_MAX;
	if (!owner->services->boottime_ns ||
	    !owner->services->boottime_ns(owner->context, &sample))
		return -ENODEV;
	if (sample < 0 || sample == KTIME_MAX)
		return -ERANGE;
	*now = sample;
	return 0;
}

static void realtime(struct timespec64 *ts, u32 mode, u32 tick_ns)
{
	const struct stela_linux_owner *owner = stela_linux_owner();
	s64 seconds;
	u32 nanoseconds;

	if (owner->services->realtime_at &&
	    owner->services->realtime_at(owner->context, ktime_get(), mode,
					 tick_ns, &seconds, &nanoseconds)) {
		*ts = (struct timespec64){.tv_sec = seconds, .tv_nsec = nanoseconds};
		return;
	}

	/* The void Linux API uses the epoch when this host has no UTC source. */
	stela_linux_unsupported("realtime clock unavailable");
	*ts = (struct timespec64){};
}

void ktime_get_real_ts64(struct timespec64 *ts)
{
	realtime(ts, 0, 0);
}

void ktime_get_coarse_real_ts64_mg(struct timespec64 *ts)
{
	realtime(ts, 1, TICK_NSEC);
}

void ktime_get_real_ts64_mg(struct timespec64 *ts)
{
	realtime(ts, 2, 0);
}

ktime_t ktime_get_with_offset(enum tk_offsets offs)
{
	switch (offs) {
	case TK_OFFS_BOOT: {
		s64 sample;
		if (stela_linux_boottime_ns(&sample))
			stela_linux_fatal("Linux boottime clock unavailable");
		return sample;
	}
	case TK_OFFS_REAL: {
		struct timespec64 ts;
		ktime_get_real_ts64(&ts);
		__int128 ns = (__int128)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
		if (ns < S64_MIN || ns >= KTIME_MAX)
			stela_linux_fatal("Linux realtime clock outside ktime range");
		return (ktime_t)ns;
	}
	case TK_OFFS_TAI:
		stela_linux_fatal("Linux TAI clock unavailable");
	default:
		stela_linux_fatal("invalid Linux clock offset");
	}
}
