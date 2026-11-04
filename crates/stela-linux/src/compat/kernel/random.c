// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/* Copyright (C) 2017-2024 Jason A. Donenfeld <Jason@zx2c4.com>.
 * Copyright Matt Mackall, 2003, 2004, 2005.
 * Copyright Theodore Ts'o, 1994-1999.
 *
 * Uniform-below sampling adapts drivers/char/random.c at Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8. The explicit u32 return cast
 * records that the high product half fits. Byte generation is Stela's
 * already-seeded platform CSPRNG, not Linux CRNG readiness or pool accounting.
 */
#include <crypto/blake2s.h>
#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <linux/random.h>
#include <stela/linux.h>
#include <stela/task.h>

void get_random_bytes(void *bytes, size_t size)
{
	const struct stela_linux_owner *owner = stela_linux_owner();
	if (!size)
		return;
	/* Missing capability is a diagnostic stop, never substituted bytes.
	 * Production kernel registration must refuse it before this API is used. */
	if (!bytes || !owner->services->random_bytes)
		stela_linux_fatal("kernel secure random capability unavailable");
	struct stela_linux_lease lease;
	stela_linux_lease_snapshot(&lease);
	int count = preempt_count();
	owner->services->random_bytes(owner->context, bytes, size);
	if (!stela_linux_lease_matches(&lease) || preempt_count() != count)
		__builtin_trap();
}

void add_device_randomness(const void *bytes, size_t size)
{
	const struct stela_linux_owner *owner = stela_linux_owner();
	unsigned long flags;

	if ((!bytes && size) || size > LONG_MAX)
		stela_linux_fatal("invalid kernel random input range");
	local_irq_save(flags);
	struct stela_linux_lease lease;
	stela_linux_lease_snapshot(&lease);
	int count = preempt_count();
	bool mixed = owner->services->mix_random &&
		owner->services->mix_random(owner->context, bytes, size);
	if (!stela_linux_lease_matches(&lease) || preempt_count() != count)
		__builtin_trap();
	local_irq_restore(flags);
	if (!mixed)
		stela_linux_unsupported("kernel random device input unavailable");
}

/* RFC 7693 keyed BLAKE2s over the domain, counter sample and device bytes.
 * The key is private output taken from the existing owner stream. */
void stela_linux_random_mix_key(const u8 *key, u64 ticks, const void *bytes,
			       size_t size, u8 *seed)
{
	static const u8 domain[] = "Stela Linux device data v1";
	struct blake2s_ctx context;
	__le64 sample = cpu_to_le64(ticks);

	blake2s_init_key(&context, BLAKE2S_HASH_SIZE, key, BLAKE2S_KEY_SIZE);
	blake2s_update(&context, domain, sizeof(domain) - 1);
	blake2s_update(&context, (const u8 *)&sample, sizeof(sample));
	if (size)
		blake2s_update(&context, bytes, size);
	blake2s_final(&context, seed);
}

u8 get_random_u8(void)
{
	u8 value;
	get_random_bytes(&value, sizeof(value));
	return value;
}

u16 get_random_u16(void)
{
	u16 value;
	get_random_bytes(&value, sizeof(value));
	return value;
}

u32 get_random_u32(void)
{
	u32 value;
	get_random_bytes(&value, sizeof(value));
	return value;
}

u64 get_random_u64(void)
{
	u64 value;
	get_random_bytes(&value, sizeof(value));
	return value;
}

u32 __get_random_u32_below(u32 ceil)
{
	/*
	 * This is the slow path for variable ceil. It is still fast, most of
	 * the time, by doing traditional reciprocal multiplication and
	 * opportunistically comparing the lower half to ceil itself, before
	 * falling back to computing a larger bound, and then rejecting samples
	 * whose lower half would indicate a range indivisible by ceil. The use
	 * of `-ceil % ceil` is analogous to `2^32 % ceil`, but is computable
	 * in 32-bits.
	 */
	u32 rand = get_random_u32();
	u64 mult;

	/*
	 * This function is technically undefined for ceil == 0, and in fact
	 * for the non-underscored constant version in the header, we build bug
	 * on that. But for the non-constant case, it's convenient to have that
	 * evaluate to being a straight call to get_random_u32(), so that
	 * get_random_u32_inclusive() can work over its whole range without
	 * undefined behavior.
	 */
	if (unlikely(!ceil))
		return rand;

	mult = (u64)ceil * rand;
	if (unlikely((u32)mult < ceil)) {
		u32 bound = -ceil % ceil;
		while (unlikely((u32)mult < bound))
			mult = (u64)ceil * get_random_u32();
	}
	return (u32)(mult >> 32);
}
