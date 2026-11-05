// SPDX-License-Identifier: GPL-2.0-only
/* Inline common-library tests only. Production CRCs and tables come from
 * unchanged Linux lib/crc/crc32-main.c and its original table generator. */
#ifdef STELA_LINUX_CRC_TEST
#include <linux/crc32.h>
#include <linux/string.h>
#include <stela/test.h>

typedef u32 (*crc_function)(u32 seed, const void *bytes, size_t length);

struct variant {
	crc_function function;
	u32 polynomial;
	u32 check;
	bool most_significant_first;
};

/* Independent bit-serial test oracle, without the production lookup tables.
 * Check values below use seed ~0 and no final inversion, as Linux requires. */
static const struct variant variants[] = {
	{crc32_le, 0xedb88320u, 0x340bc6d9u, false},
	{crc32_be, 0x04c11db7u, 0x0376e6e7u, true},
	{crc32c, 0x82f63b78u, 0x1cf96d7cu, false},
};

static u32 reference(const struct variant *variant, u32 crc, const u8 *bytes, size_t length)
{
	for (size_t i = 0; i < length; i++) {
		if (variant->most_significant_first)
			crc ^= (u32)bytes[i] << 24;
		else
			crc ^= (u32)bytes[i];
		for (unsigned int bit = 0; bit < 8; bit++) {
			if (variant->most_significant_first) {
				bool carry = (crc & 0x80000000u) != 0;
				crc <<= 1;
				if (carry)
					crc ^= variant->polynomial;
			} else {
				bool carry = (crc & 1u) != 0;
				crc >>= 1;
				if (carry)
					crc ^= variant->polynomial;
			}
		}
	}
	return crc;
}

static u32 reverse32(u32 value)
{
	u32 reversed = 0;
	for (unsigned int bit = 0; bit < 32; bit++) {
		reversed = (reversed << 1) | (value & 1u);
		value >>= 1;
	}
	return reversed;
}

static void vectors_and_aliases(void)
{
	static const u8 digits[] = "123456789";
	for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); i++) {
		const struct variant *variant = &variants[i];
		assert(variant->function(~0u, digits, 9) == variant->check);
		assert(reference(variant, ~0u, digits, 9) == variant->check);
	}
	assert((crc32_le(~0u, digits, 9) ^ ~0u) == 0xcbf43926u);
	assert((crc32c(~0u, digits, 9) ^ ~0u) == 0xe3069283u);
	assert(crc32(0x12345678u, digits, 9) == crc32_le(0x12345678u, digits, 9));
	assert(ether_crc_le(9, digits) == variants[0].check);
	/* This reaches the real unchanged byte_rev_table through Linux's macro. */
	assert(ether_crc(9, digits) == reverse32(variants[0].check));
	assert(crc32_optimizations() == 0);
}

static void seeds_alignment_and_incremental(void)
{
	static const u32 seeds[] = {0, ~0u, 1, 0x12345678u, 0x80000000u, 0xdeadbeefu};
	static const size_t lengths[] = {0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64,
				       127, 128, 255, 256};
	u8 all_bytes[256];
	u8 zeros[256] = {0};
	u8 storage[256 + 64];
	for (size_t i = 0; i < sizeof(all_bytes); i++)
		all_bytes[i] = (u8)i;
	for (size_t variant_index = 0; variant_index < sizeof(variants) / sizeof(variants[0]);
	     variant_index++) {
		const struct variant *variant = &variants[variant_index];
		for (size_t seed_index = 0; seed_index < sizeof(seeds) / sizeof(seeds[0]); seed_index++) {
			u32 seed = seeds[seed_index];
			assert(variant->function(seed, NULL, 0) == seed);
			for (size_t j = 0; j < sizeof(lengths) / sizeof(lengths[0]); j++)
				assert(variant->function(seed, zeros, lengths[j]) ==
				       reference(variant, seed, zeros, lengths[j]));
			for (size_t offset = 0; offset < 64; offset++) {
				memcpy(storage + offset, all_bytes, sizeof(all_bytes));
				for (size_t j = 0; j < sizeof(lengths) / sizeof(lengths[0]); j++) {
					size_t length = lengths[j];
					assert(variant->function(seed, storage + offset, length) ==
					       reference(variant, seed, all_bytes, length));
				}
				assert(!memcmp(storage + offset, all_bytes, sizeof(all_bytes)));
			}
			memcpy(storage + 1, all_bytes, sizeof(all_bytes));
			u32 expected = reference(variant, seed, all_bytes, sizeof(all_bytes));
			for (size_t split = 0; split <= sizeof(all_bytes); split++) {
				u32 first = variant->function(seed, storage + 1, split);
				assert(variant->function(first, storage + 1 + split,
						 sizeof(all_bytes) - split) == expected);
			}
			/* Every possible single input byte, including the high-bit cases. */
			for (size_t byte = 0; byte < sizeof(all_bytes); byte++)
				assert(variant->function(seed, &all_bytes[byte], 1) ==
				       reference(variant, seed, &all_bytes[byte], 1));
		}
	}
	/* End the misaligned valid input exactly at an ASan allocation boundary. */
	u8 *exact = calloc(sizeof(all_bytes) + 1, 1);
	assert(exact);
	memcpy(exact + 1, all_bytes, sizeof(all_bytes));
	for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); i++)
		assert(variants[i].function(~0u, exact + 1, sizeof(all_bytes)) ==
		       reference(&variants[i], ~0u, all_bytes, sizeof(all_bytes)));
	free(exact);
}

int main(void)
{
	/* Deliberately no stela_linux_enter: these are pure any-context services. */
	vectors_and_aliases();
	seeds_alignment_and_incremental();
	printf("Linux CRC: IEEE LE/BE, CRC32C, seeds, incremental input, aliases and unaligned bytes passed\n");
	return 0;
}
#endif
