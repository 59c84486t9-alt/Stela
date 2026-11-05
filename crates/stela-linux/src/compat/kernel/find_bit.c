// SPDX-License-Identifier: GPL-2.0-only
/* Inline tests only: production searches are Linux's lib/find_bit.c. */
#ifdef STELA_LINUX_FIND_BIT_TEST
#include <linux/bitmap.h>
#include <linux/string.h>
#include <stela/test.h>

enum operation { SET, ZERO, AND, ANDNOT, AND_AND, AND_ANDNOT, OR };

/* Deliberately bit-linear: no production scan, mask, hweight or bitmap helper. */
static bool bit(const unsigned long *map, unsigned long index)
{
	return ((map[index / BITS_PER_LONG] >> (index % BITS_PER_LONG)) & 1UL) != 0;
}

static bool match(const unsigned long *a, const unsigned long *b, const unsigned long *c,
		  unsigned long index, enum operation operation)
{
	bool av = bit(a, index), bv = bit(b, index), cv = bit(c, index);
	switch (operation) {
	case SET: return av;
	case ZERO: return !av;
	case AND: return av && bv;
	case ANDNOT: return av && !bv;
	case AND_AND: return av && bv && cv;
	case AND_ANDNOT: return av && bv && !cv;
	case OR: return av || bv;
	}
	assert(false);
	return false;
}

static unsigned long next(const unsigned long *a, const unsigned long *b,
			  const unsigned long *c, unsigned long size, unsigned long start,
			  enum operation operation)
{
	for (unsigned long i = start; i < size; i++)
		if (match(a, b, c, i, operation))
			return i;
	return size;
}

static unsigned long nth(const unsigned long *a, const unsigned long *b,
			 const unsigned long *c, unsigned long size, unsigned long ordinal,
			 enum operation operation)
{
	for (unsigned long i = 0; i < size; i++)
		if (match(a, b, c, i, operation)) {
			if (!ordinal)
				return i;
			ordinal--;
		}
	return size;
}

static void nth_result(unsigned long actual, unsigned long expected, unsigned long size)
{
	/* The upstream nth contract permits any >= size result for absence. */
	assert(expected < size ? actual == expected : actual >= size);
}

static void check(const unsigned long *a, const unsigned long *b,
		  const unsigned long *c, unsigned long size)
{
	assert(_find_first_bit(a, size) == next(a, b, c, size, 0, SET));
	assert(_find_first_zero_bit(a, size) == next(a, b, c, size, 0, ZERO));
	assert(_find_first_and_bit(a, b, size) == next(a, b, c, size, 0, AND));
	assert(_find_first_andnot_bit(a, b, size) == next(a, b, c, size, 0, ANDNOT));
	assert(_find_first_and_and_bit(a, b, c, size) == next(a, b, c, size, 0, AND_AND));
	assert(find_first_bit(a, size) == next(a, b, c, size, 0, SET));
	assert(find_first_zero_bit(a, size) == next(a, b, c, size, 0, ZERO));
	assert(find_first_and_bit(a, b, size) == next(a, b, c, size, 0, AND));
	assert(find_first_andnot_bit(a, b, size) == next(a, b, c, size, 0, ANDNOT));
	assert(find_first_and_and_bit(a, b, c, size) == next(a, b, c, size, 0, AND_AND));
	unsigned long last = size;
	for (unsigned long i = 0; i < size; i++)
		if (bit(a, i))
			last = i;
	assert(_find_last_bit(a, size) == last);
	assert(find_last_bit(a, size) == last);
	for (unsigned long start = 0; start <= size + 1; start++) {
		unsigned long set = next(a, b, c, size, start, SET);
		unsigned long zero = next(a, b, c, size, start, ZERO);
		unsigned long both = next(a, b, c, size, start, AND);
		unsigned long except = next(a, b, c, size, start, ANDNOT);
		unsigned long either = next(a, b, c, size, start, OR);
		assert(_find_next_bit(a, size, start) == set);
		assert(_find_next_zero_bit(a, size, start) == zero);
		assert(_find_next_and_bit(a, b, size, start) == both);
		assert(_find_next_andnot_bit(a, b, size, start) == except);
		assert(_find_next_or_bit(a, b, size, start) == either);
		assert(find_next_bit(a, size, start) == set);
		assert(find_next_zero_bit(a, size, start) == zero);
		assert(find_next_and_bit(a, b, size, start) == both);
		assert(find_next_andnot_bit(a, b, size, start) == except);
		assert(find_next_or_bit(a, b, size, start) == either);
#ifdef __LITTLE_ENDIAN
		assert(find_next_bit_le(a, size, start) == set);
		assert(find_next_zero_bit_le(a, size, start) == zero);
#endif
		unsigned long clump = ~0UL;
		unsigned long position = find_next_clump8(&clump, a, size, start);
		if (set == size) {
			assert(position == size && clump == ~0UL);
		} else {
			unsigned long base = set - set % 8;
			unsigned long expected = 0;
			/* The full storage byte includes bits before start/past size. */
			for (unsigned long j = 0; j < 8; j++)
				if (bit(a, base + j))
					expected |= 1UL << j;
			assert(position == base && clump == expected);
		}
	}
#ifdef __LITTLE_ENDIAN
	assert(find_first_zero_bit_le(a, size) == next(a, b, c, size, 0, ZERO));
#endif
	for (unsigned long n = 0; n <= size + 1; n++) {
		unsigned long set = nth(a, b, c, size, n, SET);
		unsigned long both = nth(a, b, c, size, n, AND);
		unsigned long except = nth(a, b, c, size, n, AND_ANDNOT);
		nth_result(__find_nth_bit(a, size, n), set, size);
		nth_result(__find_nth_and_bit(a, b, size, n), both, size);
		nth_result(__find_nth_and_andnot_bit(a, b, c, size, n), except, size);
		nth_result(find_nth_bit(a, size, n), set, size);
		nth_result(find_nth_and_bit(a, b, size, n), both, size);
		nth_result(find_nth_and_andnot_bit(a, b, c, size, n), except, size);
	}
	assert(_find_next_bit(a, size, ~0UL) == size);
	assert(_find_next_zero_bit(a, size, ~0UL) == size);
	assert(_find_next_and_bit(a, b, size, ~0UL) == size);
	assert(_find_next_andnot_bit(a, b, size, ~0UL) == size);
	assert(_find_next_or_bit(a, b, size, ~0UL) == size);
}

static void patterns_and_tails(void)
{
	static const unsigned long sizes[] = {
		0, 1, 7, 8, 9, 31, 32, 63, 64, 65, 127, 128, 129, 191, 192, 193, 257,
	};
	for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
		unsigned long size = sizes[s];
		unsigned long words = (size + BITS_PER_LONG - 1) / BITS_PER_LONG;
		/* No allocation for size zero: every direct scan must avoid NULL. */
		unsigned long *a = words ? calloc(words, sizeof(*a)) : NULL;
		unsigned long *b = words ? calloc(words, sizeof(*b)) : NULL;
		unsigned long *c = words ? calloc(words, sizeof(*c)) : NULL;
		assert(!words || (a && b && c));
		for (unsigned long pattern = 0; pattern < 8; pattern++) {
			for (unsigned long w = 0; w < words; w++)
				a[w] = b[w] = c[w] = 0;
			/* Include final-word padding in all patterns, with mixed tail bits. */
			for (unsigned long i = 0; i < words * BITS_PER_LONG; i++) {
				bool av = pattern == 1 || (pattern == 2 && i % 2 == 0) ||
					  (pattern == 3 && i % BITS_PER_LONG == 0) ||
					  (pattern == 4 && i % BITS_PER_LONG == BITS_PER_LONG - 1) ||
					  (pattern == 5 && i % 7 < 3) ||
					  (pattern == 6 && i >= size) ||
					  (pattern == 7 && i < size);
				if (av)
					a[i / BITS_PER_LONG] |= 1UL << (i % BITS_PER_LONG);
				if (i % 5 < 3)
					b[i / BITS_PER_LONG] |= 1UL << (i % BITS_PER_LONG);
				if (i % 3 == 1)
					c[i / BITS_PER_LONG] |= 1UL << (i % BITS_PER_LONG);
			}
			unsigned long saved[3][5] = {{0}};
			assert(words <= 5);
			if (words) {
				memcpy(saved[0], a, words * sizeof(*a));
				memcpy(saved[1], b, words * sizeof(*b));
				memcpy(saved[2], c, words * sizeof(*c));
			}
			check(a, b, c, size);
			if (words) {
				assert(!memcmp(saved[0], a, words * sizeof(*a)));
				assert(!memcmp(saved[1], b, words * sizeof(*b)));
				assert(!memcmp(saved[2], c, words * sizeof(*c)));
			}
		}
		/* Every single set position, including both sides of word boundaries. */
		for (unsigned long i = 0; i < size; i++) {
			for (unsigned long w = 0; w < words; w++)
				a[w] = 0;
			a[i / BITS_PER_LONG] = 1UL << (i % BITS_PER_LONG);
			assert(_find_first_bit(a, size) == i);
			assert(_find_last_bit(a, size) == i);
			assert(_find_next_bit(a, size, i) == i);
			assert(_find_next_bit(a, size, i + 1) == size);
			assert(__find_nth_bit(a, size, 0) == i);
			assert(__find_nth_bit(a, size, 1) >= size);
			assert(_find_first_and_bit(a, a, size) == i);
			assert(_find_first_andnot_bit(a, a, size) == size);
		}
		free(c);
		free(b);
		free(a);
	}
}

static void constant_word_helpers(void)
{
	unsigned long a = 0x81UL, b = 0xf1UL, c = 1UL;
	assert(find_first_bit(&a, 8) == 0);
	assert(find_next_bit(&a, 8, 1) == 7);
	assert(find_first_zero_bit(&a, 8) == 1);
	assert(find_next_zero_bit(&a, 8, 7) == 8);
	assert(find_last_bit(&a, 8) == 7);
	assert(find_first_and_bit(&a, &b, 8) == 0);
	assert(find_first_andnot_bit(&a, &b, 8) == 8);
	assert(find_first_and_and_bit(&a, &b, &c, 8) == 0);
	assert(find_next_and_bit(&a, &b, 8, 1) == 7);
	assert(find_next_andnot_bit(&a, &b, 8, 0) == 8);
	assert(find_next_or_bit(&a, &c, 8, 1) == 7);
	assert(find_nth_bit(&a, 8, 1) == 7);
	assert(find_nth_and_bit(&a, &b, 8, 1) == 7);
	assert(find_nth_and_andnot_bit(&a, &b, &c, 8, 0) == 7);
	assert(find_nth_bit(&a, 8, 2) >= 8);
	assert(find_nth_bit(&a, 8, ~0UL) == 8);
}

int main(void)
{
	/* Pure caller-owned storage: deliberately no stela_linux_enter. */
	patterns_and_tails();
	constant_word_helpers();
	printf("Linux bit search: direct exports, Boolean/nth/clump scans, tails and exact word allocations passed\n");
	return 0;
}
#endif
