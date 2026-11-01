// SPDX-License-Identifier: MIT
/* Linux's string-to-integer conversions, with lib/kstrtox.c's results: an
 * optional '+' or, for a signed result, '-', base 0 choosing 16 for "0x", 8 for "0" and else 10, an
 * optional "0x" for base 16, at least one digit, and at most one trailing
 * newline. -EINVAL for anything else, -ERANGE for a value that overflows. */
#include <linux/errno.h>
#include <linux/kstrtox.h>
#include <linux/limits.h>

static unsigned int digit(char c)
{
	if (c >= '0' && c <= '9')
		return (unsigned int)(c - '0');
	c |= 0x20;
	if (c >= 'a' && c <= 'z')
		return (unsigned int)(c - 'a') + 10;
	return 36;
}

static bool hex_prefix(const char *s)
{
	return s[0] == '0' && (s[1] | 0x20) == 'x' && digit(s[2]) < 16;
}

/* kstrtoull without its optional '+', which kstrtoll's '-' excludes. */
static int parse(const char *s, unsigned int base, unsigned long long *res)
{
	if (base == 0)
		base = hex_prefix(s) ? 16 : s[0] == '0' ? 8 : 10;
	if (base == 16 && hex_prefix(s))
		s += 2;
	if (base < 2 || base > 16 || digit(*s) >= base)
		return -EINVAL;
	unsigned long long value = 0;
	for (; digit(*s) < base; s++) {
		if (value > (ULLONG_MAX - digit(*s)) / base)
			return -ERANGE;
		value = value * base + digit(*s);
	}
	if (*s == '\n')
		s++;
	if (*s)
		return -EINVAL;
	*res = value;
	return 0;
}

int kstrtoull(const char *s, unsigned int base, unsigned long long *res)
{
	return parse(*s == '+' ? s + 1 : s, base, res);
}

int kstrtoll(const char *s, unsigned int base, long long *res)
{
	unsigned long long magnitude;
	int ret = s[0] == '-' ? parse(s + 1, base, &magnitude) : kstrtoull(s, base, &magnitude);
	if (ret)
		return ret;
	if (s[0] != '-') {
		if (magnitude > (unsigned long long)LLONG_MAX)
			return -ERANGE;
		*res = (long long)magnitude;
	} else {
		if (magnitude > (unsigned long long)LLONG_MAX + 1)
			return -ERANGE;
		*res = magnitude ? -(long long)(magnitude - 1) - 1 : 0;
	}
	return 0;
}

/* The digits of base at cp, stopping at the first other character. */
long simple_strtol(const char *cp, char **endp, unsigned int base)
{
	bool negative = *cp == '-';
	unsigned long value = 0;

	if (negative)
		cp++;
	if (!base)
		base = hex_prefix(cp) ? 16 : *cp == '0' ? 8 : 10;
	if (base == 16 && hex_prefix(cp))
		cp += 2;
	for (; digit(*cp) < base; cp++)
		value = value * base + digit(*cp);
	if (endp)
		*endp = (char *)cp;
	return negative ? -(long)value : (long)value;
}

int kstrtou16(const char *s, unsigned int base, u16 *res)
{
	unsigned long long value;
	int ret = kstrtoull(s, base, &value);
	if (ret)
		return ret;
	if (value > U16_MAX)
		return -ERANGE;
	*res = (u16)value;
	return 0;
}

#ifdef STELA_LINUX_KSTRTOX_TEST
#include <stela/test.h>

int main(void)
{
	long long value;
	unsigned long long unsigned_value;
	assert(!kstrtoll("-9223372036854775808", 10, &value) && value == LLONG_MIN);
	assert(!kstrtoll("9223372036854775807\n", 0, &value) && value == LLONG_MAX);
	assert(kstrtoll("9223372036854775808", 10, &value) == -ERANGE);
	assert(kstrtoll("-9223372036854775809", 10, &value) == -ERANGE);
	assert(!kstrtoll("-0x10", 0, &value) && value == -16);
	assert(!kstrtoll("+010", 0, &value) && value == 8);
	assert(!kstrtoll("-0", 10, &value) && value == 0);
	/* A sign is taken once: lib/kstrtox.c refuses "-+1" and "--1". */
	assert(kstrtoll("-+1", 10, &value) == -EINVAL);
	assert(kstrtoll("--1", 10, &value) == -EINVAL);
	assert(kstrtoll("-", 10, &value) == -EINVAL);
	assert(kstrtoull("-1", 10, &unsigned_value) == -EINVAL);
	assert(!kstrtoull("+0xff", 16, &unsigned_value) && unsigned_value == 0xff);
	printf("Linux integer parsing: signs, bases, bounds and trailing newline passed\n");
	return 0;
}
#endif
