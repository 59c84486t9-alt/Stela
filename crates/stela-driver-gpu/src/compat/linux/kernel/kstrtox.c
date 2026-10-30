// SPDX-License-Identifier: MIT
/* Linux's string-to-integer conversions, with lib/kstrtox.c's results: an
 * optional '+', base 0 choosing 16 for "0x", 8 for "0" and else 10, an
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

int kstrtoull(const char *s, unsigned int base, unsigned long long *res)
{
	if (*s == '+')
		s++;
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
