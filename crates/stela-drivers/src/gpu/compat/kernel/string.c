// SPDX-License-Identifier: MIT
/* Linux's string functions, with lib/string.c's results. memcpy, memmove,
 * memset and memcmp come from the platform's compiler runtime, as the
 * compiler itself emits calls to them. */
#include <linux/string.h>

size_t strlen(const char *s)
{
	const char *end = s;
	while (*end)
		end++;
	return (size_t)(end - s);
}

size_t strnlen(const char *s, size_t count)
{
	size_t length = 0;
	while (length < count && s[length])
		length++;
	return length;
}

int strcmp(const char *cs, const char *ct)
{
	unsigned char a, b;
	do {
		a = (unsigned char)*cs++;
		b = (unsigned char)*ct++;
	} while (a == b && a);
	return a == b ? 0 : a < b ? -1 : 1;
}

char *strstr(const char *s1, const char *s2)
{
	size_t length = strlen(s2);
	for (; length; s1++) {
		if (!*s1)
			return NULL;
		if (!memcmp(s1, s2, length))
			break;
	}
	return (char *)s1;
}

char *strsep(char **s, const char *ct)
{
	char *token = *s;
	if (!token)
		return NULL;
	for (char *c = token; *c; c++) {
		for (const char *delimiter = ct; *delimiter; delimiter++) {
			if (*c == *delimiter) {
				*c = '\0';
				*s = c + 1;
				return token;
			}
		}
	}
	*s = NULL;
	return token;
}
