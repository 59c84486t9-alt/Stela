/* SPDX-License-Identifier: MIT */
/* What libc++'s `basic_string<wchar_t>` reaches. Numbers are ASCII in the C
 * locale, so these narrow their text and use the narrow functions. */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

/* Longer than any number's text. */
#define NUMBER_BYTES 512

wchar_t *wmemchr(const wchar_t *text, wchar_t character, size_t size)
{
	for (; size; text++, size--) {
		if (*text == character)
			return (wchar_t *)text;
	}
	return NULL;
}

int wmemcmp(const wchar_t *left, const wchar_t *right, size_t size)
{
	for (; size; left++, right++, size--) {
		if (*left != *right)
			return *left < *right ? -1 : 1;
	}
	return 0;
}

static void narrow(const wchar_t *text, char *out)
{
	size_t at = 0;
	for (; at < NUMBER_BYTES - 1 && text[at] > 0 && text[at] < 0x80; at++)
		out[at] = (char)text[at];
	out[at] = 0;
}

#define PARSE(type, name, parse, ...)                                                             \
	type name(const wchar_t *text, wchar_t **end __VA_OPT__(, ) __VA_ARGS__)                  \
	{                                                                                         \
		char number[NUMBER_BYTES];                                                        \
		char *stop;                                                                       \
		narrow(text, number);                                                             \
		type value = parse;                                                               \
		if (end)                                                                          \
			*end = (wchar_t *)text + (stop - number);                                 \
		return value;                                                                     \
	}

PARSE(long, wcstol, strtol(number, &stop, base), int base)
PARSE(long long, wcstoll, strtoll(number, &stop, base), int base)
PARSE(unsigned long, wcstoul, strtoul(number, &stop, base), int base)
PARSE(unsigned long long, wcstoull, strtoull(number, &stop, base), int base)
PARSE(float, wcstof, strtof(number, &stop))
PARSE(double, wcstod, strtod(number, &stop))
PARSE(long double, wcstold, strtold(number, &stop))

int vswprintf(wchar_t *text, size_t size, const wchar_t *format, va_list list)
{
	char narrow_format[NUMBER_BYTES];
	narrow(format, narrow_format);
	char *bytes = malloc(size + 1);
	if (!bytes) {
		errno = ENOMEM;
		return -1;
	}
	int length = vsnprintf(bytes, size + 1, narrow_format, list);
	if (length < 0 || (size_t)length >= size) {
		free(bytes);
		errno = EOVERFLOW;
		return -1;
	}
	for (int at = 0; at <= length; at++)
		text[at] = (unsigned char)bytes[at];
	free(bytes);
	return length;
}

int swprintf(wchar_t *text, size_t size, const wchar_t *format, ...)
{
	va_list list;
	va_start(list, format);
	int length = vswprintf(text, size, format, list);
	va_end(list);
	return length;
}
