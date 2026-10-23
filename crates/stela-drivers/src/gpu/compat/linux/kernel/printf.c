// SPDX-License-Identifier: GPL-2.0
/* The sprintf entry points' contract from Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 lib/vsprintf.c, originally
 * Copyright (C) 1991, 1992 Linus Torvalds and contributors. Delegates to the
 * existing canonical formatter; its MIT source is unchanged. */
#include <linux/limits.h>
#include <linux/sprintf.h>

int vsprintf(char *buffer, const char *format, va_list arguments)
{
	return vsnprintf(buffer, INT_MAX, format, arguments);
}

int sprintf(char *buffer, const char *format, ...)
{
	va_list arguments;
	va_start(arguments, format);
	int length = vsprintf(buffer, format, arguments);
	va_end(arguments);
	return length;
}

#ifdef STELA_LINUX_PRINTF_TEST
#include <linux/string.h>
#include <stela/linux.h>
#include <stela/test.h>

static __printf(2, 3) int through_va_list(char *buffer, const char *format, ...)
{
	va_list arguments;
	va_start(arguments, format);
	int length = vsprintf(buffer, format, arguments);
	va_end(arguments);
	return length;
}

int main(void)
{
	stela_linux_enter(&stela_linux_bare);
	int (*volatile render)(char *, const char *, ...) = sprintf;
	char output[80];
	memset(output, 0x75, sizeof(output));
	const char expected[] = "DEVPATH_OLD=/root/7";
	assert(render(output, "DEVPATH_OLD=%s/%u", "/root", 7U) == (int)sizeof(expected) - 1);
	assert(!strcmp(output, expected) && output[sizeof(expected)] == 0x75);
	assert(through_va_list(output, "%i:%#08x:%llu", -17, 1U, 18446744073709551615ULL) ==
	       (int)sizeof("-17:0x000001:18446744073709551615") - 1);
	assert(!strcmp(output, "-17:0x000001:18446744073709551615"));
	assert(render(output, "%s", "") == 0 && !output[0]);
	stela_linux_exit();
	printf("Linux sprintf: direct and va_list text, length and termination passed\n");
	return 0;
}
#endif
