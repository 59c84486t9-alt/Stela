// SPDX-License-Identifier: GPL-2.0-only
/* Owned common string helpers following Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 lib/string_helpers.c. Its
 * original GPL notices remain with that source; lib/string.c itself is
 * compiled unchanged. */
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/string.h>

/* skip_spaces is an exact bounded projection from the pinned original
 * lib/string_helpers.c, Copyright 31 August 2008 James Bottomley;
 * Copyright (C) 2013, Intel Corporation. No dynamic module export table. */
/**
 * skip_spaces - Removes leading whitespace from @str.
 * @str: The string to be stripped.
 *
 * Returns a pointer to the first non-whitespace character in @str.
 */
char *skip_spaces(const char *str)
{
	while (isspace(*str))
		++str;
	return (char *)str;
}


char *strreplace(char *string, char old, char replacement)
{
	char *cursor = string;
	while (*cursor) {
		if (*cursor == old)
			*cursor = replacement;
		cursor++;
	}
	return string;
}

/* As strcmp, except that one trailing newline on either string is ignored. */
bool sysfs_streq(const char *s1, const char *s2)
{
	while (*s1 && *s1 == *s2) {
		s1++;
		s2++;
	}
	if (*s1 == *s2)
		return true;
	if (!*s1 && *s2 == '\n' && !s2[1])
		return true;
	return *s1 == '\n' && !s1[1] && !*s2;
}

int match_string(const char *const *array, size_t n, const char *string)
{
	for (size_t index = 0; index < n; index++) {
		if (!array[index])
			break;
		if (!strcmp(array[index], string))
			return (int)index;
	}
	return -EINVAL;
}

/* Original __sysfs_match_string from lib/string_helpers.c uses sysfs_streq
 * and stops at either the bound or the first NULL entry. */
int __sysfs_match_string(const char *const *array, size_t n, const char *string)
{
	for (size_t index = 0; index < n; index++) {
		if (!array[index])
			break;
		if (sysfs_streq(array[index], string))
			return (int)index;
	}
	return -EINVAL;
}

void memcpy_and_pad(void *dest, size_t dest_len, const void *src, size_t count, int pad)
{
	if (dest_len > count) {
		memcpy(dest, src, count);
		memset((char *)dest + count, pad, dest_len - count);
	} else {
		memcpy(dest, src, dest_len);
	}
}

#ifdef STELA_LINUX_STRING_HELPERS_TEST
#include <stela/test.h>

/* The expected set is transcribed from pinned lib/ctype.c, not derived
 * from isspace here: bytes 9..13, 32 and 160 carry its _S bit. This includes
 * Linux's single-byte NBSP, without host locale or Unicode decoding. */
static void leading_whitespace(void)
{
	char *(*volatile skip)(const char *) = skip_spaces;
	for (unsigned int byte = 0; byte < 256; byte++) {
		struct { u8 before; char text[3]; u8 after; } guarded = {
			.before = 0x61, .text = {(char)byte, 'X', 0}, .after = 0xc8,
		};
		char saved[sizeof(guarded.text)];
		memcpy(saved, guarded.text, sizeof(saved));
		bool whitespace = (byte >= 9 && byte <= 13) || byte == 32 || byte == 160;
		assert(skip(guarded.text) == guarded.text + whitespace);
		assert(guarded.before == 0x61 && guarded.after == 0xc8);
		assert(!memcmp(saved, guarded.text, sizeof(saved)));
	}
	static const char mixed[] = {'\t', '\n', '\v', '\f', '\r', ' ', (char)0xa0, '!', 0};
	assert(skip(mixed) == mixed + 7);
	char only[] = {' ', (char)0xa0, '\t', '\n', '\v', '\f', '\r', 0};
	char only_saved[sizeof(only)];
	memcpy(only_saved, only, sizeof(only));
	assert(skip(only) == only + sizeof(only) - 1);
	assert(!memcmp(only, only_saved, sizeof(only)));
	static const char empty[] = "";
	assert(skip(empty) == empty);
	static const char embedded[] = {' ', 0, '\t', 'X', 0};
	assert(skip(embedded) == embedded + 1);
	static const char utf8_nbsp[] = {(char)0xc2, (char)0xa0, 'X', 0};
	assert(skip(utf8_nbsp) == utf8_nbsp);
}

int main(void)
{
	leading_whitespace();
	const char *const choices[] = {"first", "second", NULL, "hidden"};
	assert(__sysfs_match_string(choices, ARRAY_SIZE(choices), "second\n") == 1);
	assert(__sysfs_match_string(choices, 1, "second") == -EINVAL);
	assert(__sysfs_match_string(choices, (size_t)-1, "hidden") == -EINVAL);
	assert(__sysfs_match_string(choices, ARRAY_SIZE(choices), "first\n\n") == -EINVAL);
	/* Exercise lib/string.c's implementations, not compiler-folded libc
	 * calls. */
	int (*volatile compare)(const char *, const char *, size_t) = strncmp;
	char *(*volatile find)(const char *, int) = strchr;
	char *(*volatile bounded_find)(const char *, size_t, int) = strnchr;
	const char high[] = {(char)0xff, 0};
	const char low[] = {(char)0x7f, 0};
	assert(compare(high, low, 1) == 1 && compare(low, high, 1) == -1);
	assert(!compare(NULL, NULL, 0));
	assert(!compare("a", "ab", 1) && compare("a", "ab", 2) == -1);
	assert(compare("b", "a", 1) == 1);
	const char text[] = "a/b/a";
	assert(find(text, 'a') == text && find(text, 0) == text + sizeof(text) - 1);
	assert(find(text, '/' + 256) == text + 1 && !find(text, 'z'));
	assert(!bounded_find(NULL, 0, '/'));
	assert(!bounded_find(text, 1, '/') && bounded_find(text, 2, '/') == text + 1);
	assert(!bounded_find(text, sizeof(text) - 1, 0));
	assert(bounded_find(text, sizeof(text), 0) == text + sizeof(text) - 1);
	char writable[] = "a/b/c";
	assert(strreplace(writable, '/', '!') == writable);
	assert(!strcmp(writable, "a!b!c"));
	assert(strreplace(writable, 'z', '!') == writable && !strcmp(writable, "a!b!c"));
	char empty[] = "";
	assert(strreplace(empty, 'x', 'y') == empty && !empty[0]);
	printf("Linux string helpers: byte order, bounds, search and replacement passed\n");
	return 0;
}
#endif
