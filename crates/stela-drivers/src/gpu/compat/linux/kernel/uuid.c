// SPDX-License-Identifier: GPL-2.0
/* Owned UUID syntax validation following Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 lib/uuid.c.
 * No random generation, entropy, UUID parser or namespace service is supplied. */
#include <linux/uuid.h>

bool uuid_is_valid(const char *uuid)
{
	/* The pinned API validates a 36-byte prefix, not its trailing grammar. */
	for (size_t i = 0; i < UUID_STRING_LEN; i++) {
		char c = uuid[i];
		if (i == 8 || i == 13 || i == 18 || i == 23) {
			if (c != '-')
				return false;
		} else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
			     (c >= 'A' && c <= 'F'))) {
			return false;
		}
	}
	return true;
}

#ifdef STELA_LINUX_UUID_TEST
#include <linux/string.h>
#include <stela/test.h>

int main(void)
{
	char uuid[] = "01234567-89ab-cdef-ABCD-0123456789ef";
	assert(uuid_is_valid(uuid));
	assert(uuid_is_valid("01234567-89ab-cdef-ABCD-0123456789ef extra"));
	assert(!uuid_is_valid("") && !uuid_is_valid("01234567-89ab"));
	for (size_t i = 0; i < UUID_STRING_LEN; i++) {
		char saved = uuid[i];
		uuid[i] = saved == '-' ? '_' : 'g';
		assert(!uuid_is_valid(uuid));
		uuid[i] = 0;
		assert(!uuid_is_valid(uuid));
		uuid[i] = (char)0xff;
		assert(!uuid_is_valid(uuid));
		uuid[i] = saved;
	}
	assert(uuid_is_valid(uuid) && strlen(uuid) == UUID_STRING_LEN);
	printf("Linux UUID syntax: prefix, hex/dash positions and early termination passed\n");
	return 0;
}
#endif
