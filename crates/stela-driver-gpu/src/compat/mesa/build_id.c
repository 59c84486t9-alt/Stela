// SPDX-License-Identifier: MIT
/* Mesa finds its build ID in its own ELF notes. It uses them to key caches
 * across driver builds; there is no ELF here and the shader cache is out, so
 * one note serves. */
#include <string.h>
#include "util/build_id.h"

struct build_id_note {
	uint8_t data[BUILD_ID_EXPECTED_HASH_LENGTH];
};

const struct build_id_note *build_id_find_nhdr_for_addr(const void *addr)
{
	static const struct build_id_note note = {"Stela statically"};
	(void)addr;
	return &note;
}

unsigned build_id_length(const struct build_id_note *note)
{
	return sizeof(note->data);
}

const uint8_t *build_id_data(const struct build_id_note *note)
{
	return note->data;
}

void copy_build_id_to_sha1(uint8_t sha1[BLAKE3_KEY_LEN], const struct build_id_note *note)
{
	memset(sha1, 0, BLAKE3_KEY_LEN);
	memcpy(sha1, note->data, sizeof(note->data));
}

void _mesa_sha1_format(char *buf, const unsigned char *sha1)
{
	static const char hex[] = "0123456789abcdef";
	for (int at = 0; at < 20; at++) {
		buf[at * 2] = hex[sha1[at] >> 4];
		buf[at * 2 + 1] = hex[sha1[at] & 0xf];
	}
	buf[40] = 0;
}
