/*
 * The `stela-host` record stela.efi puts on the gate's DeviceTree node
 * (stela_loader::stela_gpu::encode_host), parsed in C without a library so
 * the kext and the host's tests (tests/host_record.c) run the same code.
 *
 * Version 1: the line "stela-host 1", then one line per entry, "s Key=text"
 * or "n Key=decimal". Keys are 1-40 ASCII letters and digits; text is at
 * most STELA_HOST_TEXT_BYTES printable bytes. A malformed line is skipped.
 */
#pragma once

#define STELA_HOST_PROPERTY "stela-host"
#define STELA_HOST_TEXT_BYTES 120
#define STELA_HOST_KEY_BYTES 40

/* One entry: its key, and its number or its text, neither NUL-terminated. */
typedef void (*stela_host_entry)(void *context, const char *key, unsigned long key_length, int is_number,
    unsigned long long number, const char *text, unsigned long text_length);

static inline int
stela_host_key_byte(char byte)
{
	return (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9');
}

/*
 * Calls `entry` for each well-formed entry of `record`, `length` bytes,
 * answering how many, or -1 when the record is not version 1.
 */
static inline int
stela_host_parse(const char *record, unsigned long length, stela_host_entry entry, void *context)
{
	static const char header[] = "stela-host 1\n";
	unsigned long at = 0;
	for (; header[at]; at++) {
		if (at >= length || record[at] != header[at]) {
			return -1;
		}
	}
	int count = 0;
	while (at < length) {
		unsigned long end = at;
		while (end < length && record[end] != '\n') {
			end++;
		}
		/* "t K=" at least, with a known type, a key, then '='. */
		unsigned long key = at + 2;
		unsigned long equals = key;
		while (equals < end && stela_host_key_byte(record[equals])) {
			equals++;
		}
		int well_formed = end - at >= 4 && (record[at] == 's' || record[at] == 'n') && record[at + 1] == ' ' &&
		    equals > key && equals - key <= STELA_HOST_KEY_BYTES && equals < end && record[equals] == '=';
		if (well_formed) {
			const char *value = record + equals + 1;
			unsigned long value_length = end - equals - 1;
			if (record[at] == 'n') {
				unsigned long long number = 0;
				int digits = value_length > 0 && value_length <= 20;
				for (unsigned long index = 0; digits && index < value_length; index++) {
					unsigned long long digit = (unsigned long long)(value[index] - '0');
					if (value[index] < '0' || value[index] > '9' ||
					    number > (18446744073709551615ULL - digit) / 10) {
						digits = 0;
					} else {
						number = number * 10 + digit;
					}
				}
				if (digits) {
					entry(context, record + key, equals - key, 1, number, 0, 0);
					count++;
				}
			} else {
				int printable = value_length <= STELA_HOST_TEXT_BYTES;
				for (unsigned long index = 0; printable && index < value_length; index++) {
					printable = value[index] >= ' ' && value[index] <= '~';
				}
				if (printable) {
					entry(context, record + key, equals - key, 0, 0, value, value_length);
					count++;
				}
			}
		}
		at = end + 1;
	}
	return count;
}
