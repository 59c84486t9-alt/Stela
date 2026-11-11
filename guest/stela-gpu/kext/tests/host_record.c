/*
 * Host tests of host_record.h, which the kext compiles unchanged. With a
 * file argument it prints that record's entries, one "key|n|number" or
 * "key|s|text" line each, which xtask compares with stela-loader's encoder
 * (`guest::tests::the_kext_reads_the_records_stela_efi_writes`).
 */
#include <stdio.h>
#include <string.h>

#include "../host_record.h"

static void
print(void *context, const char *key, unsigned long key_length, int is_number, unsigned long long number,
    const char *text, unsigned long text_length)
{
	(void)context;
	if (is_number) {
		printf("%.*s|n|%llu\n", (int)key_length, key, number);
	} else {
		printf("%.*s|s|%.*s\n", (int)key_length, key, (int)text_length, text);
	}
}

static int failures;

#define CHECK(condition)                                                       \
	do {                                                                   \
		if (!(condition)) {                                            \
			printf("%s:%d: %s\n", __FILE__, __LINE__, #condition); \
			failures++;                                            \
		}                                                              \
	} while (0)

static void
count(void *context, const char *key, unsigned long key_length, int is_number, unsigned long long number,
    const char *text, unsigned long text_length)
{
	(void)key;
	(void)key_length;
	(void)is_number;
	(void)number;
	(void)text;
	(void)text_length;
	(*(int *)context)++;
}

static int
parse(const char *record)
{
	int seen = 0;
	int answered = stela_host_parse(record, strlen(record), count, &seen);
	CHECK(answered < 0 || answered == seen);
	return answered;
}

int
main(int argc, char **argv)
{
	if (argc == 2) {
		static char record[65536];
		FILE *file = fopen(argv[1], "rb");
		if (!file) {
			return 2;
		}
		size_t length = fread(record, 1, sizeof record, file);
		fclose(file);
		return stela_host_parse(record, length, print, 0) < 0;
	}
	CHECK(parse("stela-host 2\nn A=1\n") == -1);
	CHECK(parse("stela-host 1") == -1);
	CHECK(parse("stela-host 1\n") == 0);
	CHECK(parse("stela-host 1\nn A=1\ns B=two words\n") == 2);
	/* No newline after the last entry is still an entry. */
	CHECK(parse("stela-host 1\nn A=1") == 1);
	/* Malformed lines are skipped: type, key, '=', digits, overflow. */
	CHECK(parse("stela-host 1\nx A=1\nn =1\nnA=1\nn A 1\nn A=1x\nn A=18446744073709551616\nn A=\n") == 0);
	CHECK(parse("stela-host 1\nn A=18446744073709551615\ns E=\n") == 2);
	CHECK(parse("stela-host 1\ns Bad-key=1\ns K=tab\there\n") == 0);
	CHECK(parse("stela-host 1\ns K0123456789012345678901234567890123456789=x\n") == 0);
	printf("%s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
