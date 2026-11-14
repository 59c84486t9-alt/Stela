/*
 * Host tests of compression_policy.h, which the kext compiles unchanged.
 * xtask's `guest::app::tests::the_kext_c_code_passes_its_host_tests` builds
 * and runs this with the host's clang; it prints each failing check.
 */
#include <stdio.h>
#include <string.h>

#include "../compression_policy.h"

static int failures;

#define CHECK(condition)                                                       \
	do {                                                                   \
		if (!(condition)) {                                            \
			printf("%s:%d: %s\n", __FILE__, __LINE__, #condition); \
			failures++;                                            \
		}                                                              \
	} while (0)

static int
named(const char *bytes, int length)
{
	return stela_compression_key_named(bytes, length, STELA_COMPRESSION_KEY);
}

int
main(void)
{
	/* A binary list keeps the key after its string marker. */
	static const char binary[] = "bplist00\xd1\x01\x02_\x10\x1a"
				     "disable-buffer-compression\x09\x08\x0b";
	CHECK(named(binary, sizeof binary - 1));
	static const char xml[] = "<dict><key>disable-buffer-compression</key><false/></dict>";
	CHECK(named(xml, sizeof xml - 1));
	/* Other keys, a prefix and a cut file do not name it. */
	static const char other[] = "bplist00\xd1\x01\x02_\x10\x13"
				    "AppleInterfaceStyle";
	CHECK(!named(other, sizeof other - 1));
	static const char prefix[] = "disable-buffer-compressio";
	CHECK(!named(prefix, sizeof prefix - 1));
	CHECK(!named(xml, 20));
	CHECK(!named("", 0));
	CHECK(!named(NULL, 40));
	/* The key at the very end counts. */
	static const char tail[] = "xxdisable-buffer-compression";
	CHECK(named(tail, sizeof tail - 1));
	CHECK(!stela_compression_key_named(tail, sizeof tail - 1, ""));
	if (!failures) {
		printf("ok\n");
	}
	return failures != 0;
}
