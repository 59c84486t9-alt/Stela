/*
 * Host tests of app_policy.h, which the kext compiles unchanged. xtask's
 * `guest::app::tests::the_kext_policy_passes_its_host_tests` builds and
 * runs this with the host's clang; it prints each failing check.
 */
#include <stdio.h>
#include <string.h>

#include "../app_policy.h"

static int failures;

#define CHECK(condition)                                                                 \
	do {                                                                             \
		if (!(condition)) {                                                      \
			printf("%s:%d: %s\n", __FILE__, __LINE__, #condition);           \
			failures++;                                                      \
		}                                                                        \
	} while (0)

static enum stela_app_action
decide(int present, int readable, const char *identifier, const char *version, int files_match)
{
	struct stela_app_installed installed = {present, readable, identifier, version, files_match};
	return stela_app_decide(&installed, "org.stela.Stela", "0.2.0");
}

static void
versions(void)
{
	CHECK(stela_app_compare_versions("0.1.0", "0.1.0") == 0);
	CHECK(stela_app_compare_versions("0.1", "0.1.0") == 0);
	CHECK(stela_app_compare_versions("0.1.0", "0.2.0") == -1);
	CHECK(stela_app_compare_versions("1.0", "0.99.99") == 1);
	CHECK(stela_app_compare_versions("0.10.0", "0.9.0") == 1);
	CHECK(stela_app_compare_versions("1.2.3.4", "1.2.3.5") == -1);
	CHECK(stela_app_compare_versions("1.2.3.4.5", "1") == 2);
	CHECK(stela_app_compare_versions("1..2", "1") == 2);
	CHECK(stela_app_compare_versions("1.", "1") == 2);
	CHECK(stela_app_compare_versions("", "1") == 2);
	CHECK(stela_app_compare_versions("1", "1.0-beta") == 2);
	CHECK(stela_app_compare_versions("1234567890", "1") == 2);
	CHECK(stela_app_compare_versions("999999999", "1") == 1);
}

static void
decisions(void)
{
	CHECK(decide(0, 0, "", "", 0) == STELA_APP_INSTALL);
	CHECK(decide(1, 0, "", "", 0) == STELA_APP_KEEP_FOREIGN);
	CHECK(decide(1, 1, "com.example.Other", "0.2.0", 0) == STELA_APP_KEEP_FOREIGN);
	CHECK(decide(1, 1, "org.stela.Stela", "0.2.0", 1) == STELA_APP_CURRENT);
	/* The same version with other bytes: the running build's replaces it. */
	CHECK(decide(1, 1, "org.stela.Stela", "0.2.0", 0) == STELA_APP_INSTALL);
	CHECK(decide(1, 1, "org.stela.Stela", "0.1.9", 0) == STELA_APP_INSTALL);
	CHECK(decide(1, 1, "org.stela.Stela", "0.3", 0) == STELA_APP_KEEP_NEWER);
	CHECK(decide(1, 1, "org.stela.Stela", "0.3", 1) == STELA_APP_KEEP_NEWER);
	CHECK(decide(1, 1, "org.stela.Stela", "development", 0) == STELA_APP_KEEP_FOREIGN);
}

static void
plists(void)
{
	static const char info[] =
	    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n"
	    "    <key>CFBundleIdentifier</key><string>org.stela.Stela</string>\n"
	    "    <key>CFBundleShortVersionString</key>\n\t<string>0.1.0</string>\n"
	    "    <key>Escaped</key><string>a&amp;b</string>\n"
	    "    <key>Flag</key><true/>\n"
	    "    <key>Long</key><string>0123456789abcdef</string>\n"
	    "    <key>Open</key><string>unterminated\n";
	unsigned long length = sizeof info - 1;
	char value[16];
	CHECK(stela_app_plist_string(info, length, "CFBundleIdentifier", value, sizeof value));
	CHECK(!strcmp(value, "org.stela.Stela"));
	CHECK(stela_app_plist_string(info, length, "CFBundleShortVersionString", value, sizeof value));
	CHECK(!strcmp(value, "0.1.0"));
	CHECK(!stela_app_plist_string(info, length, "CFBundle", value, sizeof value) && !value[0]);
	CHECK(!stela_app_plist_string(info, length, "Escaped", value, sizeof value) && !value[0]);
	CHECK(!stela_app_plist_string(info, length, "Flag", value, sizeof value) && !value[0]);
	CHECK(!stela_app_plist_string(info, length, "Long", value, sizeof value) && !value[0]);
	CHECK(!stela_app_plist_string(info, length, "Open", value, sizeof value) && !value[0]);
	CHECK(!stela_app_plist_string(info, length, "Missing", value, sizeof value));
	/* The length bounds the search: a key past it is not found. */
	CHECK(!stela_app_plist_string(info, 60, "CFBundleIdentifier", value, sizeof value));
}

int
main(void)
{
	versions();
	decisions();
	plists();
	printf("%s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
