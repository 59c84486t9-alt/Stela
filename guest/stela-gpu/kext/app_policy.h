/*
 * Stela.app delivery's decisions, in C without a library, so the kext
 * (app_delivery.cpp) and the host's tests (tests/app_policy.c) run the same
 * code. `cargo xtask guest` writes the job whose script reads the report
 * named here; its tests check that both spell these strings alike.
 */
#pragma once

/* The registry property on the StelaGPU service holding the kext's report. */
#define STELA_APP_PROPERTY "StelaApp"
/* The reports. Only STELA_APP_STAGED lets the install job replace anything. */
#define STELA_APP_STAGED "staged"
#define STELA_APP_CURRENT_REPORT "current"
#define STELA_APP_NEWER_REPORT "kept-newer"
#define STELA_APP_FOREIGN_REPORT "kept-foreign"
#define STELA_APP_FAILED_REPORT "failed"
#define STELA_APP_ABSENT_REPORT "not-in-build"

enum stela_app_action {
	/* The installed app holds every payload file's bytes. */
	STELA_APP_CURRENT,
	/* Stage the payload for the install job. */
	STELA_APP_INSTALL,
	/* The installed Stela.app is a newer version: never downgraded. */
	STELA_APP_KEEP_NEWER,
	/* What /Applications/Stela.app holds is not a Stela.app this can compare. */
	STELA_APP_KEEP_FOREIGN,
};

/* What the kext found at /Applications/Stela.app. */
struct stela_app_installed {
	/* Something exists at the path. */
	int present;
	/* It is a directory, not a link, whose Info.plist names both strings. */
	int readable;
	const char *identifier;
	const char *version;
	/* Every payload file is present with the payload's bytes. */
	int files_match;
};

static inline int
stela_app_equal(const char *a, const char *b)
{
	while (*a && *a == *b) {
		a++;
		b++;
	}
	return *a == *b;
}

/*
 * Compares dotted decimal versions of one to four components of one to nine
 * digits each, a missing component counting 0: -1, 0 or 1 as `a` is older,
 * the same or newer than `b`; 2 when either is not such a version.
 */
static inline int
stela_app_compare_versions(const char *a, const char *b)
{
	unsigned long parts[2][4] = {{0, 0, 0, 0}, {0, 0, 0, 0}};
	const char *versions[2] = {a, b};
	for (int which = 0; which < 2; which++) {
		const char *at = versions[which];
		int component = 0;
		for (;;) {
			int digits = 0;
			while (*at >= '0' && *at <= '9') {
				if (++digits > 9) {
					return 2;
				}
				parts[which][component] = parts[which][component] * 10 + (unsigned long)(*at - '0');
				at++;
			}
			if (digits == 0) {
				return 2;
			}
			if (*at == 0) {
				break;
			}
			if (*at != '.' || ++component == 4) {
				return 2;
			}
			at++;
		}
	}
	for (int component = 0; component < 4; component++) {
		if (parts[0][component] != parts[1][component]) {
			return parts[0][component] < parts[1][component] ? -1 : 1;
		}
	}
	return 0;
}

/*
 * What to do about the installed app, given the payload's identifier and
 * version: install when absent or an older or same version that differs,
 * keep a newer one, and leave alone whatever is not comparable.
 */
static inline enum stela_app_action
stela_app_decide(const struct stela_app_installed *installed, const char *identifier, const char *version)
{
	if (!installed->present) {
		return STELA_APP_INSTALL;
	}
	if (!installed->readable || !stela_app_equal(installed->identifier, identifier)) {
		return STELA_APP_KEEP_FOREIGN;
	}
	int order = stela_app_compare_versions(installed->version, version);
	if (order == 2) {
		return STELA_APP_KEEP_FOREIGN;
	}
	if (order > 0) {
		return STELA_APP_KEEP_NEWER;
	}
	return installed->files_match ? STELA_APP_CURRENT : STELA_APP_INSTALL;
}

static inline int
stela_app_starts(const char *text, unsigned long length, unsigned long at, const char *prefix)
{
	for (; *prefix; prefix++, at++) {
		if (at >= length || text[at] != *prefix) {
			return 0;
		}
	}
	return 1;
}

/*
 * Copies the <string> following the first <key>`key`</key> of XML property
 * list text `text` of `length` bytes into `value` of `capacity` bytes,
 * NUL-terminated, answering 1. Answers 0, with `value` empty, when there is
 * no such string, it holds markup or an entity, or it does not fit.
 */
static inline int
stela_app_plist_string(const char *text, unsigned long length, const char *key, char *value, unsigned long capacity)
{
	if (capacity == 0) {
		return 0;
	}
	value[0] = 0;
	for (unsigned long at = 0; at < length; at++) {
		if (!stela_app_starts(text, length, at, "<key>")) {
			continue;
		}
		unsigned long name = at + 5;
		if (!stela_app_starts(text, length, name, key)) {
			continue;
		}
		unsigned long end = name;
		while (key[end - name]) {
			end++;
		}
		if (!stela_app_starts(text, length, end, "</key>")) {
			continue;
		}
		end += 6;
		while (end < length && (text[end] == ' ' || text[end] == '\t' || text[end] == '\n' || text[end] == '\r')) {
			end++;
		}
		if (!stela_app_starts(text, length, end, "<string>")) {
			return 0;
		}
		end += 8;
		unsigned long copied = 0;
		for (; end < length && text[end] != '<'; end++) {
			if (text[end] == '&' || text[end] == 0 || copied + 1 >= capacity) {
				value[0] = 0;
				return 0;
			}
			value[copied++] = text[end];
		}
		value[copied] = 0;
		if (!stela_app_starts(text, length, end, "</string>")) {
			value[0] = 0;
			return 0;
		}
		return 1;
	}
	return 0;
}
