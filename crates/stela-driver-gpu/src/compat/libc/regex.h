/* SPDX-License-Identifier: MIT */
/* Mesa matches drirc entries against the application's name. Stela's Mesa has
 * no application to recognize, so a pattern compiles and matches nothing. */
#ifndef STELA_LIBC_REGEX_H
#define STELA_LIBC_REGEX_H
#include <sys/cdefs.h>
#include <stddef.h>
__BEGIN_DECLS
typedef struct {
	int unused;
} regex_t;
typedef struct {
	long rm_so, rm_eo;
} regmatch_t;
#define REG_EXTENDED 1
#define REG_NOSUB 4
#define REG_NOMATCH 1
int regcomp(regex_t *regex, const char *pattern, int flags);
int regexec(const regex_t *regex, const char *text, size_t count, regmatch_t *matches, int flags);
void regfree(regex_t *regex);
__END_DECLS
#endif
