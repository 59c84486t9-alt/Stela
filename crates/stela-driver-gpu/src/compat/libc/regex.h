/* SPDX-License-Identifier: MIT */
/* The pinned LLVM Support library's POSIX regular expression engine. */
#ifndef STELA_LIBC_REGEX_H
#define STELA_LIBC_REGEX_H
#include <sys/cdefs.h>
#include <stddef.h>
#include "../../../../../third_party/llvm/llvm/lib/Support/regex_impl.h"
__BEGIN_DECLS
typedef llvm_regex_t regex_t;
typedef llvm_regmatch_t regmatch_t;
int regcomp(regex_t *regex, const char *pattern, int flags);
int regexec(const regex_t *regex, const char *text, size_t count, regmatch_t *matches, int flags);
void regfree(regex_t *regex);
size_t regerror(int code, const regex_t *regex, char *buffer, size_t size);
__END_DECLS
#endif
