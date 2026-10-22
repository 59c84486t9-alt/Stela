/* SPDX-License-Identifier: MIT */
#ifndef STELA_UNSUPPORTED_H
#define STELA_UNSUPPORTED_H

/* Define a function that Linux declares and compiled Linux code references
 * but that Stela does not provide, because no Stela entry point reaches it.
 * Reaching it anyway stops at a trap instead of continuing with an invented
 * answer. The parameter list names types only; each use says why the function
 * is unreached. */
#define STELA_UNSUPPORTED(ret, name, ...) \
	_Pragma("clang diagnostic push") \
	_Pragma("clang diagnostic ignored \"-Wc23-extensions\"") \
	ret name(__VA_ARGS__) { __builtin_trap(); } \
	_Pragma("clang diagnostic pop")

/* Define an object that only unreached code uses. It holds no data. */
#define STELA_UNSUPPORTED_OBJECT(type, name) type name = {0}

#endif
