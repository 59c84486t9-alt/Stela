/* SPDX-License-Identifier: MIT */
#ifndef STELA_UNSUPPORTED_H
#define STELA_UNSUPPORTED_H

/* Define a service that an unchanged Linux source references but Stela does
 * not provide yet. Reaching it stops at a trap instead of continuing with an
 * invented answer. The parameter list names types only.
 */
#define STELA_UNSUPPORTED_DEFINE(qualifiers, ret, name, ...) \
	_Pragma("clang diagnostic push") \
	_Pragma("clang diagnostic ignored \"-Wc23-extensions\"") \
	qualifiers ret name(__VA_ARGS__) { __builtin_trap(); } \
	_Pragma("clang diagnostic pop")
/* For the shadows' static service declarations. */
#define STELA_UNSUPPORTED(ret, name, ...) STELA_UNSUPPORTED_DEFINE(static, ret, name, __VA_ARGS__)
/* For services that Linux's own headers declare with external linkage. */
#define STELA_UNSUPPORTED_EXTERN(ret, name, ...) STELA_UNSUPPORTED_DEFINE(, ret, name, __VA_ARGS__)

#endif
