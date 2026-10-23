/* SPDX-License-Identifier: MIT */
/* The C library headers Mesa's packing helpers include, for the native packet
 * encoders, which run without one. No assertion handler exists there: a
 * violated packer invariant stops execution rather than truncating a field.
 */
#undef assert
#ifdef NDEBUG
#define assert(condition) ((void)0)
#else
#define assert(condition) do { if (!(condition)) __builtin_trap(); } while (0)
#endif
