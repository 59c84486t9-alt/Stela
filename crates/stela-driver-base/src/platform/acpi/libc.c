/* SPDX-License-Identifier: MIT */
/* Freestanding, private libc names; these never call the host C runtime. */
#include "acpi/acpi.h"
void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = dst; const unsigned char *s = src;
    for (size_t i = 0; i < n; ++i) d[i] = s[i];
    return dst;
}
void *memmove(void *dst, const void *src, size_t n) {
    unsigned char *d = dst; const unsigned char *s = src;
    if ((acpi_uintptr_t)d < (acpi_uintptr_t)s) return memcpy(dst, src, n);
    while (n) { --n; d[n] = s[n]; }
    return dst;
}
void *memset(void *dst, int c, size_t n) {
    unsigned char *d = dst; for (size_t i = 0; i < n; ++i) d[i] = (unsigned char)c;
    return dst;
}
int memcmp(const void *left, const void *right, size_t n) {
    const unsigned char *a = left, *b = right;
    for (size_t i = 0; i < n; ++i) if (a[i] != b[i]) return (int)a[i] - (int)b[i];
    return 0;
}
size_t strlen(const char *s) { size_t n = 0; while (s[n]) ++n; return n; }
size_t strnlen(const char *s, size_t max) { size_t n = 0; while (n < max && s[n]) ++n; return n; }
char *strcpy(char *d, const char *s) { size_t i = 0; do { d[i] = s[i]; } while (s[i++]); return d; }
char *strncpy(char *d, const char *s, size_t n) {
    size_t i = 0; for (; i < n && s[i]; ++i) d[i] = s[i]; for (; i < n; ++i) d[i] = 0; return d;
}
char *strcat(char *d, const char *s) { strcpy(d + strlen(d), s); return d; }
char *strncat(char *d, const char *s, size_t n) {
    size_t end = strlen(d), i = 0; while (i < n && s[i]) { d[end+i] = s[i]; ++i; } d[end+i] = 0; return d;
}
int strcmp(const char *a, const char *b) { while (*a && *a == *b) { ++a; ++b; } return (unsigned char)*a - (unsigned char)*b; }
int strncmp(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; ++i) { int delta = (unsigned char)a[i] - (unsigned char)b[i]; if (delta || !a[i]) return delta; } return 0;
}
char *strchr(const char *s, int c) { do { if (*s == (char)c) return (char *)s; } while (*s++); return 0; }
char *strrchr(const char *s, int c) { const char *found = 0; do { if (*s == (char)c) found = s; } while (*s++); return (char *)found; }
char *strstr(const char *s, const char *needle) { size_t n = strlen(needle); do { if (!strncmp(s, needle, n)) return (char *)s; } while (*s++); return 0; }
unsigned char stela_acpi_global_acquire(volatile unsigned int *lock) {
    unsigned int old = __atomic_load_n(lock, __ATOMIC_RELAXED), next;
    do { next = (old & ~1u) | 2u; if (old & 2u) next |= 1u; }
    while (!__atomic_compare_exchange_n(lock, &old, next, 0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED));
    return (next & 1u) == 0;
}
unsigned char stela_acpi_global_release(volatile unsigned int *lock) {
    unsigned int old = __atomic_load_n(lock, __ATOMIC_RELAXED), next;
    do { next = old & ~3u; }
    while (!__atomic_compare_exchange_n(lock, &old, next, 0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED));
    return (old & 1u) != 0;
}
