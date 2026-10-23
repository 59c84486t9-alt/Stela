/* SPDX-License-Identifier: MIT */
#ifndef STELA_ACPI_ENVIRONMENT
#define STELA_ACPI_ENVIRONMENT
#include <stddef.h>
#include <stdarg.h>
#define ACPI_MACHINE_WIDTH 64
#define COMPILER_DEPENDENT_INT64 long long
#define COMPILER_DEPENDENT_UINT64 unsigned long long
#define ACPI_USE_SYSTEM_CLIBRARY
#define ACPI_MISALIGNMENT_NOT_SUPPORTED /* Portable byte-copy branch: no C alignment UB. */
#define ACPI_USE_LOCAL_CACHE
#define ACPI_USE_DO_WHILE_0
#define ACPI_STRUCT_INIT(field, value) .field = value
#define ACPI_OFFSET(type, field) __builtin_offsetof(type, field)
#define acpi_uintptr_t __UINTPTR_TYPE__
#define __init
#define __iomem

/* The firmware Global Lock must retain real atomic effects, including its
 * pending bit. The bridge implements the ACPI FACS lock algorithm. */
unsigned char stela_acpi_global_acquire(volatile unsigned int *lock);
unsigned char stela_acpi_global_release(volatile unsigned int *lock);
#define ACPI_ACQUIRE_GLOBAL_LOCK(facs, acquired) \
    ((acquired) = stela_acpi_global_acquire(&(facs)->global_lock))
#define ACPI_RELEASE_GLOBAL_LOCK(facs, pending) \
    ((pending) = stela_acpi_global_release(&(facs)->global_lock))
void stela_acpi_flush_cpu_cache(void);
#define ACPI_FLUSH_CPU_CACHE() stela_acpi_flush_cpu_cache()

#define memcpy stela_acpi_memcpy
#define memmove stela_acpi_memmove
#define memset stela_acpi_memset
#define memcmp stela_acpi_memcmp
#define strlen stela_acpi_strlen
#define strnlen stela_acpi_strnlen
#define strcpy stela_acpi_strcpy
#define strncpy stela_acpi_strncpy
#define strcat stela_acpi_strcat
#define strncat stela_acpi_strncat
#define strcmp stela_acpi_strcmp
#define strncmp stela_acpi_strncmp
#define strchr stela_acpi_strchr
#define strrchr stela_acpi_strrchr
#define strstr stela_acpi_strstr
#define strtoul stela_acpi_strtoul
#define snprintf stela_acpi_snprintf
#define vsnprintf stela_acpi_vsnprintf
#define sprintf stela_acpi_sprintf
void *memcpy(void *, const void *, size_t);
void *memmove(void *, const void *, size_t);
void *memset(void *, int, size_t);
int memcmp(const void *, const void *, size_t);
size_t strlen(const char *);
size_t strnlen(const char *, size_t);
char *strcpy(char *, const char *);
char *strncpy(char *, const char *, size_t);
char *strcat(char *, const char *);
char *strncat(char *, const char *, size_t);
int strcmp(const char *, const char *);
int strncmp(const char *, const char *, size_t);
char *strchr(const char *, int);
char *strrchr(const char *, int);
char *strstr(const char *, const char *);
unsigned long strtoul(const char *, char **, int);
int snprintf(char *, unsigned long long, const char *, ...);
int vsnprintf(char *, unsigned long long, const char *, va_list);
int sprintf(char *, const char *, ...);
static inline int isdigit(int c) { return c >= '0' && c <= '9'; }
static inline int islower(int c) { return c >= 'a' && c <= 'z'; }
static inline int isupper(int c) { return c >= 'A' && c <= 'Z'; }
static inline int isalpha(int c) { return islower(c) || isupper(c); }
static inline int isalnum(int c) { return isalpha(c) || isdigit(c); }
static inline int isspace(int c) { return c == ' ' || (c >= '\t' && c <= '\r'); }
static inline int isprint(int c) { return c >= 0x20 && c <= 0x7e; }
static inline int isxdigit(int c) { return isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
static inline int toupper(int c) { return islower(c) ? c - 'a' + 'A' : c; }
static inline int tolower(int c) { return isupper(c) ? c - 'A' + 'a' : c; }
#endif
