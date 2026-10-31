/* SPDX-License-Identifier: MIT */
/* What libc++ names. libc++'s strings are all that run wide text, and wchar.c
 * has what they reach; the rest are declarations, so a caller fails the link. */
#ifndef STELA_LIBC_WCHAR_H
#define STELA_LIBC_WCHAR_H
#include <sys/cdefs.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>
__BEGIN_DECLS
#define WEOF 0xffffffffu
#define WCHAR_MIN __WCHAR_MIN__
#define WCHAR_MAX __WCHAR_MAX__
typedef unsigned int wint_t;
typedef struct {
	unsigned int bytes;
	unsigned int count;
} mbstate_t;
int fwprintf(FILE *file, const wchar_t *format, ...);
int fwscanf(FILE *file, const wchar_t *format, ...);
int swprintf(wchar_t *text, size_t size, const wchar_t *format, ...);
int swscanf(const wchar_t *text, const wchar_t *format, ...);
int vfwprintf(FILE *file, const wchar_t *format, va_list list);
int vfwscanf(FILE *file, const wchar_t *format, va_list list);
int vswprintf(wchar_t *text, size_t size, const wchar_t *format, va_list list);
int vswscanf(const wchar_t *text, const wchar_t *format, va_list list);
int vwprintf(const wchar_t *format, va_list list);
int vwscanf(const wchar_t *format, va_list list);
int wprintf(const wchar_t *format, ...);
int wscanf(const wchar_t *format, ...);
wint_t fgetwc(FILE *file);
wchar_t *fgetws(wchar_t *text, int size, FILE *file);
wint_t fputwc(wchar_t character, FILE *file);
int fputws(const wchar_t *text, FILE *file);
int fwide(FILE *file, int mode);
wint_t getwc(FILE *file);
wint_t getwchar(void);
wint_t putwc(wchar_t character, FILE *file);
wint_t putwchar(wchar_t character);
wint_t ungetwc(wint_t character, FILE *file);
double wcstod(const wchar_t *text, wchar_t **end);
float wcstof(const wchar_t *text, wchar_t **end);
long double wcstold(const wchar_t *text, wchar_t **end);
long wcstol(const wchar_t *text, wchar_t **end, int base);
long long wcstoll(const wchar_t *text, wchar_t **end, int base);
unsigned long wcstoul(const wchar_t *text, wchar_t **end, int base);
unsigned long long wcstoull(const wchar_t *text, wchar_t **end, int base);
wchar_t *wcscpy(wchar_t *to, const wchar_t *from);
wchar_t *wcsncpy(wchar_t *to, const wchar_t *from, size_t size);
wchar_t *wcscat(wchar_t *to, const wchar_t *from);
wchar_t *wcsncat(wchar_t *to, const wchar_t *from, size_t size);
int wcscmp(const wchar_t *left, const wchar_t *right);
int wcscoll(const wchar_t *left, const wchar_t *right);
int wcsncmp(const wchar_t *left, const wchar_t *right, size_t size);
size_t wcsxfrm(wchar_t *to, const wchar_t *from, size_t size);
wchar_t *wcschr(const wchar_t *text, wchar_t character);
wchar_t *wcspbrk(const wchar_t *text, const wchar_t *set);
wchar_t *wcsrchr(const wchar_t *text, wchar_t character);
wchar_t *wcsstr(const wchar_t *text, const wchar_t *part);
wchar_t *wmemchr(const wchar_t *text, wchar_t character, size_t size);
size_t wcscspn(const wchar_t *text, const wchar_t *set);
size_t wcslen(const wchar_t *text);
size_t wcsspn(const wchar_t *text, const wchar_t *set);
wchar_t *wcstok(wchar_t *text, const wchar_t *set, wchar_t **state);
int wmemcmp(const wchar_t *left, const wchar_t *right, size_t size);
wchar_t *wmemcpy(wchar_t *to, const wchar_t *from, size_t size);
wchar_t *wmemmove(wchar_t *to, const wchar_t *from, size_t size);
wchar_t *wmemset(wchar_t *to, wchar_t character, size_t size);
size_t wcsftime(wchar_t *text, size_t size, const wchar_t *format, const struct tm *time);
wint_t btowc(int character);
int wctob(wint_t character);
int mbsinit(const mbstate_t *state);
size_t mbrlen(const char *text, size_t size, mbstate_t *state);
size_t mbrtowc(wchar_t *to, const char *text, size_t size, mbstate_t *state);
size_t wcrtomb(char *to, wchar_t character, mbstate_t *state);
size_t mbsrtowcs(wchar_t *to, const char **text, size_t size, mbstate_t *state);
size_t wcsrtombs(char *to, const wchar_t **text, size_t size, mbstate_t *state);
__END_DECLS
#endif
