/* SPDX-License-Identifier: MIT */
/* What libc++ names; see wchar.h. */
#ifndef STELA_LIBC_WCTYPE_H
#define STELA_LIBC_WCTYPE_H
#include <sys/cdefs.h>
#include <wchar.h>
__BEGIN_DECLS
typedef unsigned long wctrans_t;
typedef unsigned long wctype_t;
int iswalnum(wint_t character);
int iswalpha(wint_t character);
int iswblank(wint_t character);
int iswcntrl(wint_t character);
int iswctype(wint_t character, wctype_t type);
int iswdigit(wint_t character);
int iswgraph(wint_t character);
int iswlower(wint_t character);
int iswprint(wint_t character);
int iswpunct(wint_t character);
int iswspace(wint_t character);
int iswupper(wint_t character);
int iswxdigit(wint_t character);
wint_t towctrans(wint_t character, wctrans_t transformation);
wint_t towlower(wint_t character);
wint_t towupper(wint_t character);
wctrans_t wctrans(const char *name);
wctype_t wctype(const char *name);
__END_DECLS
#endif
