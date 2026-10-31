/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_FENV_H
#define STELA_LIBC_FENV_H
#include <sys/cdefs.h>
__BEGIN_DECLS
#define FE_TONEAREST 0
#define FE_DOWNWARD 0x400
#define FE_UPWARD 0x800
#define FE_TOWARDZERO 0xc00
#define FE_INVALID 1
#define FE_DIVBYZERO 4
#define FE_OVERFLOW 8
#define FE_UNDERFLOW 16
#define FE_INEXACT 32
#define FE_ALL_EXCEPT 61
/* SSE's control and status register, the only unit Mesa folds constants on. */
typedef unsigned int fenv_t;
typedef unsigned short fexcept_t;
int fegetenv(fenv_t *environment);
int fesetenv(const fenv_t *environment);
int feholdexcept(fenv_t *environment);
int fegetexcept(void);
int fegetround(void);
int fesetround(int mode);
int feclearexcept(int exceptions);
int fetestexcept(int exceptions);
int fegetexceptflag(fexcept_t *flags, int exceptions);
int fesetexceptflag(const fexcept_t *flags, int exceptions);
int feraiseexcept(int exceptions);
int feupdateenv(const fenv_t *environment);
__END_DECLS
#endif
