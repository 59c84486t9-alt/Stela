// SPDX-License-Identifier: MIT
/* C's mathematics over the x87 unit, which computes the elementary functions
 * to a precision past double's, so no tables are needed here. Mesa uses these
 * to fold constants the way a GPU will evaluate them, which is itself never
 * exact, and for nothing that must round identically across hosts. */
#include <fenv.h>
#include <float.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>

static inline long double x87_scale(long double x, long double exponent)
{
	__asm__("fscale" : "+t"(x) : "u"(exponent));
	return x;
}

/* 2^x, of any finite x. */
static long double x87_exp2(long double x)
{
	long double whole, fraction;
	__asm__("frndint" : "=t"(whole) : "0"(x));
	fraction = x - whole;
	__asm__("f2xm1" : "+t"(fraction));
	return x87_scale(fraction + 1, whole);
}

/* y * log2(x). */
static long double x87_ylog2(long double y, long double x)
{
	long double result;
	__asm__("fyl2x" : "=t"(result) : "0"(x), "u"(y) : "st(1)");
	return result;
}

static long double x87_ln(long double x)
{
	return x87_ylog2(0.693147180559945309417232121458176568L, x);
}

static long double x87_atan2(long double y, long double x)
{
	long double result;
	__asm__("fpatan" : "=t"(result) : "0"(x), "u"(y) : "st(1)");
	return result;
}

static long double x87_sqrt(long double x)
{
	__asm__("fsqrt" : "+t"(x));
	return x;
}

/* The argument reduced to fsin's range, by fprem's partial remainders. */
static long double x87_reduce(long double x)
{
	long double pi2 = 6.283185307179586476925286766559005768L;
	unsigned short status;
	do {
		__asm__("fprem\n\tfnstsw %1" : "+t"(x), "=a"(status) : "u"(pi2));
	} while (status & 0x400);
	return x;
}

static long double x87_sin(long double x)
{
	x = x87_reduce(x);
	__asm__("fsin" : "+t"(x));
	return x;
}

static long double x87_cos(long double x)
{
	x = x87_reduce(x);
	__asm__("fcos" : "+t"(x));
	return x;
}

static long double x87_tan(long double x)
{
	return x87_sin(x) / x87_cos(x);
}

static long double x87_exp(long double x)
{
	return x87_exp2(x * 1.442695040888963407359924681001892137L);
}

static long double pow_of(long double x, long double y)
{
	if (y == 0 || x == 1)
		return 1;
	if (x != x || y != y)
		return x + y;
	if (x == 0)
		return y > 0 ? (signbit(x) && y == rint(y) && (long long)y % 2 ? -0.0L : 0.0L) :
			       HUGE_VAL;
	if (x < 0) {
		if (y != rint(y))
			return NAN;
		long double magnitude = x87_exp2(x87_ylog2(y, -x));
		return (long long)y % 2 ? -magnitude : magnitude;
	}
	return x87_exp2(x87_ylog2(y, x));
}

#define ONE(name, expression)                                                                      \
	double name(double x)                                                                      \
	{                                                                                          \
		long double v = x;                                                                 \
		return (double)(expression);                                                       \
	}                                                                                          \
	float name##f(float x)                                                                     \
	{                                                                                          \
		long double v = x;                                                                 \
		return (float)(expression);                                                        \
	}
#define TWO(name, expression)                                                                      \
	double name(double x, double y)                                                            \
	{                                                                                          \
		long double a = x, b = y;                                                          \
		return (double)(expression);                                                       \
	}                                                                                          \
	float name##f(float x, float y)                                                            \
	{                                                                                          \
		long double a = x, b = y;                                                          \
		return (float)(expression);                                                        \
	}

ONE(sin, x87_sin(v))
ONE(cos, x87_cos(v))
ONE(tan, x87_tan(v))
ONE(asin, x87_atan2(v, x87_sqrt((1 - v) * (1 + v))))
ONE(acos, x87_atan2(x87_sqrt((1 - v) * (1 + v)), v))
ONE(atan, x87_atan2(v, 1))
ONE(exp, x87_exp(v))
ONE(exp2, x87_exp2(v))
ONE(expm1, x87_exp(v) - 1)
ONE(log, x87_ln(v))
ONE(log2, x87_ylog2(1, v))
ONE(log10, x87_ylog2(0.301029995663981195213738894724493027L, v))
ONE(log1p, x87_ln(1 + v))
ONE(sqrt, x87_sqrt(v))
ONE(cbrt, v < 0 ? -pow_of(-v, 1.0L / 3) : pow_of(v, 1.0L / 3))
ONE(sinh, (x87_exp(v) - x87_exp(-v)) / 2)
ONE(cosh, (x87_exp(v) + x87_exp(-v)) / 2)
ONE(tanh, (x87_exp(v) - x87_exp(-v)) / (x87_exp(v) + x87_exp(-v)))
ONE(asinh, x87_ln(v + x87_sqrt(v * v + 1)))
ONE(acosh, x87_ln(v + x87_sqrt(v * v - 1)))
ONE(atanh, x87_ln((1 + v) / (1 - v)) / 2)
TWO(pow, pow_of(a, b))
TWO(atan2, x87_atan2(a, b))
TWO(hypot, x87_sqrt(a * a + b * b))
TWO(fdim, a > b ? a - b : 0)
TWO(fmax, a != a ? b : b != b ? a : a > b ? a : b)
TWO(fmin, a != a ? b : b != b ? a : a < b ? a : b)

/* Rounding, in the mode the x87 control word gives `frndint`. */
static long double round_with(long double x, unsigned short mode)
{
	unsigned short saved, changed;
	__asm__("fnstcw %0" : "=m"(saved));
	changed = (unsigned short)((saved & ~0xc00) | mode);
	__asm__("fldcw %0" : : "m"(changed));
	__asm__("frndint" : "+t"(x));
	__asm__("fldcw %0" : : "m"(saved));
	return x;
}

static long double round_as_set(long double x)
{
	__asm__("frndint" : "+t"(x));
	return x;
}

#define ROUND_DOWN 0x400
#define ROUND_UP 0x800
#define ROUND_ZERO 0xc00

long double floorl(long double x)
{
	return round_with(x, ROUND_DOWN);
}

ONE(floor, round_with(v, ROUND_DOWN))
ONE(ceil, round_with(v, ROUND_UP))
ONE(trunc, round_with(v, ROUND_ZERO))
ONE(rint, round_as_set(v))
ONE(nearbyint, round_as_set(v))
ONE(round, v < 0 ? -round_with(0.5L - v, ROUND_DOWN) : round_with(v + 0.5L, ROUND_DOWN))
ONE(fabs, v < 0 ? -v : v == 0 ? 0 : v)

long lrint(double x)
{
	return (long)rint(x);
}

long lrintf(float x)
{
	return (long)rintf(x);
}

long long llrint(double x)
{
	return (long long)rint(x);
}

long long llrintf(float x)
{
	return (long long)rintf(x);
}

long lround(double x)
{
	return (long)round(x);
}

long lroundf(float x)
{
	return (long)roundf(x);
}

long long llround(double x)
{
	return (long long)round(x);
}

long long llroundf(float x)
{
	return (long long)roundf(x);
}

double logb(double x)
{
	if (x == 0)
		return -HUGE_VAL;
	if (isinf(x))
		return HUGE_VAL;
	if (isnan(x))
		return x;
	int exponent;
	frexp(x, &exponent);
	return exponent - 1;
}

/* Maclaurin's series near zero, a continued fraction of erfc beyond it. */
double erf(double x)
{
	if (isnan(x))
		return x;
	double magnitude = fabs(x);
	long double result;
	if (magnitude < 2.5) {
		long double square = (long double)magnitude * magnitude;
		long double term = magnitude;
		long double sum = term;
		for (int n = 1; n < 80; n++) {
			term *= -square / n;
			sum += term / (2 * n + 1);
		}
		result = sum * 1.128379167095512573896158903121545172L;
	} else if (magnitude >= 6) {
		result = 1;
	} else {
		long double fraction = 0;
		for (int n = 60; n > 0; n--) {
			fraction = (n / 2.0L) / (magnitude + fraction);
		}
		long double square = (long double)magnitude * magnitude;
		result = 1 - x87_exp2(-square * 1.442695040888963407359924681001892137L)
				     * 0.564189583547756286948079451560772586L / (magnitude + fraction);
	}
	return x < 0 ? -(double)result : (double)result;
}

double copysign(double x, double y)
{
	return __builtin_copysign(x, y);
}

float copysignf(float x, float y)
{
	return __builtin_copysignf(x, y);
}

double ldexp(double x, int exponent)
{
	return (double)x87_scale(x, exponent);
}

float ldexpf(float x, int exponent)
{
	return (float)x87_scale(x, exponent);
}

double scalbn(double x, int exponent)
{
	return ldexp(x, exponent);
}

float scalbnf(float x, int exponent)
{
	return ldexpf(x, exponent);
}

double fma(double x, double y, double z)
{
	return (double)((long double)x * y + z);
}

float fmaf(float x, float y, float z)
{
	return (float)((double)x * y + z);
}

double modf(double x, double *integer)
{
	*integer = trunc(x);
	return copysign(isinf(x) ? 0 : x - *integer, x);
}

float modff(float x, float *integer)
{
	*integer = truncf(x);
	return copysignf(isinf(x) ? 0 : x - *integer, x);
}

double fmod(double x, double y)
{
	long double a = x, b = y;
	unsigned short status;
	do {
		__asm__("fprem\n\tfnstsw %1" : "+t"(a), "=a"(status) : "u"(b));
	} while (status & 0x400);
	return (double)a;
}

float fmodf(float x, float y)
{
	return (float)fmod(x, y);
}

double remainder(double x, double y)
{
	long double a = x, b = y;
	unsigned short status;
	do {
		__asm__("fprem1\n\tfnstsw %1" : "+t"(a), "=a"(status) : "u"(b));
	} while (status & 0x400);
	return (double)a;
}

float remainderf(float x, float y)
{
	return (float)remainder(x, y);
}

double frexp(double x, int *exponent)
{
	*exponent = 0;
	if (x == 0 || x != x || isinf(x))
		return x;
	int shift = 0;
	if (fabs(x) < DBL_MIN) {
		x *= 0x1p54;
		shift = -54;
	}
	union {
		double value;
		uint64_t bits;
	} u = {x};
	*exponent = (int)(u.bits >> 52 & 0x7ff) - 1022 + shift;
	u.bits = (u.bits & ~(0x7ffull << 52)) | 1022ull << 52;
	return u.value;
}

float frexpf(float x, int *exponent)
{
	return (float)frexp(x, exponent);
}

double nextafter(double x, double y)
{
	if (x != x || y != y)
		return x + y;
	if (x == y)
		return y;
	union {
		double value;
		uint64_t bits;
	} u = {x};
	if (x == 0)
		u.bits = (y < 0 ? 1ull << 63 : 0) | 1;
	else if ((x < y) == (x > 0))
		u.bits++;
	else
		u.bits--;
	return u.value;
}

float nextafterf(float x, float y)
{
	if (x != x || y != y)
		return x + y;
	if (x == y)
		return y;
	union {
		float value;
		uint32_t bits;
	} u = {x};
	if (x == 0)
		u.bits = (y < 0 ? 1u << 31 : 0) | 1;
	else if ((x < y) == (x > 0))
		u.bits++;
	else
		u.bits--;
	return u.value;
}

static unsigned int read_mxcsr(void)
{
	unsigned int value;
	__asm__("stmxcsr %0" : "=m"(value));
	return value;
}

static void write_mxcsr(unsigned int value)
{
	__asm__("ldmxcsr %0" : : "m"(value));
}

/* FE_ rounding modes are x87's, two bits lower than MXCSR's field. */
#define ROUND_SHIFT 3
#define ROUND_MASK 0x6000
#define FE_MASK 0xc00

int fegetenv(fenv_t *environment)
{
	*environment = read_mxcsr();
	return 0;
}

/* The elementary functions round on the x87 unit, so it follows MXCSR. */
static void follow_mxcsr(void)
{
	unsigned short control;
	__asm__("fnstcw %0" : "=m"(control));
	control = (unsigned short)((control & ~FE_MASK) | (read_mxcsr() & ROUND_MASK) >> ROUND_SHIFT);
	__asm__("fldcw %0" : : "m"(control));
}

int fesetenv(const fenv_t *environment)
{
	write_mxcsr(*environment);
	follow_mxcsr();
	return 0;
}

int feholdexcept(fenv_t *environment)
{
	*environment = read_mxcsr();
	write_mxcsr(*environment & ~(unsigned int)FE_ALL_EXCEPT);
	return 0;
}

/* The exceptions that trap: none, since MXCSR's masks stay set. */
int fegetexcept(void)
{
	return 0;
}

int fegetround(void)
{
	return (int)((read_mxcsr() & ROUND_MASK) >> ROUND_SHIFT);
}

int fesetround(int mode)
{
	write_mxcsr((read_mxcsr() & ~(unsigned int)ROUND_MASK) | (unsigned int)mode << ROUND_SHIFT);
	follow_mxcsr();
	return 0;
}

int feclearexcept(int exceptions)
{
	write_mxcsr(read_mxcsr() & ~(unsigned int)exceptions);
	return 0;
}

int fetestexcept(int exceptions)
{
	return (int)read_mxcsr() & exceptions;
}
