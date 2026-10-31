/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_MATH_H
#define STELA_LIBC_MATH_H
#define M_E 2.7182818284590452354
#define M_LOG2E 1.4426950408889634074
#define M_LOG10E 0.43429448190325182765
#define M_LN2 0.69314718055994530942
#define M_LN10 2.30258509299404568402
#define M_PI 3.14159265358979323846
#define M_PI_2 1.57079632679489661923
#define M_PI_4 0.78539816339744830962
#define M_1_PI 0.31830988618379067154
#define M_2_PI 0.63661977236758134308
#define M_SQRT2 1.41421356237309504880
#define M_SQRT1_2 0.70710678118654752440
#define HUGE_VAL __builtin_huge_val()
#define HUGE_VALF __builtin_huge_valf()
#define INFINITY __builtin_inff()
#define NAN __builtin_nanf("")
#define FP_NAN 0
#define FP_INFINITE 1
#define FP_ZERO 2
#define FP_SUBNORMAL 3
#define FP_NORMAL 4
#define isnan(x) __builtin_isnan(x)
#define isinf(x) __builtin_isinf(x)
#define isfinite(x) __builtin_isfinite(x)
#define isnormal(x) __builtin_isnormal(x)
#define signbit(x) __builtin_signbit(x)
#define fpclassify(x) \
	__builtin_fpclassify(FP_NAN, FP_INFINITE, FP_NORMAL, FP_SUBNORMAL, FP_ZERO, x)
#define STELA_MATH_1(name) double name(double x); float name##f(float x);
#define STELA_MATH_2(name) double name(double x, double y); float name##f(float x, float y);
STELA_MATH_1(acos) STELA_MATH_1(acosh) STELA_MATH_1(asin) STELA_MATH_1(asinh)
long double floorl(long double x);
STELA_MATH_1(atan) STELA_MATH_1(atanh) STELA_MATH_1(cbrt) STELA_MATH_1(ceil)
STELA_MATH_1(cos) STELA_MATH_1(cosh) STELA_MATH_1(exp) STELA_MATH_1(exp2)
STELA_MATH_1(expm1) STELA_MATH_1(fabs) STELA_MATH_1(floor) STELA_MATH_1(log)
STELA_MATH_1(log10) STELA_MATH_1(log1p) STELA_MATH_1(log2) STELA_MATH_1(nearbyint)
STELA_MATH_1(rint) STELA_MATH_1(round) STELA_MATH_1(sin) STELA_MATH_1(sinh)
STELA_MATH_1(sqrt) STELA_MATH_1(tan) STELA_MATH_1(tanh) STELA_MATH_1(trunc)
STELA_MATH_2(atan2) STELA_MATH_2(copysign) STELA_MATH_2(fdim) STELA_MATH_2(fmax)
STELA_MATH_2(fmin) STELA_MATH_2(fmod) STELA_MATH_2(hypot) STELA_MATH_2(nextafter)
STELA_MATH_2(pow) STELA_MATH_2(remainder)
#undef STELA_MATH_1
#undef STELA_MATH_2
double fma(double x, double y, double z);
float fmaf(float x, float y, float z);
double frexp(double x, int *exponent);
float frexpf(float x, int *exponent);
double ldexp(double x, int exponent);
float ldexpf(float x, int exponent);
double scalbn(double x, int exponent);
float scalbnf(float x, int exponent);
double modf(double x, double *integer);
float modff(float x, float *integer);
long lrint(double x);
long lrintf(float x);
long long llrint(double x);
long long llrintf(float x);
long lround(double x);
long lroundf(float x);
long long llround(double x);
long long llroundf(float x);
#endif
