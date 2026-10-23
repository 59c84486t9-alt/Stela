/* SPDX-License-Identifier: MIT */
/* The functions Mesa's floating-point helpers name; see assert.h. The integer
 * encoders call none of them, and nothing defines them.
 */
#ifndef STELA_FREESTANDING_MATH_H
#define STELA_FREESTANDING_MATH_H
float fabsf(float);
double fmax(double, double);
double fmin(double, double);
long long llroundf(float);
long lrintf(float);
float roundf(float);
#endif
