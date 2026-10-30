/* SPDX-License-Identifier: MIT */
/* Kbuild generates these with kernel/time/timeconst.bc; here for HZ=1000. */
#ifndef __KERNEL_TIMECONST_H
#define __KERNEL_TIMECONST_H

#include <linux/param.h>
#include <linux/types.h>

#if HZ != 1000
#error "generated/timeconst.h has the wrong HZ value!"
#endif

#define HZ_TO_MSEC_MUL32	U64_C(0x80000000)
#define HZ_TO_MSEC_ADJ32	U64_C(0x0)
#define HZ_TO_MSEC_SHR32	31
#define MSEC_TO_HZ_MUL32	U64_C(0x80000000)
#define MSEC_TO_HZ_ADJ32	U64_C(0x0)
#define MSEC_TO_HZ_SHR32	31
#define HZ_TO_MSEC_NUM		1
#define HZ_TO_MSEC_DEN		1
#define MSEC_TO_HZ_NUM		1
#define MSEC_TO_HZ_DEN		1

#define HZ_TO_USEC_MUL32	U64_C(0xFA000000)
#define HZ_TO_USEC_ADJ32	U64_C(0x0)
#define HZ_TO_USEC_SHR32	22
#define USEC_TO_HZ_MUL32	U64_C(0x83126E98)
#define USEC_TO_HZ_ADJ32	U64_C(0x1FF7CED9168)
#define USEC_TO_HZ_SHR32	41
#define HZ_TO_USEC_NUM		1000
#define HZ_TO_USEC_DEN		1
#define USEC_TO_HZ_NUM		1
#define USEC_TO_HZ_DEN		1000
#define HZ_TO_NSEC_NUM		1000000
#define HZ_TO_NSEC_DEN		1
#define NSEC_TO_HZ_NUM		1
#define NSEC_TO_HZ_DEN		1000000

#endif /* __KERNEL_TIMECONST_H */
