/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_BITFIELD_H
#define STELA_LINUX_BITFIELD_H
#include <linux/bits.h>
#include <linux/build_bug.h>
#include <linux/compiler.h>
#include <linux/limits.h>
#define __bf_shf(x) (__builtin_ffsll(x) - 1)
#define FIELD_PREP(mask, val) (((typeof(mask))(val) << __bf_shf(mask)) & (mask))
#define FIELD_PREP_CONST(mask, val) FIELD_PREP(mask, val)
#define FIELD_GET(mask, reg) ((typeof(mask))(((reg) & (mask)) >> __bf_shf(mask)))
#define FIELD_MAX(mask) ((typeof(mask))((mask) >> __bf_shf(mask)))
#define FIELD_FIT(mask, val) (!((((typeof(mask))(val)) << __bf_shf(mask)) & ~(mask)))
#endif
