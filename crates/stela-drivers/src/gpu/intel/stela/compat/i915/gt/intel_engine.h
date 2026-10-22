/* SPDX-License-Identifier: MIT */
#ifndef STELA_I915_INTEL_ENGINE_H
#define STELA_I915_INTEL_ENGINE_H
#include <linux/types.h>
#include "intel_engine_types.h"
#include "intel_uncore.h"
/* Register access through the engine's uncore, from intel_engine.h. */
#define __ENGINE_REG_OP(op__, engine__, ...) \
	intel_uncore_##op__((engine__)->uncore, __VA_ARGS__)
#define __ENGINE_READ_OP(op__, engine__, reg__) \
	__ENGINE_REG_OP(op__, (engine__), reg__((engine__)->mmio_base))
#define ENGINE_POSTING_READ(...) __ENGINE_READ_OP(posting_read_fw, __VA_ARGS__)
#define __ENGINE_WRITE_OP(op__, engine__, reg__, val__) \
	__ENGINE_REG_OP(op__, (engine__), reg__((engine__)->mmio_base), (val__))
#define ENGINE_WRITE(...) __ENGINE_WRITE_OP(write, __VA_ARGS__)
/* Status-page slots, from intel_engine.h. */
#define I915_GEM_HWS_PREEMPT 0x32
#define I915_GEM_HWS_PREEMPT_ADDR (I915_GEM_HWS_PREEMPT * sizeof(u32))
#define I915_GEM_HWS_SEQNO 0x40
#define I915_GEM_HWS_SEQNO_ADDR (I915_GEM_HWS_SEQNO * sizeof(u32))
#define I915_GEM_HWS_SCRATCH 0x80
static bool intel_engine_has_semaphores(const struct intel_engine_cs *engine);
static bool intel_engine_uses_wa_hold_switchout(struct intel_engine_cs *engine);
#endif
