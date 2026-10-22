/* SPDX-License-Identifier: MIT */
/* Copyright © 2022 Intel Corporation */
#ifndef XE_WOPCM_CORE_H
#define XE_WOPCM_CORE_H
#ifndef XE_WOPCM_WARN
#error "WOPCM requires the real caller warning binding"
#endif
/* Original WOPCM policy, with mandatory real context/diagnostic operations.
 * The caller retains exclusive serialization and acknowledged GT forcewake.
 * No default operations or firmware availability state are supplied here. */
enum xe_wopcm_event {
	XE_WOPCM_INVALID_LAYOUT, XE_WOPCM_GUC_SPACE, XE_WOPCM_HUC_SPACE,
	XE_WOPCM_INIT_FAILED, XE_WOPCM_OFFSET_READBACK, XE_WOPCM_SIZE_READBACK,
	XE_WOPCM_TOTAL, XE_WOPCM_LOCKED, XE_WOPCM_CALCULATED, XE_WOPCM_PARTITION_FAILED,
};
struct xe_wopcm_core_ops {
	u32 (*read32)(void *, struct xe_reg);
	int (*write32_and_verify)(void *, struct xe_reg, u32, u32, u32);
	bool (*huc_available)(void *);
	void (*assert_held)(void *);
	void (*report)(void *, enum xe_wopcm_event, u32, u32, u32);
};
struct xe_wopcm_core {
	void *context;
	const struct xe_wopcm_core_ops *ops;
};
static inline void xe_wopcm_core_report(const struct xe_wopcm_core *core,
		enum xe_wopcm_event event, u32 a, u32 b, u32 c)
{
	core->ops->report(core->context, event, a, b, c);
}
#include "xe_wopcm_size.h"

/* 16KB WOPCM (RSVD WOPCM) is reserved from HuC firmware top. */
#define WOPCM_RESERVED_SIZE		SZ_16K

/* 16KB reserved at the beginning of GuC WOPCM. */
#define GUC_WOPCM_RESERVED		SZ_16K
/* 8KB from GUC_WOPCM_RESERVED is reserved for GuC stack. */
#define GUC_WOPCM_STACK_RESERVED	SZ_8K

/* GuC WOPCM Offset value needs to be aligned to 16KB. */
#define GUC_WOPCM_OFFSET_ALIGNMENT	(1UL << GUC_WOPCM_OFFSET_SHIFT)

/* 36KB WOPCM reserved at the end of WOPCM */
#define WOPCM_HW_CTX_RESERVED		(SZ_32K + SZ_4K)

static u32 context_reserved_size(void)
{
	return WOPCM_HW_CTX_RESERVED;
}

static bool __check_layout(const struct xe_wopcm_core *core, u32 wopcm_size,
			   u32 guc_wopcm_base, u32 guc_wopcm_size,
			   u32 guc_fw_size, u32 huc_fw_size)
{
	const u32 ctx_rsvd = context_reserved_size();
	u32 size;

	size = wopcm_size - ctx_rsvd;
	if (unlikely(guc_wopcm_base >= size ||
		     guc_wopcm_size > size - guc_wopcm_base)) {
		xe_wopcm_core_report(core, XE_WOPCM_INVALID_LAYOUT, guc_wopcm_base, guc_wopcm_size, size);
		return false;
	}

	size = guc_fw_size + GUC_WOPCM_RESERVED + GUC_WOPCM_STACK_RESERVED;
	if (unlikely(guc_wopcm_size < size)) {
		xe_wopcm_core_report(core, XE_WOPCM_GUC_SPACE, guc_wopcm_size, size, 0);
		return false;
	}

	size = huc_fw_size + WOPCM_RESERVED_SIZE;
	if (unlikely(guc_wopcm_base < size)) {
		xe_wopcm_core_report(core, XE_WOPCM_HUC_SPACE, guc_wopcm_base, size, 0);
		return false;
	}

	return true;
}

static bool __wopcm_regs_locked(const struct xe_wopcm_core *core,
				u32 *guc_wopcm_base, u32 *guc_wopcm_size)
{
	u32 reg_base = core->ops->read32(core->context, DMA_GUC_WOPCM_OFFSET);
	u32 reg_size = core->ops->read32(core->context, GUC_WOPCM_SIZE);

	if (!(reg_size & GUC_WOPCM_SIZE_LOCKED) ||
	    !(reg_base & GUC_WOPCM_OFFSET_VALID))
		return false;

	*guc_wopcm_base = reg_base & GUC_WOPCM_OFFSET_MASK;
	*guc_wopcm_size = reg_size & GUC_WOPCM_SIZE_MASK;
	return true;
}

static int __wopcm_init_regs(const struct xe_wopcm_core *core,
			     struct xe_wopcm *wopcm)
{
	u32 base = wopcm->guc.base;
	u32 size = wopcm->guc.size;
	u32 huc_agent = core->ops->huc_available(core->context) ? HUC_LOADING_AGENT_GUC : 0;
	u32 mask;
	int err;

	XE_WOPCM_WARN(core, 0, !(base & GUC_WOPCM_OFFSET_MASK));
	XE_WOPCM_WARN(core, 1, base & ~GUC_WOPCM_OFFSET_MASK);
	XE_WOPCM_WARN(core, 2, !(size & GUC_WOPCM_SIZE_MASK));
	XE_WOPCM_WARN(core, 3, size & ~GUC_WOPCM_SIZE_MASK);

	mask = GUC_WOPCM_SIZE_MASK | GUC_WOPCM_SIZE_LOCKED;
	err = core->ops->write32_and_verify(core->context, GUC_WOPCM_SIZE, size, mask,
					 size | GUC_WOPCM_SIZE_LOCKED);
	if (err)
		goto err_out;

	mask = GUC_WOPCM_OFFSET_MASK | GUC_WOPCM_OFFSET_VALID | huc_agent;
	err = core->ops->write32_and_verify(core->context, DMA_GUC_WOPCM_OFFSET,
					 base | huc_agent, mask,
					 base | huc_agent |
					 GUC_WOPCM_OFFSET_VALID);
	if (err)
		goto err_out;

	return 0;

err_out:
	xe_wopcm_core_report(core, XE_WOPCM_INIT_FAILED, 0, 0, 0);
	xe_wopcm_core_report(core, XE_WOPCM_OFFSET_READBACK, DMA_GUC_WOPCM_OFFSET.addr,
		   core->ops->read32(core->context, DMA_GUC_WOPCM_OFFSET), 0);
	xe_wopcm_core_report(core, XE_WOPCM_SIZE_READBACK, GUC_WOPCM_SIZE.addr,
		   core->ops->read32(core->context, GUC_WOPCM_SIZE), 0);

	return err;
}


static u32 max_wopcm_size(enum xe_platform platform)
{
	if (platform == XE_NOVALAKE_P)
		return SZ_16M;
	else
		return SZ_8M;
}

/**
 * xe_wopcm_init() - Initialize the WOPCM structure.
 * @wopcm: pointer to xe_wopcm.
 *
 * This function will partition WOPCM space based on GuC and HuC firmware sizes
 * and will allocate max remaining for use by GuC. This function will also
 * enforce platform dependent hardware restrictions on GuC WOPCM offset and
 * size. It will fail the WOPCM init if any of these checks fail, so that the
 * following WOPCM registers setup and GuC firmware uploading would be aborted.
 */
static int xe_wopcm_core_init(struct xe_wopcm *wopcm, enum xe_platform platform,
		bool discrete, u32 guc_fw_size, u32 huc_fw_size,
		const struct xe_wopcm_core *core)
{
	u32 ctx_rsvd = context_reserved_size();
	u32 guc_wopcm_base;
	u32 guc_wopcm_size;
	bool locked;
	int ret = 0;

	if (!guc_fw_size)
		return -EINVAL;

	wopcm->size = xe_wopcm_default_size(platform, discrete);
	xe_wopcm_core_report(core, XE_WOPCM_TOTAL, wopcm->size, 0, 0);

	core->ops->assert_held(core->context);
	XE_WOPCM_WARN(core, 4, guc_fw_size >= wopcm->size);
	XE_WOPCM_WARN(core, 5, huc_fw_size >= wopcm->size);
	XE_WOPCM_WARN(core, 6, ctx_rsvd + WOPCM_RESERVED_SIZE >= wopcm->size);

	locked = __wopcm_regs_locked(core, &guc_wopcm_base, &guc_wopcm_size);
	if (locked) {
		xe_wopcm_core_report(core, XE_WOPCM_LOCKED, guc_wopcm_base, guc_wopcm_size, 0);
		/*
		 * When the GuC wopcm base and size are preprogrammed by
		 * BIOS/IFWI, check against the max allowed wopcm size to
		 * validate if the programmed values align to the wopcm layout.
		 *
		 * FIXME: This is giving the maximum overall WOPCM size and not
		 * the size relative to each GT.
		 */
		wopcm->size = max_wopcm_size(platform);

		goto check;
	}

	/*
	 * Aligned value of guc_wopcm_base will determine available WOPCM space
	 * for HuC firmware and mandatory reserved area.
	 */
	guc_wopcm_base = huc_fw_size + WOPCM_RESERVED_SIZE;
	guc_wopcm_base = ALIGN(guc_wopcm_base, GUC_WOPCM_OFFSET_ALIGNMENT);

	/*
	 * Need to clamp guc_wopcm_base now to make sure the following math is
	 * correct. Formal check of whole WOPCM layout will be done below.
	 */
	guc_wopcm_base = min(guc_wopcm_base, wopcm->size - ctx_rsvd);

	/* Aligned remainings of usable WOPCM space can be assigned to GuC. */
	guc_wopcm_size = wopcm->size - ctx_rsvd - guc_wopcm_base;
	guc_wopcm_size &= GUC_WOPCM_SIZE_MASK;

	xe_wopcm_core_report(core, XE_WOPCM_CALCULATED, guc_wopcm_base, guc_wopcm_size, 0);

check:
	if (__check_layout(core, wopcm->size, guc_wopcm_base, guc_wopcm_size,
			   guc_fw_size, huc_fw_size)) {
		wopcm->guc.base = guc_wopcm_base;
		wopcm->guc.size = guc_wopcm_size;
		XE_WOPCM_WARN(core, 7, !wopcm->guc.base);
		XE_WOPCM_WARN(core, 8, !wopcm->guc.size);
	} else {
		xe_wopcm_core_report(core, XE_WOPCM_PARTITION_FAILED, 0, 0, 0);
		return -E2BIG;
	}

	if (!locked)
		ret = __wopcm_init_regs(core, wopcm);

	return ret;
}
#undef XE_WOPCM_WARN
#endif
