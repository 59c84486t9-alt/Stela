/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */
#ifndef XE_GUC_RESET_CORE_H
#define XE_GUC_RESET_CORE_H
/* Whole original GuC reset/SRAM policy. Every binding is mandatory; includers
 * retain the actual forcewake, VF/WA selection, ordered I/O, poll and diagnostics.
 * This does not sanitize software state or establish whole-device quiescence. */
#ifndef XE_GUC_RESET_CONTEXT
#error "GuC reset requires XE_GUC_RESET_CONTEXT"
#endif
#ifndef XE_GUC_RESET_READ
#error "GuC reset requires XE_GUC_RESET_READ"
#endif
#ifndef XE_GUC_RESET_RMW
#error "GuC reset requires XE_GUC_RESET_RMW"
#endif
#ifndef XE_GUC_RESET_WRITE
#error "GuC reset requires XE_GUC_RESET_WRITE"
#endif
#ifndef XE_GUC_RESET_WAIT
#error "GuC reset requires XE_GUC_RESET_WAIT"
#endif
#ifndef XE_GUC_RESET_ASSERT_HELD
#error "GuC reset requires XE_GUC_RESET_ASSERT_HELD"
#endif
#ifndef XE_GUC_RESET_IS_VF
#error "GuC reset requires XE_GUC_RESET_IS_VF"
#endif
#ifndef XE_GUC_RESET_VF_BOOTSTRAP
#error "GuC reset requires XE_GUC_RESET_VF_BOOTSTRAP"
#endif
#ifndef XE_GUC_RESET_WA_14025883347
#error "GuC reset requires XE_GUC_RESET_WA_14025883347"
#endif
#ifndef XE_GUC_RESET_WARN_READY
#error "GuC reset requires XE_GUC_RESET_WARN_READY"
#endif
#ifndef XE_GUC_RESET_WARN_SRAM
#error "GuC reset requires XE_GUC_RESET_WARN_SRAM"
#endif
#ifndef XE_GUC_RESET_ERROR_TIMEOUT
#error "GuC reset requires XE_GUC_RESET_ERROR_TIMEOUT"
#endif
#ifndef XE_GUC_RESET_ERROR_STATUS
#error "GuC reset requires XE_GUC_RESET_ERROR_STATUS"
#endif
/*
 * Wa_14025883347: Prevent GuC firmware DMA failures during GuC-only reset by ensuring
 * SRAM save/restore operations are complete before reset.
 */
static inline void xe_guc_reset_prevent_fw_dma_failure(XE_GUC_RESET_CONTEXT *context)
{
	u32 boot_hash_chk, guc_status, sram_status;
	int ret;

	guc_status = XE_GUC_RESET_READ(context, GUC_STATUS);
	if (guc_status & GS_MIA_IN_RESET)
		return;

	boot_hash_chk = XE_GUC_RESET_READ(context, BOOT_HASH_CHK);
	if (!(boot_hash_chk & GUC_BOOT_UKERNEL_VALID))
		return;

	/* Disable idle flow during reset (GuC reset re-enables it automatically) */
	XE_GUC_RESET_RMW(context, GUC_MAX_IDLE_COUNT, 0, GUC_IDLE_FLOW_DISABLE);

	ret = XE_GUC_RESET_WAIT(context, GUC_STATUS, GS_UKERNEL_MASK,
			     FIELD_PREP(GS_UKERNEL_MASK, XE_GUC_LOAD_STATUS_READY),
			     100000, &guc_status, false);
	if (ret)
		XE_GUC_RESET_WARN_READY(context, guc_status);

	ret = XE_GUC_RESET_WAIT(context, GUC_SRAM_STATUS, GUC_SRAM_HANDLING_MASK,
			     0, 5000, &sram_status, false);
	if (ret)
		XE_GUC_RESET_WARN_SRAM(context, sram_status);
}

static inline int xe_guc_reset_core(XE_GUC_RESET_CONTEXT *context)
{
	u32 guc_status, gdrst;
	int ret;

	XE_GUC_RESET_ASSERT_HELD(context);

	if (XE_GUC_RESET_IS_VF(context))
		return XE_GUC_RESET_VF_BOOTSTRAP(context);

	if (XE_GUC_RESET_WA_14025883347(context))
		xe_guc_reset_prevent_fw_dma_failure(context);

	XE_GUC_RESET_WRITE(context, GDRST, GRDOM_GUC);

	ret = XE_GUC_RESET_WAIT(context, GDRST, GRDOM_GUC, 0, 5000, &gdrst, false);
	if (ret) {
		XE_GUC_RESET_ERROR_TIMEOUT(context, gdrst);
		goto err_out;
	}

	guc_status = XE_GUC_RESET_READ(context, GUC_STATUS);
	if (!(guc_status & GS_MIA_IN_RESET)) {
		XE_GUC_RESET_ERROR_STATUS(context, guc_status);
		ret = -EIO;
		goto err_out;
	}

	return 0;

err_out:

	return ret;
}

#undef XE_GUC_RESET_CONTEXT
#undef XE_GUC_RESET_READ
#undef XE_GUC_RESET_RMW
#undef XE_GUC_RESET_WRITE
#undef XE_GUC_RESET_WAIT
#undef XE_GUC_RESET_ASSERT_HELD
#undef XE_GUC_RESET_IS_VF
#undef XE_GUC_RESET_VF_BOOTSTRAP
#undef XE_GUC_RESET_WA_14025883347
#undef XE_GUC_RESET_WARN_READY
#undef XE_GUC_RESET_WARN_SRAM
#undef XE_GUC_RESET_ERROR_TIMEOUT
#undef XE_GUC_RESET_ERROR_STATUS
#endif
