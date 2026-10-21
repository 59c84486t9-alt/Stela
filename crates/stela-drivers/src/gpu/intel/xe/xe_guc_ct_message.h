/* SPDX-License-Identifier: MIT */
/* Copyright © 2022 Intel Corporation */
#ifndef XE_GUC_CT_MESSAGE_H
#define XE_GUC_CT_MESSAGE_H

#include "abi/guc_communication_ctb_abi.h"

/* Header construction shared with h2g_write(). The caller has validated the
 * payload length, fence and message type and has reserved response credits.
 */
static inline void xe_guc_ct_message_header(u32 *cmd, u32 len, u32 fence,
                                          u32 type, u32 action)
{
	cmd[0] = FIELD_PREP(GUC_CTB_MSG_0_FORMAT, GUC_CTB_FORMAT_HXG) |
		FIELD_PREP(GUC_CTB_MSG_0_NUM_DWORDS, len) |
		FIELD_PREP(GUC_CTB_MSG_0_FENCE, fence);
	cmd[1] = FIELD_PREP(GUC_HXG_MSG_0_TYPE, type) |
		FIELD_PREP(GUC_HXG_EVENT_MSG_0_ACTION |
			   GUC_HXG_EVENT_MSG_0_DATA0, action);
}

#endif
