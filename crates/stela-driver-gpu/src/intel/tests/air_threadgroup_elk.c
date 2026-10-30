/* SPDX-License-Identifier: MIT */
#include "air_threadgroup_elk.h"
#include "intel/compiler/elk/elk_compiler.h"
#include "intel/compiler/elk/elk_eu.h"
#include <assert.h>
#include <string.h>

/* Retained Gen7/8 decoding and uncompaction, in a separate TU because BRW's
 * newer decoder intentionally has no Gen7 compaction table. No descriptor
 * fields are inferred from byte offsets or from the source shader alone.
 */
void stela_intel_elk_shared_stats(const struct elk_compiler *compiler, const void *code,
                                 unsigned bytes, struct stela_intel_shared_stats *stats)
{
    const struct intel_device_info *dev = compiler->devinfo;
    bool wait_pending = false;
    for (unsigned offset = 0; offset < bytes;) {
        elk_inst inst = {0};
        assert(bytes - offset >= sizeof(elk_compact_inst));
        memcpy(&inst, (const char *)code + offset, sizeof(elk_compact_inst));
        bool compact = elk_inst_cmpt_control(dev, &inst);
        unsigned size = compact ? sizeof(elk_compact_inst) : sizeof(elk_inst);
        assert(bytes - offset >= size);
        if (compact) {
            elk_compact_inst encoded;
            memcpy(&encoded, (const char *)code + offset, sizeof(encoded));
            elk_uncompact_instruction(&compiler->isa, &inst, &encoded);
        } else memcpy(&inst, (const char *)code + offset, sizeof(inst));
        enum elk_opcode op = elk_inst_opcode(&compiler->isa, &inst);
        if (wait_pending) {
            assert(op == ELK_OPCODE_WAIT && elk_inst_exec_size(dev, &inst) == ELK_EXECUTE_1 &&
                   elk_inst_mask_control(dev, &inst) == ELK_MASK_DISABLE);
            ++stats->waits; wait_pending = false;
        }
        if (op == ELK_OPCODE_SEND || op == ELK_OPCODE_SENDC) {
            unsigned sfid = elk_inst_sfid(dev, &inst);
            uint32_t desc = elk_inst_send_desc(dev, &inst);
            if (sfid == ELK_SFID_MESSAGE_GATEWAY &&
                elk_inst_gateway_subfuncid(dev, &inst) == ELK_MESSAGE_GATEWAY_SFID_BARRIER_MSG) {
                assert(elk_inst_mask_control(dev, &inst) == ELK_MASK_DISABLE);
                assert(desc == (elk_message_desc(dev, reg_unit(dev), 0, false) |
                                ELK_MESSAGE_GATEWAY_SFID_BARRIER_MSG));
                ++stats->barriers; wait_pending = true;
            } else if (sfid == GFX7_SFID_DATAPORT_DATA_CACHE ||
                       sfid == HSW_SFID_DATAPORT_DATA_CACHE_1) {
                unsigned type = elk_dp_desc_msg_type(dev, desc);
                stats->fences += sfid == GFX7_SFID_DATAPORT_DATA_CACHE &&
                                  type == GFX7_DATAPORT_DC_MEMORY_FENCE;
                if (elk_dp_desc_binding_table_index(dev, desc) == GFX7_BTI_SLM) {
                    if (sfid == HSW_SFID_DATAPORT_DATA_CACHE_1) {
                        stats->loads += type == HSW_DATAPORT_DC_PORT1_UNTYPED_SURFACE_READ;
                        stats->stores += type == HSW_DATAPORT_DC_PORT1_UNTYPED_SURFACE_WRITE;
                    } else {
                        stats->loads += type == GFX7_DATAPORT_DC_UNTYPED_SURFACE_READ ||
                                        type == GFX7_DATAPORT_DC_DWORD_SCATTERED_READ ||
                                        type == GFX7_DATAPORT_DC_BYTE_SCATTERED_READ;
                        stats->stores += type == GFX7_DATAPORT_DC_UNTYPED_SURFACE_WRITE ||
                                         type == GFX7_DATAPORT_DC_DWORD_SCATTERED_WRITE ||
                                         type == GFX7_DATAPORT_DC_BYTE_SCATTERED_WRITE;
                    }
                }
            }
        }
        stela_intel_shared_order(stats, offset + 1);
        offset += size;
    }
    assert(!wait_pending);
}
