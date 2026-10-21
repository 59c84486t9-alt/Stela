/* SPDX-License-Identifier: MIT */
#include "fp_controls_elk.h"
#include "intel/compiler/elk/elk_compiler.h"
#include "intel/compiler/elk/elk_eu.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Original ELK accessors/uncompactor are required for Gen7; the newer gen
 * decoder deliberately has no Gen7 compact table. No bitfield is guessed.
 */
void stela_intel_elk_fp_control_stats(const struct elk_compiler *compiler, const void *code,
                                     unsigned bytes, const char *target, bool ftz,
                                     struct stela_intel_fp_stats *stats)
{
    const struct intel_device_info *device = compiler->devinfo;
    uint32_t known = 0, value = 0;
    unsigned ordinal = 0;
    for (unsigned offset = 0; offset < bytes; ++ordinal) {
        elk_inst inst = {0};
        assert(bytes - offset >= sizeof(elk_compact_inst));
        memcpy(&inst, (const char *)code + offset, sizeof(elk_compact_inst));
        bool compact = elk_inst_cmpt_control(device, &inst);
        unsigned size = compact ? sizeof(elk_compact_inst) : sizeof(elk_inst);
        assert(bytes - offset >= size);
        if (compact) {
            elk_compact_inst encoded;
            memcpy(&encoded, (const char *)code + offset, sizeof(encoded));
            elk_uncompact_instruction(&compiler->isa, &inst, &encoded);
        } else memcpy(&inst, (const char *)code + offset, sizeof(inst));
        enum elk_opcode op = elk_inst_opcode(&compiler->isa, &inst);
        if (elk_inst_dst_reg_file(device, &inst) == ELK_ARCHITECTURE_REGISTER_FILE &&
            elk_inst_dst_da_reg_nr(device, &inst) == ELK_ARF_CONTROL &&
            elk_inst_dst_da1_subreg_nr(device, &inst) == 0) {
            assert(elk_inst_src0_reg_file(device, &inst) == ELK_ARCHITECTURE_REGISTER_FILE &&
                   elk_inst_src0_da_reg_nr(device, &inst) == ELK_ARF_CONTROL &&
                   elk_inst_src0_da1_subreg_nr(device, &inst) == 0 &&
                   elk_inst_src1_reg_file(device, &inst) == ELK_IMMEDIATE_VALUE);
            assert(elk_inst_exec_size(device, &inst) == ELK_EXECUTE_1 &&
                   elk_inst_mask_control(device, &inst) == ELK_MASK_DISABLE &&
                   elk_inst_thread_control(device, &inst) == ELK_THREAD_SWITCH);
            uint32_t immediate = elk_inst_imm_ud(device, &inst);
            if (op == ELK_OPCODE_AND) {
                known |= ~immediate; value &= immediate;
                stats->clear += immediate == ~UINT32_C(0xb0);
            } else {
                assert(op == ELK_OPCODE_OR);
                known |= immediate; value |= immediate;
                stats->preserve += immediate == 0x80;
            }
            ++stats->writes;
            printf("STELA_INTEL_FP_CONTROL {\"target\":\"%s\",\"instruction\":%u,"
                   "\"op\":\"%s\",\"immediate\":%u,\"exec_size\":1,"
                   "\"thread_control\":%u,\"swsb_regdist\":0}\n", target, ordinal,
                   op == ELK_OPCODE_AND ? "and" : "or", immediate,
                   (unsigned)elk_inst_thread_control(device, &inst));
        }
        enum elk_reg_type dst = elk_inst_dst_type(device, &inst);
        enum elk_reg_type src = elk_inst_src0_type(device, &inst);
        bool arithmetic = (op == ELK_OPCODE_ADD || op == ELK_OPCODE_MUL ||
                           op == ELK_OPCODE_MAD || op == ELK_OPCODE_CMP) &&
            (dst == ELK_REGISTER_TYPE_F || src == ELK_REGISTER_TYPE_F);
        bool conversion = op == ELK_OPCODE_MOV && dst == ELK_REGISTER_TYPE_F &&
            (src == ELK_REGISTER_TYPE_D || src == ELK_REGISTER_TYPE_UD);
        if (arithmetic || conversion) {
            assert((known & 0xb0) == 0xb0 && (value & 0xb0) == (ftz ? 0u : 0x80u));
            stats->floating += arithmetic; stats->conversions += conversion;
        }
        offset += size;
    }
}
