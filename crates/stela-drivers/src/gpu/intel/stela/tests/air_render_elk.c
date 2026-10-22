/* SPDX-License-Identifier: MIT */
#include "intel/compiler/elk/elk_compiler.h"
#include "intel/compiler/elk/elk_eu.h"
#include "intel/compiler/elk/elk_disasm.h"
#include <string.h>

bool stela_intel_render_elk_valid(const struct elk_compiler *, const void *, unsigned, FILE *);

static bool finish(const struct elk_compiler *compiler, const void *code, unsigned bytes, FILE *out)
{
    if (!elk_validate_instructions(&compiler->isa, code, 0, bytes, NULL)) return false;
    if (out) elk_disassemble_with_labels(&compiler->isa, code, 0, bytes, out);
    return true;
}

/* The original Gen7/8 decoder and uncompactor have separate implementation
 * enums from BRW. Locate the actual EOT with those helpers, validate its whole
 * instruction span, and require original inter-kernel alignment bytes be zero.
 */
bool stela_intel_render_elk_valid(const struct elk_compiler *compiler, const void *code,
                                 unsigned bytes, FILE *out)
{
    const struct intel_device_info *dev = compiler->devinfo;
    bool eot = false;
    unsigned validated = 0;
    for (unsigned offset = 0; offset < bytes;) {
        if (eot) {
            bool zero = true;
            for (unsigned i = offset; i < bytes; i++) zero &= !((const uint8_t *)code)[i];
            if (zero) return finish(compiler, code, validated, out);
        }
        elk_inst in = {0};
        if (bytes - offset < sizeof(elk_compact_inst)) return false;
        memcpy(&in, (const uint8_t *)code + offset, sizeof(elk_compact_inst));
        bool compact = elk_inst_cmpt_control(dev, &in);
        unsigned size = compact ? sizeof(elk_compact_inst) : sizeof(elk_inst);
        if (bytes - offset < size) return false;
        if (compact) {
            elk_compact_inst encoded; memcpy(&encoded, &in, sizeof(encoded));
            elk_uncompact_instruction(&compiler->isa, &in, &encoded);
        } else memcpy(&in, (const uint8_t *)code + offset, sizeof(in));
        offset += size;
        enum elk_opcode op = elk_inst_opcode(&compiler->isa, &in);
        if (eot && op != ELK_OPCODE_NOP) return false;
        eot |= (op == ELK_OPCODE_SEND || op == ELK_OPCODE_SENDC) && elk_inst_eot(dev, &in);
        validated = offset;
    }
    return eot && finish(compiler, code, validated, out);
}
