/* SPDX-License-Identifier: MIT */
#include "intel/compiler/elk/elk_eu.h"
#include "intel/compiler/elk/elk_compiler.h"
#include <string.h>
/* Own helper declarations, also in air_compile.h and air_graphics.h; their BRW
 * declarations cannot be co-included with original ELK EU implementation enums. */
bool stela_intel_air_validate_elk(const struct elk_compiler *, const void *, uint32_t);
bool stela_intel_graphics_validate_elk(const struct elk_compiler *, const void *, uint32_t, unsigned);
bool stela_intel_air_validate_elk(const struct elk_compiler *compiler, const void *code, uint32_t bytes)
{
    return compiler && code && bytes && bytes <= INT32_MAX &&
        elk_validate_instructions(&compiler->isa, code, 0, (int)bytes, NULL);
}
/* Like original generate_code, validate every instruction and control-flow
 * path, not only a prefix through the first EOT. elk_realign/elk_append_data
 * zero-fill only up to the following variant's or data's alignment, so the
 * program ends at the first instruction boundary inside its zero suffix and
 * that suffix must be exactly the alignment padding. Compact NOP tails remain
 * instructions, as in the original compactor. */
bool stela_intel_graphics_validate_elk(const struct elk_compiler *compiler,
    const void *code, uint32_t bytes, unsigned end_alignment)
{
    if (!compiler || !code || !bytes || bytes > INT32_MAX || (bytes & 7) ||
        (end_alignment != 16 && end_alignment != 32 && end_alignment != 64)) return false;
    const uint8_t *data = code;
    uint32_t nonzero = bytes;
    while (nonzero && !data[nonzero - 1]) --nonzero;
    uint32_t offset = 0;
    while (offset < nonzero) {
        elk_inst instruction = {0};
        if (bytes - offset < sizeof(elk_compact_inst)) return false;
        memcpy(&instruction, data + offset, sizeof(elk_compact_inst));
        unsigned size = elk_inst_cmpt_control(compiler->devinfo, &instruction) ?
            sizeof(elk_compact_inst) : sizeof(elk_inst);
        if (bytes - offset < size) return false;
        offset += size;
    }
    return offset && ((offset + end_alignment - 1) & ~(end_alignment - 1)) == bytes &&
        elk_validate_instructions(&compiler->isa, code, 0, (int)offset, NULL);
}
