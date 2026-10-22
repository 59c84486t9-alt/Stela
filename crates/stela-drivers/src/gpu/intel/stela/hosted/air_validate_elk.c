/* SPDX-License-Identifier: MIT */
#include "intel/compiler/elk/elk_eu.h"
#include "intel/compiler/elk/elk_compiler.h"
/* Own helper declaration also in air_compile.h; its BRW declarations cannot
 * be co-included with original ELK EU implementation enums. */
bool stela_intel_air_validate_elk(const struct elk_compiler *, const void *, uint32_t);
bool stela_intel_air_validate_elk(const struct elk_compiler *compiler, const void *code, uint32_t bytes)
{
    return compiler && code && bytes && bytes <= INT32_MAX &&
        elk_validate_instructions(&compiler->isa, code, 0, (int)bytes, NULL);
}
