/* SPDX-License-Identifier: MIT */
#include "legacy_elk_validate.h"
#include "intel/compiler/elk/elk_eu.h"
#include "intel/compiler/elk/elk_compiler.h"

/* BRW/ELK EU implementation enums intentionally live in separate TUs. */
bool stela_legacy_elk_code_valid(const struct elk_compiler *compiler, const void *code,
                                unsigned bytes)
{
    return elk_validate_instructions(&compiler->isa, code, 0, bytes, NULL);
}
