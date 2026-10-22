/* SPDX-License-Identifier: MIT */
/* Xe's MI packets, from the unchanged Linux xe_ring_ops.c emitters. */
#include "commands.h"
#include <stela/linux.h>
#include <unsupported.h>

#include "xe_ring_ops.c"

/* The packet emitters these primitives call touch no job, queue or context. */
STELA_UNSUPPORTED(u32, xe_lrc_ctx_job_timestamp_ggtt_addr, struct xe_lrc *)
STELA_UNSUPPORTED(u32, xe_lrc_ctx_timestamp_ggtt_addr, struct xe_lrc *)
STELA_UNSUPPORTED(u32, xe_lrc_ggtt_addr, struct xe_lrc *)
STELA_UNSUPPORTED(u32, xe_lrc_seqno_ggtt_addr, struct xe_lrc *)
STELA_UNSUPPORTED(u32, xe_lrc_start_seqno_ggtt_addr, struct xe_lrc *)
STELA_UNSUPPORTED(void, xe_lrc_write_ring, struct xe_lrc *, const void *, size_t)
STELA_UNSUPPORTED(bool, xe_sched_job_is_migration, struct xe_exec_queue *)

#define INVALID_ARGUMENT (-22)
#define NO_SPACE (-28)

static int reserve(const struct stela_intel_commands *commands, size_t count)
{
    if (!commands || !commands->words || commands->used > commands->capacity ||
        commands->capacity > SIZE_MAX / sizeof(uint32_t) ||
        (commands->address_bits != 48 && commands->address_bits != 57))
        return INVALID_ARGUMENT;
    if (count > commands->capacity - commands->used)
        return NO_SPACE;
    return 0;
}

static bool valid_address(const struct stela_intel_commands *commands,
                          uint64_t address, uint64_t alignment)
{
    return !(address & (alignment - 1)) && address < (UINT64_C(1) << commands->address_bits);
}

int stela_intel_batch_start(struct stela_intel_commands *commands, uint64_t address, bool ppgtt)
{
    int err = reserve(commands, 3);
    if (err) return err;
    if (!valid_address(commands, address, 4)) return INVALID_ARGUMENT;
    stela_linux_enter(&stela_linux_bare);
    (void)emit_bb_start(address, ppgtt ? BIT(8) : 0, commands->words + commands->used, 0);
    stela_linux_exit();
    commands->used += 3;
    return 0;
}

int stela_intel_store_qword(struct stela_intel_commands *commands, uint64_t address, uint64_t value)
{
    int err = reserve(commands, 5);
    if (err) return err;
    /* MI_STORE_DATA_IMM has a 48-bit address field, even with a 57-bit VM. */
    if (!valid_address(commands, address, 8) || address >= (UINT64_C(1) << 48))
        return INVALID_ARGUMENT;
    stela_linux_enter(&stela_linux_bare);
    (void)emit_store_imm_ppgtt_posted(address, value, commands->words + commands->used, 0);
    stela_linux_exit();
    commands->used += 5;
    return 0;
}

int stela_intel_batch_end(struct stela_intel_commands *commands)
{
    int err = reserve(commands, 1);
    if (err) return err;
    commands->words[commands->used++] = MI_BATCH_BUFFER_END;
    return 0;
}

int stela_intel_user_interrupt(struct stela_intel_commands *commands)
{
    int err = reserve(commands, 3);
    if (err) return err;
    stela_linux_enter(&stela_linux_bare);
    (void)emit_user_interrupt(commands->words + commands->used, 0);
    stela_linux_exit();
    commands->used += 3;
    return 0;
}
