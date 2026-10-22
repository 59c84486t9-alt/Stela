/* SPDX-License-Identifier: MIT */
#ifndef STELA_GUC_RESET_MODEL_H
#define STELA_GUC_RESET_MODEL_H
#include <linux/types.h>
#include "regs/xe_gt_regs.h"
#include "regs/xe_guc_regs.h"
#include "abi/guc_errors_abi.h"
struct reset_test_model;
struct reset_test_mmio { struct reset_test_model *owner; };
struct reset_test_event { uint32_t kind, reg, a, b, c; int64_t ns; };
struct reset_test_model {
    struct reset_test_mmio mmio;
    bool held, vf, wa, boot_valid, initial_reset, mia_reset, reset_written, idle_written;
    bool sram_started;
    int bootstrap_status;
    uint32_t warnings, errors, idle, gdrst_reads, gdrst_clear_read, events;
    uint64_t clear_us, ready_us, sram_us;
    int64_t ns, reset_at, idle_at, sram_at;
    struct reset_test_event trace[256];
};
u32 reset_test_read(struct reset_test_mmio *, struct xe_reg);
void reset_test_write(struct reset_test_mmio *, struct xe_reg, u32);
u32 reset_test_rmw(struct reset_test_mmio *, struct xe_reg, u32, u32);
int reset_test_wait(struct reset_test_mmio *, struct xe_reg, u32, u32, u32, u32 *, bool);
void reset_test_assert(struct reset_test_model *, unsigned);
void reset_test_diagnostic(struct reset_test_model *, const char *, u32);
int reset_test_bootstrap(struct reset_test_model *);
bool reset_test_wa(struct reset_test_model *, uint64_t);
int reset_donor(struct reset_test_model *);
int reset_linux(struct reset_test_model *);
#endif
