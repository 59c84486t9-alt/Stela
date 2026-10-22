/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_WOPCM_DONOR_H
#define STELA_INTEL_WOPCM_DONOR_H
#include "../../xe/xe_scalar_types.h"
#include "../../xe/xe_platform_types.h"
#include "../../xe/xe_wopcm_types.h"
#include "../../xe/regs/xe_guc_regs.h"
#include <pthread.h>
struct stela_wopcm_record { uint32_t kind, a, b, c; };
struct stela_wopcm_model {
    enum xe_platform platform;
    bool discrete, huc_available;
    uint32_t guc_fw_size, huc_fw_size, reg_offset, reg_size;
    unsigned fail_write, writes, used;
    pthread_mutex_t *lock;
    struct stela_wopcm_record records[64];
};
void stela_wopcm_record(struct stela_wopcm_model *, uint32_t, uint32_t, uint32_t, uint32_t);
u32 stela_wopcm_read(struct stela_wopcm_model *, struct xe_reg);
void stela_wopcm_write(struct stela_wopcm_model *, struct xe_reg, u32);
void stela_wopcm_assert(struct stela_wopcm_model *);
bool stela_wopcm_huc(struct stela_wopcm_model *);
int stela_wopcm_donor(struct stela_wopcm_model *, struct xe_wopcm *);
bool stela_wopcm_donor_role(bool media_gt, unsigned graphics_verx100);
#endif
