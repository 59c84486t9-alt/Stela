/* SPDX-License-Identifier: MIT */
#include "sampler_internal.h"
#define __gen_address_type uint64_t
#define __gen_user_data void
static inline uint64_t combine_address(void *data, void *location,
                                       uint64_t address, uint32_t delta)
{
    (void)data; (void)location;
    return address + delta;
}
#define __gen_combine_address combine_address
#include "intel/genxml/gen_macros.h"
#include "intel/genxml/genX_pack.h"

/* This is only a zero-init/generated-pack call scope, without Iris batch/BO
 * address handling. The hardware field policy itself remains in the original
 * shared Iris helper; the actual bit algorithm remains in its XML packer. */
#define sampler_generated_pack(cmd) cmd##_pack
#define iris_pack_state(cmd, dst, name) \
    for (struct cmd name = {0}, *_once = &name; _once != NULL; \
         sampler_generated_pack(cmd)(NULL, (void *)(dst), &name), _once = NULL)
#include "gallium/drivers/iris/iris_sampler_state.h"
#undef iris_pack_state
#undef sampler_generated_pack

_Static_assert(GENX(SAMPLER_STATE_length) == STELA_INTEL_SAMPLER_STATE_DWORDS,
               "Actual sampler state must match the owned output ABI");

void STELA_SAMPLER_PACK(const struct pipe_sampler_state *sampler, uint32_t *output)
{
    fill_sampler_state(output, sampler, sampler->max_anisotropy);
}
