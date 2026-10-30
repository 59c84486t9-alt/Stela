/* SPDX-License-Identifier: MIT */
#ifndef STELA_METAL_THREADGROUP_H
#define STELA_METAL_THREADGROUP_H
#include "air_metadata.h"
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define STELA_METAL_THREADGROUP_ABI 1u
#define STELA_METAL_THREADGROUP_ALIGNMENT 16u

/* Same-process borrowed values, never an IPC wire format or resource authority.
 * The real encoder supplies its selected entry's requested byte lengths from
 * setThreadgroupMemoryLength:atIndex:. Unrelated encoder bindings are omitted.
 * Zero/unknown lengths remain unsupported by the current nonempty-view frontend.
 * All reserved fields must be zero. Storage is valid/disjoint/serialized. */
struct stela_metal_threadgroup_request_row {
    uint32_t index, reserved;
    uint64_t bytes;
};
struct stela_metal_threadgroup_request {
    uint32_t size, abi, count, reserved;
    const struct stela_metal_threadgroup_request_row *rows;
};
struct stela_metal_threadgroup_binding {
    struct stela_air_buffer buffer;
    uint64_t bytes;
    uint32_t alignment;
};
/* Copied fixed-size normalized identity in AIR metadata order, including unused
 * declared AS3 arguments. Backend total shared memory includes this dynamic
 * specialization and layout padding: it is NOT staticThreadgroupMemoryLength.
 * Neither total-minus-requested-lengths nor a hardware capability is inferred.
 * Source/static accounting and a public Metal PSO remain separate contracts. */
struct stela_metal_threadgroup_specialization {
    uint32_t count;
    struct stela_metal_threadgroup_binding bindings[AIR_MAX_ARGUMENTS];
};
enum stela_metal_threadgroup_status {
    STELA_METAL_THREADGROUP_OK,
    STELA_METAL_THREADGROUP_INVALID,
    STELA_METAL_THREADGROUP_UNSUPPORTED,
    STELA_METAL_THREADGROUP_LIMIT,
};
/* No allocation or lowering. The explicit limit is the actual backend's shared
 * byte representation/capacity; original NIR additionally checks combined static
 * and dynamic aligned layout. Failure leaves output unchanged. NULL request
 * means no supplied lengths, and succeeds only when there are no declared AS3
 * arguments. Successful storage owns no input pointers. */
enum stela_metal_threadgroup_status stela_metal_threadgroup_normalize(
    const struct stela_air_argument_info *, uint32_t argument_count,
    const struct stela_metal_threadgroup_request *, uint32_t max_bytes,
    struct stela_metal_threadgroup_specialization *output);

/* Exact selected dispatch value comparison only, independent of row ordering.
 * Target/compiler/options/workgroup/profile and all input identities remain
 * separate required cache keys. This establishes no device/VM ownership,
 * reservation, memory visibility, lifetime, submission or completion. */
bool stela_metal_threadgroup_matches(const struct stela_metal_threadgroup_specialization *,
                                    const struct stela_metal_threadgroup_request *);
#ifdef __cplusplus
}
#endif
#endif
