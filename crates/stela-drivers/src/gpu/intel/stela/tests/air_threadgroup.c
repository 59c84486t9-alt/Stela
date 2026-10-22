/* SPDX-License-Identifier: MIT */
#include "air_to_nir.h"
#include "air_probe_input.h"
#include "air_threadgroup_elk.h"
#include "legacy_elk_validate.h"
#include "../hosted/compute.h"
#include "../hosted/legacy_compute.h"
#include "intel/common/intel_common.h"
#include "intel/common/intel_compute_slm.h"
#include "intel/compiler/brw/brw_nir.h"
#include "intel/compiler/brw/brw_eu.h"
#include "intel/compiler/elk/elk_nir.h"
#include "intel/dev/intel_debug.h"
#include "stela/tests/intel_probe.h"
#include "stela/tests/targets/intel.h"
#include "threadgroup_bits.h"
#include "util/ralloc.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* Offline compiler/resource-policy qualification. The raw module is never
 * edited. Its caller supplies the exact workgroup/dynamic-AS3 specialization;
 * placements below are explicitly model offsets, with no actual GPU mappings,
 * submission, SLM ownership, cache transition or completion being fabricated.
 */
struct binding {
    unsigned workgroup, shared, dynamic_index;
    unsigned buffers, threadgroups, rejection;
};

static void compiler_log(void *data, unsigned *id, const char *format, ...)
{
    (void)data; (void)id;
    va_list args; va_start(args, format); vfprintf(stderr, format, args); va_end(args);
}

static bool bind_buffer(const struct stela_air_buffer *desc, unsigned *slot, void *data)
{
    struct binding *b = data;
    if (b->buffers || desc->address_space != 1 || desc->index != 7 ||
        desc->access != STELA_AIR_READ_WRITE || desc->type_size != 4 || desc->type_alignment != 4)
        return false;
    ++b->buffers; *slot = 0;
    return true;
}

static bool bind_threadgroup(const struct stela_air_buffer *desc,
                             struct stela_air_threadgroup_view *view, void *data)
{
    struct binding *b = data;
    if (b->threadgroups || desc->address_space != 3 || desc->index != b->dynamic_index ||
        desc->access != STELA_AIR_READ_WRITE || desc->type_size != 4 || desc->type_alignment != 4)
        return false;
    ++b->threadgroups;
    *view = (struct stela_air_threadgroup_view){b->shared, 4, STELA_AIR_READ_WRITE};
    switch (b->rejection) {
    case 1: view->size = 0; break;
    case 2: view->alignment = 3; break;
    case 3: view->available_access = STELA_AIR_READ; break;
    case 4: return false;
    }
    return true;
}

static nir_shader *lower(const nir_shader_compiler_options *options, LLVMMemoryBufferRef input,
                          const char *entry, struct binding *b, unsigned limit,
                          struct stela_air_error *error)
{
    const struct stela_air_options air = {
        .workgroup_size = {b->workgroup, 1, 1}, .max_instructions = 1000,
        .bind_ssbo = bind_buffer, .ssbo_count = 1, .binding_data = b,
        .bind_threadgroup = bind_threadgroup, .max_threadgroup_bytes = limit,
    };
    return stela_air_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                             entry, options, &air, error);
}

static void check_refusals(const nir_shader_compiler_options *options, LLVMMemoryBufferRef input,
                           const char *entry, const struct binding *specialization)
{
    /* Refuse a missing/exceeded backend limit and invalid actual dynamic view
     * contracts without changing a single byte of the original source input.
     */
    for (unsigned i = 0; i < (specialization->dynamic_index == UINT32_MAX ? 2u : 6u); ++i) {
        struct binding b = *specialization;
        unsigned limit = b.shared;
        if (i == 0) limit = 0;
        else if (i == 1) --limit;
        else b.rejection = i - 1;
        struct stela_air_error error;
        nir_shader *nir = lower(options, input, entry, &b, limit, &error);
        assert(!nir && error.kind != STELA_AIR_OK);
    }
}

static nir_shader *input_shader(const nir_shader_compiler_options *options,
                                 LLVMMemoryBufferRef input, const char *entry,
                                 const struct binding *specialization, unsigned limit)
{
    check_refusals(options, input, entry, specialization);
    struct binding b = *specialization;
    struct stela_air_error error;
    nir_shader *nir = lower(options, input, entry, &b, limit, &error);
    if (!nir) fprintf(stderr, "AIR threadgroup: %s\n", error.detail);
    assert(nir && error.kind == STELA_AIR_OK && b.buffers == 1);
    assert(b.threadgroups == (b.dynamic_index != UINT32_MAX));
    assert(nir->info.shared_size == b.shared && nir->info.num_ssbos == 1);
    unsigned loads = 0, stores = 0, barriers = 0;
    nir_foreach_function_impl(impl, nir) nir_foreach_block(block, impl)
        nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic) continue;
            nir_intrinsic_instr *intr = nir_instr_as_intrinsic(instr);
            loads += intr->intrinsic == nir_intrinsic_load_shared;
            stores += intr->intrinsic == nir_intrinsic_store_shared;
            if (intr->intrinsic == nir_intrinsic_barrier) {
                assert(nir_intrinsic_execution_scope(intr) == SCOPE_WORKGROUP &&
                       nir_intrinsic_memory_scope(intr) == SCOPE_WORKGROUP &&
                       nir_intrinsic_memory_semantics(intr) == NIR_MEMORY_ACQ_REL &&
                       nir_intrinsic_memory_modes(intr) == nir_var_mem_shared);
                ++barriers;
            }
        }
    assert(loads && stores && barriers);
    return nir;
}

static void brw_stats(const struct intel_device_info *dev, void *context, const void *code,
                       unsigned bytes, struct stela_intel_shared_stats *stats)
{
    gen_decode_params decoded = {.devinfo = dev, .raw_bytes = code,
        .raw_bytes_size = bytes, .mem_ctx = context};
    assert(gen_decode(&decoded));
    bool wait_pending = false;
    for (int i = 0; i < decoded.num_insts; ++i) {
        const gen_inst *inst = &decoded.insts[i];
        if (wait_pending) {
            assert(inst->no_mask);
            assert(dev->ver >= 12 ? inst->opcode == GEN_OP_SYNC && inst->sync.func == GEN_SYNC_BAR :
                                   inst->opcode == GEN_OP_WAIT && inst->exec_size == 1);
            ++stats->waits; wait_pending = false;
        }
        stela_intel_shared_order(stats, i + 1);
        if (inst->opcode != GEN_OP_SEND && inst->opcode != GEN_OP_SENDC &&
            inst->opcode != GEN_OP_SENDS && inst->opcode != GEN_OP_SENDSC) continue;
        /* Original brw_shader::emit_cs_terminate also uses the gateway on
         * Gen12.5+. Its EOT is not a workgroup barrier. */
        if (inst->send.eot) continue;
        if (inst->send.sfid == GEN_SFID_MESSAGE_GATEWAY) {
            assert(!inst->send.desc_is_reg && inst->no_mask);
            assert(inst->send.desc_imm == (brw_message_desc(dev, reg_unit(dev), 0, false) |
                                           GEN_MESSAGE_GATEWAY_SFID_BARRIER_MSG));
            ++stats->barriers; wait_pending = true;
        } else if (inst->send.sfid == GEN_SFID_SLM) {
            assert(!inst->send.desc_is_reg);
            gen_lsc_desc desc = gen_lsc_desc_decode(dev, inst->send.desc_imm);
            stats->loads += desc.op == LSC_OP_LOAD || desc.op == LSC_OP_LOAD_CMASK;
            stats->stores += desc.op == LSC_OP_STORE || desc.op == LSC_OP_STORE_CMASK;
            stats->fences += desc.op == LSC_OP_FENCE;
            if (desc.op == LSC_OP_FENCE)
                /* Original lower_lsc_memory_fence rebuilds the final SEND
                 * descriptor with backup routing false. The earlier logical
                 * descriptor's routing bit is not the emitted instruction. */
                assert(desc.fence.scope == LSC_FENCE_THREADGROUP &&
                       desc.fence.flush_type == LSC_FLUSH_TYPE_NONE && !desc.fence.route_to_lsc);
        } else if (inst->send.sfid == GEN_SFID_HDC0 || inst->send.sfid == GEN_SFID_HDC1) {
            assert(!inst->send.desc_is_reg);
            gen_hdc_desc desc = gen_hdc_desc_decode(dev, inst->send.desc_imm);
            stats->fences += inst->send.sfid == GEN_SFID_HDC0 &&
                              desc.msg_type == GEN_DATAPORT_DC_MEMORY_FENCE;
            if (desc.bti == GEN_BTI_SLM) {
                if (inst->send.sfid == GEN_SFID_HDC1) {
                    stats->loads += desc.msg_type == GEN_DATAPORT_DC_PORT1_UNTYPED_SURFACE_READ;
                    stats->stores += desc.msg_type == GEN_DATAPORT_DC_PORT1_UNTYPED_SURFACE_WRITE;
                } else {
                    stats->loads += desc.msg_type == GEN_DATAPORT_DC_DWORD_SCATTERED_READ ||
                                    desc.msg_type == GEN_DATAPORT_DC_BYTE_SCATTERED_READ;
                    stats->stores += desc.msg_type == GEN_DATAPORT_DC_DWORD_SCATTERED_WRITE ||
                                     desc.msg_type == GEN_DATAPORT_DC_BYTE_SCATTERED_WRITE;
                }
            }
        }
        stela_intel_shared_order(stats, i + 1);
    }
    assert(!wait_pending);
}

static uint32_t field(const uint32_t *words, unsigned start, unsigned bits)
{
    assert(bits && bits <= 32 && start % 32 + bits <= 32);
    return (words[start / 32] >> (start % 32)) & (UINT32_MAX >> (32 - bits));
}

static void check_plan(const struct brw_compiler *brw, const struct elk_compiler *elk,
                       const struct isl_device *isl, const struct brw_cs_prog_data *bd,
                       const struct elk_cs_prog_data *ed, const struct shader_info *shader,
                       const char *target, const char *entry, const struct binding *specialization,
                       const void *code, const struct stela_intel_shared_stats *stats)
{
    const struct intel_device_info *dev = isl->info;
    unsigned bytes = brw ? bd->base.program_size : ed->base.program_size;
    unsigned shared = brw ? bd->base.total_shared : ed->base.total_shared;
    bool barrier = brw ? bd->uses_barrier : ed->uses_barrier;
    assert(shared == specialization->shared && barrier);
    struct intel_cs_dispatch_info dispatch = brw ? brw_cs_get_dispatch_info(dev, bd, NULL) :
                                                  elk_cs_get_dispatch_info(dev, ed, NULL);
    assert(dispatch.group_size == specialization->workgroup && dispatch.simd_size == 16 &&
           dispatch.threads == specialization->workgroup / 16);
    unsigned encoded = intel_compute_slm_encode_size(dev->ver, shared);
    unsigned allocated = intel_compute_slm_calculate_size(dev->ver, shared);
    assert(allocated >= shared && allocated <= intel_device_info_get_max_slm_size(dev));
    const uint32_t groups[] = {3, 5, 7};
    const struct stela_intel_legacy_placement legacy_placement = {
        .code_offset = 0x1000, .code_span = bytes,
        .binding_table_offset = 0x2000, .binding_table_span = 4, .binding_table_entries = 1,
        .curbe_offset = 0x4000, .curbe_span = 2048, .descriptor_offset = 0x5000, .descriptor_span = 32,
    };
    uint32_t words[44]; memset(words, 0xa5, sizeof(words));
    struct stela_intel_commands commands = {words, ARRAY_SIZE(words), 1, 48};
    unsigned native_slm, native_barrier, preferred = 0, push_bytes = 0;
    if (dev->verx10 >= 125) {
        const struct stela_intel_compute_placement placement = {
            .code_offset = 0x1000, .code_span = bytes,
            .binding_table_offset = 0x2000, .binding_table_span = 4, .binding_table_entries = 1,
        };
        struct stela_intel_compute_plan plan, before;
        /* Dynamic AS3 has already become total_shared; adding it here again
         * as variable SLM would silently allocate a different specialization.
         */
        assert(stela_intel_compute_plan(brw, isl, bd, shader, &placement, groups, 0, &plan) == 0);
        assert(plan.requirements.slm_bytes_per_group == allocated &&
               plan.dispatch.slm_encoding == encoded && plan.dispatch.barrier_encoding == 1);
        preferred = intel_compute_preferred_slm_calc_encode_size(dev, shared, dispatch.group_size,
                                                                 dispatch.simd_size);
        assert(plan.dispatch.preferred_slm_encoding == preferred);
        assert(stela_intel_compute_dispatch(&commands, &plan.dispatch) == 0);
        assert(commands.used == 1 + COMPUTE_WALKER_length(dev));
        unsigned base = 32 + COMPUTE_WALKER_body_start(dev) +
                             COMPUTE_WALKER_BODY_InterfaceDescriptor_start(dev);
        native_slm = field(words, base + INTERFACE_DESCRIPTOR_DATA_SharedLocalMemorySize_start(dev),
                            INTERFACE_DESCRIPTOR_DATA_SharedLocalMemorySize_bits(dev));
        native_barrier = field(words, base + INTERFACE_DESCRIPTOR_DATA_NumberOfBarriers_start(dev),
                                INTERFACE_DESCRIPTOR_DATA_NumberOfBarriers_bits(dev));
        assert(field(words, base + INTERFACE_DESCRIPTOR_DATA_PreferredSLMAllocationSize_start(dev),
                     INTERFACE_DESCRIPTOR_DATA_PreferredSLMAllocationSize_bits(dev)) == preferred);
        assert(field(words, base + INTERFACE_DESCRIPTOR_DATA_NumberofThreadsinGPGPUThreadGroup_start(dev),
                     INTERFACE_DESCRIPTOR_DATA_NumberofThreadsinGPGPUThreadGroup_bits(dev)) == dispatch.threads);
        memset(&before, 0xa5, sizeof(before)); plan = before;
        for (unsigned i = 0; i < 2; ++i) {
            struct brw_cs_prog_data bad = *bd;
            bad.base.total_shared = i ? UINT32_MAX : intel_device_info_get_max_slm_size(dev) + 1;
            assert(stela_intel_compute_plan(brw, isl, &bad, shader, &placement, groups, 0, &plan) != 0);
            assert(!memcmp(&plan, &before, sizeof(plan)));
        }
    } else {
        struct stela_intel_legacy_plan plan, before;
        assert((brw ? stela_intel_legacy_brw_plan(brw, isl, bd, shader, &legacy_placement, groups, 0, &plan) :
                      stela_intel_legacy_elk_plan(elk, isl, ed, shader, &legacy_placement, groups, &plan)) == 0);
        assert(plan.slm_bytes_per_group == allocated);
        push_bytes = plan.curbe_bytes;
        native_slm = field(plan.descriptor, INTERFACE_DESCRIPTOR_DATA_SharedLocalMemorySize_start(dev),
                            INTERFACE_DESCRIPTOR_DATA_SharedLocalMemorySize_bits(dev));
        native_barrier = field(plan.descriptor, INTERFACE_DESCRIPTOR_DATA_BarrierEnable_start(dev),
                                INTERFACE_DESCRIPTOR_DATA_BarrierEnable_bits(dev));
        assert(field(plan.descriptor, INTERFACE_DESCRIPTOR_DATA_NumberofThreadsinGPGPUThreadGroup_start(dev),
                     INTERFACE_DESCRIPTOR_DATA_NumberofThreadsinGPGPUThreadGroup_bits(dev)) == dispatch.threads);
        assert(stela_intel_gpgpu_dispatch(&commands, &plan.dispatch) == 0 &&
               commands.used == 1 + plan.walker_words &&
               !memcmp(words + 1, plan.walker, plan.walker_words * 4));
        assert(plan.curbe_bytes >= 32 * dispatch.threads);
        for (unsigned i = 0; i < dispatch.threads; ++i) assert(plan.curbe[i * 8] == i);
        memset(&before, 0xa5, sizeof(before)); plan = before;
        for (unsigned i = 0; i < 2; ++i) {
            int status;
            unsigned rejected = i ? UINT32_MAX : intel_device_info_get_max_slm_size(dev) + 1;
            if (brw) {
                struct brw_cs_prog_data bad = *bd; bad.base.total_shared = rejected;
                status = stela_intel_legacy_brw_plan(brw, isl, &bad, shader, &legacy_placement, groups, 0, &plan);
            } else {
                struct elk_cs_prog_data bad = *ed; bad.base.total_shared = rejected;
                status = stela_intel_legacy_elk_plan(elk, isl, &bad, shader, &legacy_placement, groups, &plan);
            }
            assert(status != 0 && !memcmp(&plan, &before, sizeof(plan)));
        }
    }
    assert(native_slm == encoded && native_barrier == 1);
    assert(words[0] == UINT32_C(0xa5a5a5a5) && words[commands.used] == UINT32_C(0xa5a5a5a5));
    record_compiled(target, bytes);
    record_object("facts");
    record_str("entry", entry);
    record_uint("pci_id", dev->pci_device_id);
    record_uint("workgroup", specialization->workgroup);
    record_uint("shared_bytes", shared);
    record_uint("slm_limit", intel_device_info_get_max_slm_size(dev));
    record_uint("allocated_slm", allocated);
    record_uint("slm_encoding", native_slm);
    record_uint("preferred_slm_encoding", preferred);
    record_uint("barrier_encoding", native_barrier);
    record_uint("simd", dispatch.simd_size);
    record_uint("threads", dispatch.threads);
    record_uint("curbe_bytes", push_bytes);
    record_uint("ssbo_count", 1);
    record_uint("metal_buffer_index", 7);
    record_int("dynamic_threadgroup_index",
               specialization->dynamic_index == UINT32_MAX ? -1 : (int)specialization->dynamic_index);
    record_uint("extra_variable_slm", 0);
    record_uint("shared_loads", stats->loads);
    record_uint("shared_stores", stats->stores);
    record_uint("fences", stats->fences);
    record_uint("barriers", stats->barriers);
    record_uint("waits", stats->waits);
    record_blake3("code_blake3", code, bytes);
    record_end();
}

/* Exercise the producer's actual Gen35 refusal before any compilation; no
 * shader metadata is represented as a compiled Gen35 program. */
static void held(const char *target, const struct intel_device_info *dev)
{
    struct isl_device isl = {0}; isl_device_init(&isl, dev);
    void *context = ralloc_context(NULL);
    struct brw_compiler *compiler = brw_compiler_create(context, dev);
    const struct brw_cs_prog_data uncompiled = {0};
    const struct shader_info shader = {.stage = MESA_SHADER_COMPUTE};
    const struct stela_intel_compute_placement placement = {0};
    const uint32_t groups[] = {1, 1, 1};
    struct stela_intel_compute_plan plan, before;
    memset(&before, 0xa5, sizeof(before)); plan = before;
    assert(stela_intel_compute_plan(compiler, &isl, &uncompiled, &shader,
                                    &placement, groups, 0, &plan) == -95);
    assert(!memcmp(&plan, &before, sizeof(plan)));
    ralloc_free(context);
    record_held(target, stela_intel_hold(dev));
}

static void compile(const char *target, const struct intel_device_info *device, LLVMMemoryBufferRef input,
                     const char *entry, const struct binding *specialization)
{
    const struct intel_device_info dev = *device; const bool use_elk = stela_intel_elk(&dev);
    struct isl_device isl = {0}; isl_device_init(&isl, &dev);
    void *context = ralloc_context(NULL);
    struct brw_compiler *brw = use_elk ? NULL : brw_compiler_create(context, &dev);
    struct elk_compiler *elk = use_elk ? elk_compiler_create(context, &dev) : NULL;
    if (brw) brw->shader_debug_log = brw->shader_perf_log = compiler_log;
    if (elk) elk->shader_debug_log = elk->shader_perf_log = compiler_log;
    const nir_shader_compiler_options *options = brw ? &brw->nir_options[MESA_SHADER_COMPUTE] :
                                                                     elk->nir_options[MESA_SHADER_COMPUTE];
    nir_shader *nir = input_shader(options, input, entry, specialization,
                                   intel_device_info_get_max_slm_size(&dev));
    if (brw) {
        const struct brw_nir_compiler_opts opts = {0}; brw_preprocess_nir(brw, nir, &opts);
    } else {
        const struct elk_nir_compiler_opts opts = {0}; elk_preprocess_nir(elk, nir, &opts);
    }
    const nir_lower_compute_system_values_options sys = {.has_base_workgroup_id = false};
    NIR_PASS(_, nir, nir_lower_compute_system_values, &sys);
    nir_shader_gather_info(nir, nir_shader_get_entrypoint(nir));
    nir->info.min_subgroup_size = nir->info.max_subgroup_size = 16;
    struct brw_cs_prog_data bd = {0}; struct elk_cs_prog_data ed = {0};
    const unsigned *code;
    if (brw) {
        struct brw_cs_prog_key key = {0};
        brw_nir_lower_cs_intrinsics(nir, &dev, &bd);
        if (brw_nir_lower_cs_subgroup_id(nir, &dev, 0)) {
            bd.base.push_sizes[0] = 4;
            brw_cs_fill_push_const_info(&dev, &bd, 0); bd.base.push_sizes[0] = align(4, REG_SIZE);
        } else brw_cs_fill_push_const_info(&dev, &bd, -1);
        nir_validate_shader(nir, "AIR threadgroup original BRW compile");
        struct brw_compile_cs_params p = {.base = {.mem_ctx = context, .nir = nir,
            .key = &key.base, .prog_data = &bd.base}};
        code = brw_compile(brw, &p.base);
        if (!code) fprintf(stderr, "%s: %s\n", target, p.base.error_str);
        assert(code && !p.base.error_str);
        unsigned sends;
        assert(validate_intel_code(&dev, context, code, bd.base.program_size, target, &sends));
        assert(bd.uses_fence);
    } else {
        struct elk_cs_prog_key key = {0}; elk_nir_lower_cs_intrinsics(nir, &dev, &ed);
        nir_validate_shader(nir, "AIR threadgroup original ELK compile");
        struct elk_compile_cs_params p = {.base = {.mem_ctx = context, .nir = nir},
            .key = &key, .prog_data = &ed};
        code = elk_compile_cs(elk, &p);
        if (!code) fprintf(stderr, "%s: %s\n", target, p.base.error_str);
        assert(code && !p.base.error_str && stela_legacy_elk_code_valid(elk, code, ed.base.program_size));
    }
    struct stela_intel_shared_stats stats = {0};
    if (elk) stela_intel_elk_shared_stats(elk, code, ed.base.program_size, &stats);
    else brw_stats(&dev, context, code, bd.base.program_size, &stats);
    assert(stats.loads && stats.stores && stats.fences && stats.barriers && stats.waits == stats.barriers);
    assert(stats.barriers == 1 && stats.first_store < stats.first_fence &&
           stats.first_fence < stats.first_barrier && stats.first_barrier < stats.first_wait &&
           stats.first_wait < stats.first_load);
    check_plan(brw, elk, &isl, &bd, &ed, &nir->info, target, entry, specialization, code, &stats);
    ralloc_free(nir); ralloc_free(context);
}

int main(int argc, char **argv)
{
    /* Deliberately bounded test specializations, not a production Metal parser.
     * Static modules take 'none'; AS3 index3 is genuine Apple input, index7 is
     * the original LLVM namespace-separation fixture. Ordinary AS1 is index7.
     */
    if (argc != 11 || strcmp(argv[5], "--workgroup") || strcmp(argv[7], "--shared") ||
        strcmp(argv[9], "--threadgroup-index")) return 2;
    struct binding b = {0};
    if (!strcmp(argv[6], "32") && !strcmp(argv[8], "128")) b.workgroup = 32, b.shared = 128;
    else if (!strcmp(argv[6], "64") && !strcmp(argv[8], "256")) b.workgroup = 64, b.shared = 256;
    else return 2;
    if (!strcmp(argv[10], "none")) b.dynamic_index = UINT32_MAX;
    else if (!strcmp(argv[10], "3")) b.dynamic_index = 3;
    else if (!strcmp(argv[10], "7")) b.dynamic_index = 7;
    else return 2;
    const char *entry = NULL;
    LLVMMemoryBufferRef input = stela_intel_air_probe_input(5, argv, &entry);
    if (!input) return 2;
    struct intel_device_info device; const char *platform;
    STELA_INTEL_FOREACH_TARGET(platform, device) record_expect(platform, stela_intel_hold(&device));
    process_intel_debug_variable(); glsl_type_singleton_init_or_ref();
    STELA_INTEL_FOREACH_TARGET(platform, device) {
        if (stela_intel_hold(&device)) held(platform, &device);
        else compile(platform, &device, input, entry, &b);
    }
    glsl_type_singleton_decref(); LLVMDisposeMemoryBuffer(input);
    return 0;
}
