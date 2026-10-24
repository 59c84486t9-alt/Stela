/* SPDX-License-Identifier: MIT */
/* Hosted compiler/RAW/table/plan fixtures. Device topologies and placements
 * are synthetic models, not initialized hardware or native execution. */
#include "../hosted/air_compile.h"
#include "compute.h"
#include "legacy_compute.h"
#include "surface.h"
#include "fp_controls.h"
#include "compiler/tests/air_test_fixture.h"
#include "compiler/tests/air_division_fixture.h"
#include "compiler/tests/air_count_fixture.h"
#include "compiler/tests/air_permutation_fixture.h"
#include "compiler/tests/targets/intel.h"
#include "compiler/tests/threadgroup_record.h"
#include "intel/compiler/brw/brw_nir.h"
#include "intel/compiler/elk/elk_nir.h"
#include "intel/common/intel_compute_slm.h"
#include "util/ralloc.h"
#include "util/mesa-blake3.h"
#include <CommonCrypto/CommonDigest.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef NDEBUG
#error "Owned Intel tests require assertions"
#endif
#define CHECK(x) \
    do { \
        if (!(x)) { \
            fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #x); \
            abort(); \
        } \
    } while (0)
static unsigned allocations, fail_allocation, live_allocations;
void *stela_intel_air_test_malloc(size_t);
void *stela_intel_air_test_calloc(size_t, size_t);
void stela_intel_air_test_free(void *);
void *stela_intel_air_test_malloc(size_t bytes) {
    if (++allocations == fail_allocation) return NULL;
    void *p = malloc(bytes); if (p) live_allocations++; return p;
}
void *stela_intel_air_test_calloc(size_t count, size_t bytes) {
    if (++allocations == fail_allocation) return NULL;
    void *p = calloc(count, bytes); if (p) live_allocations++; return p;
}
void stela_intel_air_test_free(void *p) {
    if (p) { CHECK(live_allocations); live_allocations--; } free(p);
}
/* Inject only direct owner calls. Original backend/LLVM/GLSL allocators retain
 * their normal implementation. Context counters follow actual parent disposal. */
static void *contexts[8];
static unsigned live_contexts;
void *stela_intel_air_test_ralloc_context(const void *);
void *stela_intel_air_test_ralloc_array_size(const void *,size_t,unsigned);
void stela_intel_air_test_ralloc_free(void *);
void *stela_intel_air_test_ralloc_context(const void *parent)
{
    if(++allocations==fail_allocation)return NULL;
    void *p=ralloc_context(parent);if(!p)return NULL;
    unsigned i;for(i=0;i<ARRAY_SIZE(contexts);i++)if(!contexts[i])break;
    CHECK(i<ARRAY_SIZE(contexts));contexts[i]=p;live_contexts++;return p;
}
void *stela_intel_air_test_ralloc_array_size(const void *parent,size_t size,unsigned count)
{
    if(++allocations==fail_allocation)return NULL;
    return ralloc_array_size(parent,size,count);
}
void stela_intel_air_test_ralloc_free(void *p)
{
    for (unsigned i = 0; i < ARRAY_SIZE(contexts); i++)
        if (p && contexts[i] == p) {
            contexts[i] = NULL;
            CHECK(live_contexts);
            live_contexts--;
            break;
        }
    ralloc_free(p);
}
struct bytes { uint8_t *data; size_t size; };
static void append(struct bytes *bytes, const void *data, size_t size)
{
   CHECK(size <= SIZE_MAX - bytes->size);
   bytes->data = realloc(bytes->data, bytes->size + size);
   CHECK(bytes->data);
   memcpy(bytes->data + bytes->size, data, size);
   bytes->size += size;
}
static void little(void *data, uint64_t value, unsigned bytes)
{
   for (unsigned i = 0; i < bytes; i++) ((uint8_t *)data)[i] = (uint8_t)(value >> (8 * i));
}
static void tag(struct bytes *bytes, const char name[4], const void *data, size_t size)
{
   CHECK(size <= UINT16_MAX);
   uint8_t length[2]; little(length, size, 2);
   append(bytes, name, 4); append(bytes, length, 2); append(bytes, data, size);
}
static void digest(const void *bytes, size_t size, uint8_t output[32])
{
   CHECK(size <= AIR_MAX_BITCODE_BYTES);
   CC_SHA256(bytes, (CC_LONG)size, output);
}
/* Own one-entry framing fixture, never a second parser. The production Rust
 * parser and shared inspector independently validate all original extents. */
static struct bytes archive(const void *air, size_t size, const char *name,
                            unsigned air_minor, unsigned major, unsigned minor,
                            unsigned os_major, unsigned os_minor)
{
   struct bytes record = {0}; uint8_t prefix[4] = {0}, kind = 2, hash[32];
   append(&record, prefix, 4); tag(&record, "NAME", name, strlen(name) + 1);
   tag(&record, "TYPE", &kind, 1); digest(air, size, hash); tag(&record, "HASH", hash, 32);
   uint8_t length[8], offsets[24] = {0}, versions[8]; little(length, size, 8);
   tag(&record, "MDSZ", length, 8); tag(&record, "OFFT", offsets, 24);
   little(versions, 2, 2); little(versions + 2, air_minor, 2);
   little(versions + 4, major, 2); little(versions + 6, minor, 2);
   tag(&record, "VERS", versions, 8);
   append(&record, "ENDT", 4);
   little(record.data, record.size, 4);
   uint8_t header[88] = {0}; memcpy(header, "MTLB", 4);
   little(header + 4, 0x8001, 2); little(header + 6, 2, 2); little(header + 8, 9, 2);
   header[11] = 0x81; little(header + 12, os_major, 2); little(header + 14, os_minor, 2);
   size_t start = 92 + record.size;
   little(header + 16, start + size, 8);
   little(header + 24, 88, 8);
   little(header + 32, record.size, 8);
   little(header + 40, start, 8); little(header + 56, start, 8);
   little(header + 72, start, 8); little(header + 80, size, 8);
   struct bytes result = {0}; append(&result, header, sizeof(header));
   little(prefix, 1, 4); append(&result, prefix, 4); append(&result, record.data, record.size);
   append(&result, air, size); free(record.data); return result;
}
static struct stela_metal_assembly *assemble(const struct bytes *bytes)
{
   struct stela_metal_assembly_options options = stela_metal_assembly_default_options();
   struct stela_metal_assembly_error error; struct stela_metal_assembly *library = NULL;
   enum stela_metal_assembly_status status = stela_metal_assemble_archive(
      &options, bytes->data, bytes->size, &library, &error);
   if (status) fprintf(stderr, "assembly refused: %u %s\n", status, error.detail);
   CHECK(status == STELA_METAL_ASSEMBLY_OK && library);
   return library;
}
static struct stela_metal_assembly *fixture(LLVMMemoryBufferRef air)
{
   struct bytes bytes = archive(LLVMGetBufferStart(air), LLVMGetBufferSize(air), "kernel", 8, 4, 0,
      26, 7);
   struct stela_metal_assembly *library = assemble(&bytes); free(bytes.data); return library;
}
static struct stela_metal_assembly *two_entries(LLVMMemoryBufferRef air)
{
   size_t size = LLVMGetBufferSize(air);
   struct bytes a = archive(LLVMGetBufferStart(air), size, "kernel", 8, 4, 0, 26, 7);
   struct bytes b = archive(LLVMGetBufferStart(air), size, "other", 8, 4, 0, 26, 7);
   size_t a_record = a.size - 92 - size, b_record = b.size - 92 - size;
   size_t start = 92 + a_record + b_record;
   uint8_t header[88], count[4]; memcpy(header, a.data, sizeof(header));
   little(header + 16, start + size, 8); little(header + 32, a_record + b_record, 8);
   little(header + 40, start, 8); little(header + 56, start, 8); little(header + 72, start, 8);
   little(count, 2, 4);
   struct bytes bytes = {0}; append(&bytes, header, sizeof(header)); append(&bytes, count, 4);
   append(&bytes, a.data + 92, a_record); append(&bytes, b.data + 92, b_record);
   append(&bytes, LLVMGetBufferStart(air), size);
   struct stela_metal_assembly *library = assemble(&bytes);
   free(a.data); free(b.data); free(bytes.data); return library;
}
static void text_append(char *text, size_t capacity, const char *format, ...)
{
   size_t length = strlen(text); CHECK(length < capacity);
   va_list args;
   va_start(args, format);
   int bytes = vsnprintf(text + length, capacity - length, format, args);
   va_end(args); CHECK(bytes >= 0 && (size_t)bytes < capacity - length);
}
static LLVMMemoryBufferRef multibuffer(unsigned count)
{
   CHECK(count <= 31);
   char prefix[4096] = "target datalayout = \"e-p:64:64-i64:64-n8:16:32\"\n"
      "target triple = \"air64_v28-apple-macosx26.7.0\"\ndefine void @kernel(i32 %tid";
   char body[8192] = "%index = zext i32 %tid to i64\n", metadata[16384] = "}\n"
      "!air.version = !{!0}\n!air.language_version = !{!1}\n!air.kernel = !{!2}\n"
      "!0 = !{i32 2, i32 8, i32 0}\n!1 = !{!\"Metal\", i32 4, i32 0, i32 0}\n"
      "!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n!4 = !{!5";
   for (unsigned i = 0; i < count; i++) {
      text_append(prefix, sizeof(prefix), ", ptr addrspace(1) %%b%u", i);
      text_append(body, sizeof(body),
         "%%p%u = getelementptr i32, ptr addrspace(1) %%b%u, i64 %%index\n"
         "%%v%u = load i32, ptr addrspace(1) %%p%u, align 4\n"
         "%%x%u = add i32 %%v%u, %u\nstore i32 %%x%u, ptr addrspace(1) %%p%u, align 4\n",
         i, i, i, i, i, i, i + 1, i, i);
      text_append(metadata, sizeof(metadata), ",!%u", i + 6);
   }
   text_append(prefix, sizeof(prefix), ") {\n"); text_append(body, sizeof(body), "ret void\n");
   text_append(metadata, sizeof(metadata), "}\n!5 = !{i32 0, !\"air.thread_position_in_grid\","
      " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"tid\"}\n");
   for (unsigned i = 0; i < count; i++)
      text_append(metadata, sizeof(metadata),
         "!%u = !{i32 %u, !\"air.buffer\", !\"air.location_index\", i32 %u, i32 1,"
         " !\"air.read_write\", !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4,"
         " !\"air.arg_type_align_size\", i32 4, !\"air.arg_type_name\", !\"uint\", "
         "!\"air.arg_name\", !\"buffer%u\"}\n",
         i + 6, i + 1, (i * 7 + 3) % 31, i);
   return stela_air_test_custom_bitcode(prefix, body, metadata, "");
}


struct context {
    const char *name;
    struct intel_device_info device;
    struct isl_device isl;
    void *memory;
    struct brw_compiler *brw;
    struct elk_compiler *elk;
};
static void *expected_log_data;
static unsigned callback_count;
static void logger(void *data,unsigned *id,const char *format,...)
{
    if(expected_log_data){CHECK(data==expected_log_data);callback_count++;}
    (void)id;va_list args;va_start(args,format);vfprintf(stderr,format,args);va_end(args);
}
static void context(struct context *c,const char *target)
{
    memset(c,0,sizeof(*c));c->name=target;int pci=intel_device_name_to_pci_device_id(target);
    CHECK(pci>=0&&intel_get_device_info_for_build(pci,&c->device));
    c->memory=ralloc_context(NULL);CHECK(c->memory);isl_device_init(&c->isl,&c->device);
    if(c->device.ver<=8) { c->elk=elk_compiler_create(c->memory,&c->device);CHECK(c->elk);
        c->elk->shader_debug_log=c->elk->shader_perf_log=logger;
    } else { c->brw=brw_compiler_create(c->memory,&c->device);CHECK(c->brw);
        c->brw->shader_debug_log=c->brw->shader_perf_log=logger;
    }
}
static struct stela_intel_air_options options(void)
{
    return (struct stela_intel_air_options){.size = sizeof(struct stela_intel_air_options),
        .abi = STELA_INTEL_AIR_ABI,
        .workgroup_size = {32, 1, 1},
        .max_instructions = 4096,
        .max_code_bytes = 1024 * 1024};
}
static struct stela_intel_air_compilation *compile(struct context *c,
    struct stela_metal_assembly *library, unsigned selected,
    const struct stela_intel_air_options *opts, enum stela_intel_air_status expected)
{
    struct stela_intel_air_compilation *owner=NULL;struct stela_intel_air_error error;
#ifdef STELA_INTEL_AIR_ALLOC_TEST
    unsigned baseline=live_allocations;
#endif
    enum stela_intel_air_status status = stela_intel_air_compile(c->brw, c->elk, NULL, library,
        selected, opts, &owner, &error);
    if (status != expected)
        fprintf(stderr, "status%u expected%u: %s AIR%u %s\n", status, expected, error.detail,
            error.air.kind, error.air.detail);
    CHECK(status==expected&&error.status==status&&!!owner==(status==STELA_INTEL_AIR_OK));
#ifdef STELA_INTEL_AIR_ALLOC_TEST
    if(status)CHECK(live_allocations==baseline&&!live_contexts);
#endif
    return owner;
}
static void destroy(struct stela_intel_air_compilation **owner)
{
    stela_intel_air_destroy(owner);
    CHECK(!*owner);
    stela_intel_air_destroy(owner);
    stela_intel_air_destroy(NULL);
}
struct reference {const struct stela_intel_air_provenance *p;};
static bool reference_threadgroup(const struct stela_air_buffer *buffer,
    struct stela_air_threadgroup_view *view,void *data)
{
    const struct reference *ref=data;
    for(unsigned i=0;i<ref->p->threadgroup.count;i++) {
        const struct stela_metal_threadgroup_binding *row=&ref->p->threadgroup.bindings[i];
        if(row->buffer.argument==buffer->argument) {
            CHECK(row->buffer.index == buffer->index && buffer->address_space == 3 &&
                row->buffer.type_size == buffer->type_size &&
                row->buffer.type_alignment == buffer->type_alignment);
            *view=(struct stela_air_threadgroup_view){.size=row->bytes,.alignment=row->alignment,
                .available_access=STELA_AIR_READ_WRITE};return true;
        }
    }
    CHECK(false);return false;
}
static bool reference_bind(const struct stela_air_buffer *buffer,unsigned *slot,void *data)
{
    struct reference *ref=data;unsigned row=0;
    for(unsigned i=0;i<ref->p->argument_count;i++) {
        const struct stela_air_argument_info *a=&ref->p->arguments[i];
        if(a->kind!=1||a->buffer.address_space!=1)continue;
        if(a->buffer.argument==buffer->argument) {
            CHECK(a->buffer.index==buffer->index&&buffer->address_space==1);*slot=row;return true;
        }
        row++;
    }
    CHECK(false);return false;
}
static int plan(struct context *c,const struct stela_intel_air_compilation *owner,unsigned count)
{
    const struct stela_intel_air_binary *bin=stela_intel_air_binary(owner);
    const struct shader_info *info=&stela_intel_air_nir(owner)->info;
    const uint32_t groups[]={3,5,7};
    if(c->device.verx10>=125) {
        struct stela_intel_compute_plan p;
        struct stela_intel_compute_placement place={.code_offset=4096,.code_span=bin->code_bytes,
            .binding_table_offset=8192,.binding_table_entries=count,.binding_table_span=count*4u};
        int status=stela_intel_compute_plan(c->brw,&c->isl,bin->brw,info,&place,groups,0,&p);
        if(c->device.ver==35){CHECK(status==-95);return status;}
        CHECK(status==0&&p.requirements.binding_table_entries==count&&p.dispatch.groups[1]==5);
        CHECK(p.requirements.slm_bytes_per_group ==
                intel_compute_slm_calculate_size((unsigned)c->device.ver, info->shared_size) &&
            p.dispatch.slm_encoding ==
                intel_compute_slm_encode_size((unsigned)c->device.ver, info->shared_size));
        uint32_t words[64];memset(words,0xa5,sizeof(words));
        struct stela_intel_commands commands={words,ARRAY_SIZE(words),1,48};
        CHECK(stela_intel_compute_dispatch(&commands, &p.dispatch) == 0 && commands.used > 1 &&
            words[0] == UINT32_C(0xa5a5a5a5) && words[commands.used] == UINT32_C(0xa5a5a5a5));
        return 0;
    }
    struct stela_intel_legacy_plan p;
    struct stela_intel_legacy_placement place={.code_offset=4096,.code_span=bin->code_bytes,
        .binding_table_offset=8192,.binding_table_entries=count,.binding_table_span=count*4u,
        .curbe_offset=16384,.curbe_span=2048,.descriptor_offset=20480,.descriptor_span=32};
    int status=c->brw?stela_intel_legacy_brw_plan(c->brw,&c->isl,bin->brw,info,&place,groups,0,&p):
        stela_intel_legacy_elk_plan(c->elk,&c->isl,bin->elk,info,&place,groups,&p);
    CHECK(status==0&&p.binding_table_entries==count&&p.dispatch.groups[2]==7);
    CHECK(p.slm_bytes_per_group ==
        intel_compute_slm_calculate_size((unsigned)c->device.ver, info->shared_size));
    uint32_t words[64];memset(words,0xa5,sizeof(words));
    struct stela_intel_commands commands={words,ARRAY_SIZE(words),1,48};
    CHECK(stela_intel_gpgpu_dispatch(&commands, &p.dispatch) == 0 &&
        commands.used == 1 + p.walker_words && !memcmp(words + 1, p.walker, p.walker_words * 4) &&
        words[0] == UINT32_C(0xa5a5a5a5) && words[commands.used] == UINT32_C(0xa5a5a5a5));
    return 0;
}
static void raw_states(struct context *c,const struct stela_intel_air_compilation *owner)
{
    unsigned count;const struct stela_intel_air_binding *map=stela_intel_air_bindings(owner,&count);
    struct stela_intel_raw_limits limits;CHECK(!stela_intel_query_raw_limits(&c->isl,&limits));
    uint32_t states[AIR_MAX_ARGUMENTS][16], table[AIR_MAX_ARGUMENTS];
    CHECK(limits.state_bytes <= sizeof(states[0]));
    for(unsigned i=0;i<count;i++) {
        CHECK(map[i].slot==i);
        struct stela_intel_raw_view view = {.gpu_base = 0x100000 + i * 8192u,
            .mapped_bytes = 8192,
            .buffer_bytes = 8191,
            .offset = 256,
            .bytes = 4091,
            .address_bits = limits.surface_address_bits == 32 ? 32 : 48,
            .alignment = MAX2(4u, map[i].buffer.type_alignment),
            .access = (unsigned)map[i].buffer.access,
            .available_access = STELA_INTEL_BUFFER_READ_WRITE};
        CHECK(stela_intel_raw_buffer_state(&c->isl, &view, states[i], sizeof(states[i])) ==
            (int)limits.state_bytes);
        table[i]=0x10000+i*limits.gpu_state_alignment;
        CHECK(table[i]%limits.gpu_state_alignment==0);
        uint32_t before[16];memcpy(before,states[i],sizeof(before));
        view.available_access=0;
        CHECK(stela_intel_raw_buffer_state(&c->isl, &view, states[i], sizeof(states[i])) == -22 &&
            !memcmp(before, states[i], sizeof(before)));
        view.available_access = STELA_INTEL_BUFFER_READ_WRITE;
        view.mapped_bytes = 4092;
        view.buffer_bytes = 4092;
        CHECK(stela_intel_raw_buffer_state(&c->isl, &view, states[i], sizeof(states[i])) == -22 &&
            !memcmp(before, states[i], sizeof(before)));
        view.mapped_bytes=view.buffer_bytes=8192;view.offset=1;
        CHECK(stela_intel_raw_buffer_state(&c->isl, &view, states[i], sizeof(states[i])) == -22 &&
            !memcmp(before, states[i], sizeof(before)));
    }
    for(unsigned i=0;i<count;i++)CHECK(table[map[i].slot]==0x10000+i*limits.gpu_state_alignment);
}
/* A fixture's compile target: "<fixture>/<platform>". */
static void owned_target(char name[64],const char *fixture,const char *platform)
{
    snprintf(name,64,"%s/%s",fixture,platform);
}
static void expect_owned(const char *fixture,const char *platform)
{
    char target[64];owned_target(target,fixture,platform);record_expect(target,NULL);
}
static void validate(struct context *c, struct stela_metal_assembly *library,
    struct stela_intel_air_compilation *owner, const char *fixture)
{
    const struct stela_intel_air_binary *bin=stela_intel_air_binary(owner);
    const struct stela_intel_air_provenance *p=stela_intel_air_provenance(owner);unsigned count;
    const struct stela_intel_air_binding *map=stela_intel_air_bindings(owner,&count);
    CHECK(bin && bin->code && bin->code_bytes && p && map &&
        count == stela_intel_air_nir(owner)->info.num_ssbos);
    struct stela_metal_input_view original={.size=sizeof(original),.abi=STELA_METAL_INPUT_ABI};
    CHECK(stela_metal_assembly_original(library,&original,NULL)==STELA_METAL_ASSEMBLY_OK);
    struct reference ref={p};
    struct stela_air_options opts = {
        .workgroup_size = {p->options.workgroup_size[0], p->options.workgroup_size[1],
            p->options.workgroup_size[2]},
        .max_instructions = p->options.max_instructions,
        .fp_profile = p->options.fp_profile,
        .bind_ssbo = count ? reference_bind : NULL,
        .ssbo_count = count,
        .binding_data = &ref,
        .bind_threadgroup = p->threadgroup.count ? reference_threadgroup : NULL,
        .max_threadgroup_bytes = intel_device_info_get_max_slm_size(&c->device)};
    struct stela_air_error error;void *memory=ralloc_context(NULL);CHECK(memory);
    nir_shader *nir=stela_air_to_nir(original.bytes+p->air_offset,(size_t)p->air_bytes,p->name,
        stela_intel_air_nir(owner)->options,&opts,&error);CHECK(nir);
    if(c->brw){const struct brw_nir_compiler_opts o={0};brw_preprocess_nir(c->brw,nir,&o);}
    else{const struct elk_nir_compiler_opts o={0};elk_preprocess_nir(c->elk,nir,&o);}
    const nir_lower_compute_system_values_options sys={.has_base_workgroup_id=false};
    NIR_PASS(_, nir, nir_lower_compute_system_values, &sys);
    nir_shader_gather_info(nir, nir_shader_get_entrypoint(nir));
    if (p->options.subgroup_size)
        nir->info.min_subgroup_size = nir->info.max_subgroup_size = (uint8_t)
                                                                        p->options.subgroup_size;
    const void *code;unsigned bytes;
    if(c->brw) {
        struct brw_cs_prog_data d = {0};
        struct brw_cs_prog_key key = {0};
        brw_nir_lower_cs_intrinsics(nir, &c->device, &d);
        if (brw_nir_lower_cs_subgroup_id(nir, &c->device, 0)) {
            d.base.push_sizes[0] = 4;
            brw_cs_fill_push_const_info(&c->device, &d, 0);
            d.base.push_sizes[0] = REG_SIZE;
        } else brw_cs_fill_push_const_info(&c->device, &d, -1);
        struct brw_compile_cs_params args = {
            .base = {.mem_ctx = memory, .nir = nir, .key = &key.base, .prog_data = &d.base}};
        code = brw_compile(c->brw, &args.base);
        CHECK(code && !args.base.error_str);
        bytes = d.base.program_size;
        struct brw_cs_prog_data expected=*bin->brw;
        CHECK(d.base.num_relocs==expected.base.num_relocs);
        if (d.base.num_relocs)
            CHECK(!memcmp(d.base.relocs, expected.base.relocs,
                d.base.num_relocs * sizeof(*d.base.relocs)));
        d.base.relocs=expected.base.relocs=NULL;CHECK(!memcmp(&d,&expected,sizeof(d)));
    } else {
        struct elk_cs_prog_data d = {0};
        d.base.param = ralloc_array(memory, uint32_t, 0);
        CHECK(d.base.param);
        struct elk_cs_prog_key key={0};elk_nir_lower_cs_intrinsics(nir,&c->device,&d);
        struct elk_compile_cs_params args = {
            .base = {.mem_ctx = memory, .nir = nir}, .key = &key, .prog_data = &d};
        code = elk_compile_cs(c->elk, &args);
        CHECK(code && !args.base.error_str);
        bytes = d.base.program_size;
        struct elk_cs_prog_data expected=*bin->elk;
        CHECK(d.base.nr_params == expected.base.nr_params &&
            d.base.num_relocs == expected.base.num_relocs);
        if (d.base.nr_params)
            CHECK(!memcmp(d.base.param, expected.base.param,
                d.base.nr_params * sizeof(*d.base.param)));
        if (d.base.num_relocs)
            CHECK(!memcmp(d.base.relocs, expected.base.relocs,
                d.base.num_relocs * sizeof(*d.base.relocs)));
        d.base.param = expected.base.param = NULL;
        d.base.relocs = expected.base.relocs = NULL;
        CHECK(!memcmp(&d, &expected, sizeof(d)));
    }
    CHECK(bytes == bin->code_bytes && !memcmp(code, bin->code, bytes));
    ralloc_free(nir);
    ralloc_free(memory);
    raw_states(c,owner);int plan_status=plan(c,owner,count);
    char target[64];owned_target(target,fixture,c->name);
    record_compiled(target,bin->code_bytes);
    record_object("facts");
    record_uint("pci_id",c->device.pci_device_id);
    record_uint("verx10",c->device.verx10);
    record_uint("backend",bin->backend);
    record_uint("buffers",count);
    record_uint("executable_bytes",bin->executable_bytes);
    record_blake3("code_blake3",bin->code,bin->code_bytes);
    record_int("plan",plan_status);
    record_uint("subgroup",p->options.subgroup_size);
    record_threadgroup(&p->threadgroup,stela_intel_air_nir(owner)->info.shared_size);
    record_end();
}
/* Every manifest target. Gen7 refuses FP32 denorm preservation, which an
 * unchanged input may request. */
static void targets(struct stela_metal_assembly *library, enum stela_air_fp_profile fp,
    const char *fixture, unsigned subgroup)
{
    struct intel_device_info device;const char *name;
    STELA_INTEL_FOREACH_TARGET(name,device) {
        char target[64];owned_target(target,fixture,name);
        if (device.ver == 7)
            record_expect_unless_refused(target, STELA_REFUSAL_INTEL_GEN7_FP32_PRESERVE);
        else record_expect(target,stela_intel_hold(&device));
    }
    STELA_INTEL_FOREACH_TARGET(name,device) {
        struct context c;
        context(&c, name);
        struct stela_intel_air_options opts = options();
        opts.fp_profile = fp;
        opts.subgroup_size = subgroup;
        struct stela_intel_air_compilation *owner=NULL;struct stela_intel_air_error error;
        enum stela_intel_air_status status = stela_intel_air_compile(c.brw, c.elk, NULL, library, 0,
            &opts, &owner, &error);
        char target[64];owned_target(target,fixture,name);
        if(status==STELA_INTEL_AIR_UNSUPPORTED&&c.device.ver==35) {
            CHECK(strstr(error.detail,"Gen35"));record_held(target,STELA_HOLD_INTEL_GEN35);
        } else if(status==STELA_INTEL_AIR_UNSUPPORTED&&c.device.ver<8) {
            CHECK(strstr(error.detail, "FP controls"));
            record_refused(target, STELA_REFUSAL_INTEL_GEN7_FP32_PRESERVE);
        } else {
            if (status)
                fprintf(stderr, "%s status%u: %s AIR%u %s\n", name, status, error.detail,
                    error.air.kind, error.air.detail);
            CHECK(status==STELA_INTEL_AIR_OK&&owner);validate(&c,library,owner,fixture);
            const struct stela_intel_air_binary *retained=stela_intel_air_binary(owner);
            blake3_hash before, after;
            _mesa_blake3_compute(retained->code, retained->code_bytes, before);
            ralloc_free(c.memory);c.memory=NULL;
            _mesa_blake3_compute(retained->code, retained->code_bytes, after);
            CHECK(!memcmp(before, after, sizeof(before)));
            if (retained->elk && retained->elk->base.nr_params)
                CHECK(retained->elk->base.param[retained->elk->base.nr_params - 1] ==
                    ELK_PARAM_BUILTIN_SUBGROUP_ID);
            nir_validate_shader((nir_shader *)stela_intel_air_nir(owner),
                "after compiler destruction");
            destroy(&owner);
        }
        ralloc_free(c.memory);
    }
}
static struct bytes read_file(const char *path)
{
    FILE *f=fopen(path,"rb");CHECK(f&&!fseek(f,0,SEEK_END));long size=ftell(f);
    CHECK(size>0&&size<=AIR_MAX_BITCODE_BYTES&&!fseek(f,0,SEEK_SET));
    struct bytes b={.data=malloc((size_t)size),.size=(size_t)size};CHECK(b.data);
    CHECK(fread(b.data,1,b.size,f)==b.size&&fgetc(f)==EOF&&!ferror(f)&&!fclose(f));return b;
}
struct facts{const char *name;unsigned air,major,minor,osmajor,osminor;bool found;};
static bool inspect(const struct stela_air_inspection *i,const struct stela_air_entry *e,void *data)
{
    struct facts *f = data;
    if (strlen(f->name) != e->name_bytes || memcmp(f->name, e->name, e->name_bytes)) return true;
    f->found=true;f->air=i->air_minor;f->major=i->language_major;f->minor=i->language_minor;
    CHECK(sscanf(i->target,"air64_v%*u-apple-macosx%u.%u.",&f->osmajor,&f->osminor)==2);return true;
}
static void selected_tests(void)
{
    struct context c;context(&c,"bdw");struct stela_intel_air_options opts=options();
    const char *metadata =
        "}\n!air.version = !{!0}\n!air.language_version = !{!1}\n"
        "!air.kernel = !{!2,!7}\n!0 = !{i32 2, i32 8, i32 0}\n"
        "!1 = !{!\"Metal\", i32 4, i32 0, i32 0}\n!2 = !{ptr @kernel, !3, !4}\n"
        "!3 = !{}\n!4 = !{!5,!6}\n"
        "!5 = !{i32 0, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\"}\n"
        "!6 = !{i32 1, !\"air.buffer\", !\"air.location_index\", i32 13, i32 1, !\"air.write\","
        " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4,"
        " !\"air.arg_type_align_size\", i32 4, !\"air.arg_type_name\", !\"uint\","
        " !\"air.arg_name\", !\"result\"}\n"
        "!7 = !{ptr @other, !3, !4}\n";
    LLVMMemoryBufferRef air = stela_air_test_custom_bitcode(stela_air_test_prefix,
        "store i32 11, ptr addrspace(1) %out, align 4\nret void\n", metadata,
        "define void @other(i32 %tid, ptr addrspace(1) %out) {\n"
        "store i32 99, ptr addrspace(1) %out, align 4\nret void\n}\n");
    struct stela_metal_assembly *library=two_entries(air); LLVMDisposeMemoryBuffer(air);
    struct stela_intel_air_compilation *owner=compile(&c,library,1,&opts,STELA_INTEL_AIR_OK);
    const struct stela_intel_air_provenance *p=stela_intel_air_provenance(owner);
    CHECK(p->selected_entry==1&&!strcmp(p->name,"other")&&p->input.entry_count==2&&
        p->arguments[1].buffer.index==13&&p->arguments[1].buffer.access==STELA_AIR_WRITE);
    unsigned stores=0;
    nir_foreach_function_impl(impl, (nir_shader *)stela_intel_air_nir(owner))
        nir_foreach_block(block, impl) nir_foreach_instr(instr, block)
    {
        if (instr->type != nir_instr_type_intrinsic) continue;
        nir_intrinsic_instr *intr = nir_instr_as_intrinsic(instr);
        if (intr->intrinsic == nir_intrinsic_store_ssbo) {
            CHECK(nir_src_is_const(intr->src[0]) && nir_src_as_uint(intr->src[0]) == 99);
            stores++;
        }
    }
    CHECK(stores == 1);
    expect_owned("selected-second-entry", c.name);
    validate(&c, library, owner, "selected-second-entry");
    air = multibuffer(3);
    struct stela_metal_assembly *second_library = fixture(air);
    LLVMDisposeMemoryBuffer(air);
    opts.workgroup_size[0]=4;opts.workgroup_size[1]=2;opts.workgroup_size[2]=2;
    struct stela_intel_air_compilation *second = compile(&c, second_library, 0, &opts,
        STELA_INTEL_AIR_OK);
    expect_owned("coexisting-3d",c.name);expect_owned("after-other-owner-destroy",c.name);
    validate(&c, second_library, second, "coexisting-3d");
    destroy(&second);
    stela_metal_assembly_destroy(&second_library);
    validate(&c,library,owner,"after-other-owner-destroy");
    stela_metal_assembly_destroy(&library);ralloc_free(c.memory);
    CHECK(!strcmp(p->name,"other")&&!strcmp(p->arguments[1].name,"result"));destroy(&owner);
}
#ifdef STELA_INTEL_AIR_CAPTURE_TEST
/* Failure-only malformed output records after a real original compile. No
 * fabricated successful program or rewritten vendor algorithm is published. */
static unsigned bad_capture;
const unsigned *stela_intel_air_test_brw_compile(const struct brw_compiler *,
    struct brw_compile_params *);
const unsigned *stela_intel_air_test_elk_compile(const struct elk_compiler *,
    struct elk_compile_cs_params *);
static struct intel_shader_reloc invalid_relocation;
#define CORRUPT(d, error, code) \
    do { \
        switch (bad_capture) { \
        case 0: (code) = NULL; break; \
        case 1: (error) = "failure-only original-output fixture"; break; \
        case 2: (d)->base.program_size = 0; break; \
        case 3: (d)->base.stage = MESA_SHADER_VERTEX; break; \
        case 4: (d)->prog_mask = 0; break; \
        case 5: (d)->local_size[0]++; break; \
        case 6: \
            (d)->prog_offset[0] = UINT32_MAX; \
            (d)->prog_mask |= 1; \
            break; \
        case 7: \
            (d)->base.const_data_size = 16; \
            (d)->base.const_data_offset = (d)->base.program_size; \
            break; \
        case 8: \
            (d)->base.num_relocs = 1; \
            (d)->base.relocs = NULL; \
            break; \
        case 9: \
        case 10: \
        case 11: \
            invalid_relocation = (struct intel_shader_reloc){.type = bad_capture == 9 ? \
                    (enum intel_shader_reloc_type)99 : \
                    INTEL_SHADER_RELOC_TYPE_MOV_IMM, \
                .offset = bad_capture == 11 ? 1 : (d)->base.program_size - 8}; \
            (d)->base.num_relocs = 1; \
            (d)->base.relocs = &invalid_relocation; \
            break; \
        default: CHECK(false); \
        } \
    } while (0)
const unsigned *stela_intel_air_test_brw_compile(const struct brw_compiler *compiler,
    struct brw_compile_params *p)
{
    const unsigned *code=brw_compile(compiler,p);CHECK(code&&!p->error_str);
    struct brw_cs_prog_data *d = (struct brw_cs_prog_data *)p->prog_data;
    CORRUPT(d, p->error_str, code);
    return code;
}
const unsigned *stela_intel_air_test_elk_compile(const struct elk_compiler *compiler,
    struct elk_compile_cs_params *p)
{
    const unsigned *code=elk_compile_cs(compiler,p);CHECK(code&&!p->base.error_str);
    CORRUPT(p->prog_data,p->base.error_str,code);return code;
}
static void invalid_capture_tests(void)
{
    for(unsigned backend=0;backend<2;backend++) {
        struct context c;
        context(&c, backend ? "bdw" : "skl");
        struct stela_intel_air_options opts = options();
        LLVMMemoryBufferRef air = stela_air_test_bitcode(stela_air_test_store_body, "");
        struct stela_metal_assembly *library = fixture(air);
        LLVMDisposeMemoryBuffer(air);
        for (bad_capture = 0; bad_capture < 12; bad_capture++)
            CHECK(!compile(&c, library, 0, &opts, STELA_INTEL_AIR_BACKEND));
        stela_metal_assembly_destroy(&library);ralloc_free(c.memory);
    }
    puts("malformed original compiler outputs refused atomically; no successful fake program");
}
#endif
static void integer_division_tests(void)
{
    for (unsigned i = 0; i < ARRAY_SIZE(stela_air_division_fixtures); i++) {
        LLVMMemoryBufferRef air = stela_air_test_bitcode(stela_air_division_fixtures[i].body, "");
        struct stela_metal_assembly *library = fixture(air);
        LLVMDisposeMemoryBuffer(air);
        targets(library, STELA_AIR_FP_IEEE_DEFAULT, stela_air_division_fixtures[i].name, 0);
        stela_metal_assembly_destroy(&library);
    }
}
static void integer_count_tests(void)
{
    for (unsigned i = 0; i < ARRAY_SIZE(stela_air_count_fixtures); i++) {
        LLVMMemoryBufferRef air = stela_air_test_bitcode(stela_air_count_fixtures[i].body,
                                                       stela_air_count_fixtures[i].declarations);
        struct stela_metal_assembly *library = fixture(air);
        LLVMDisposeMemoryBuffer(air);
        targets(library, STELA_AIR_FP_IEEE_DEFAULT, stela_air_count_fixtures[i].name, 0);
        stela_metal_assembly_destroy(&library);
    }
}
static void permutation_options_tests(void)
{
    const char *platforms[] = {"bdw", "skl"};
    for (unsigned i = 0; i < ARRAY_SIZE(platforms); i++) {
        struct context c;
        context(&c, platforms[i]);
        const nir_shader_compiler_options *original = c.brw ?
            &c.brw->nir_options[MESA_SHADER_COMPUTE] : c.elk->nir_options[MESA_SHADER_COMPUTE];
        uint64_t original_mask = original->lower_int64_options;
        LLVMMemoryBufferRef air = stela_air_test_bitcode(stela_air_permutation_fixtures[3].body,
                                                       stela_air_permutation_fixtures[3].declarations);
        struct stela_metal_assembly *library = fixture(air);
        LLVMDisposeMemoryBuffer(air);
        struct stela_intel_air_options opts = options();
        struct stela_intel_air_compilation *owner = compile(&c, library, 0, &opts, STELA_INTEL_AIR_OK);
        const nir_shader *actual = stela_intel_air_nir(owner);
        CHECK(actual && actual->options != original &&
            actual->options->lower_int64_options == (original_mask |
                (c.elk ? nir_lower_bitfield_reverse64 : 0)));
        CHECK(original->lower_int64_options == original_mask);
        expect_owned("integer-permutation-policy", c.name);
        validate(&c, library, owner, "integer-permutation-policy");
        CHECK(original->lower_int64_options == original_mask);
        destroy(&owner);
        stela_metal_assembly_destroy(&library);
        ralloc_free(c.memory);
    }
}
static void integer_permutation_tests(void)
{
    permutation_options_tests();
    for (unsigned i = 0; i < ARRAY_SIZE(stela_air_permutation_fixtures); i++) {
        LLVMMemoryBufferRef air = stela_air_test_bitcode(stela_air_permutation_fixtures[i].body,
                                                       stela_air_permutation_fixtures[i].declarations);
        struct stela_metal_assembly *library = fixture(air);
        LLVMDisposeMemoryBuffer(air);
        targets(library, STELA_AIR_FP_IEEE_DEFAULT, stela_air_permutation_fixtures[i].name, 0);
        stela_metal_assembly_destroy(&library);
    }
}
static void original_tests(void)
{
    integer_permutation_tests();
    integer_count_tests();
    integer_division_tests();
    selected_tests();
    LLVMMemoryBufferRef air = stela_air_test_bitcode(stela_air_test_store_body, "");
    struct stela_metal_assembly *library = fixture(air);
    LLVMDisposeMemoryBuffer(air);
    targets(library, STELA_AIR_FP_IEEE_DEFAULT, "original-integer", 0);
    stela_metal_assembly_destroy(&library);
    for(unsigned count=0;count<=31;count++) {
        air=multibuffer(count);library=fixture(air);LLVMDisposeMemoryBuffer(air);
        char fixture_name[32];snprintf(fixture_name,sizeof(fixture_name),"buffers-%u",count);
        targets(library, STELA_AIR_FP_IEEE_DEFAULT, fixture_name, 0);
        stela_metal_assembly_destroy(&library);
    }
    air=stela_air_test_bitcode("ret void\n","");library=fixture(air);LLVMDisposeMemoryBuffer(air);
    targets(library, STELA_AIR_FP_IEEE_DEFAULT, "unused-buffer-no-effects", 0);
    stela_metal_assembly_destroy(&library);
    air = stela_air_test_bitcode(stela_air_test_store_body, "");
    library = fixture(air);
    LLVMDisposeMemoryBuffer(air);
    struct context c;context(&c,"skl");struct stela_intel_air_options opts=options();
    struct stela_intel_air_compilation *owner=compile(&c,library,0,&opts,STELA_INTEL_AIR_OK);
    const struct stela_intel_air_provenance *p=stela_intel_air_provenance(owner);
    const struct stela_metal_library_manifest *m=stela_metal_assembly_manifest(library);
    CHECK(!memcmp(&p->input, &m->input, sizeof(p->input)) &&
        !memcmp(&p->entry, &m->entries[0].entry, sizeof(p->entry)) &&
        !memcmp(p->air_sha256, m->entries[0].air_sha256, 32) &&
        p->arguments[1].name != m->entries[0].arguments[1].name);
    stela_metal_assembly_destroy(&library);ralloc_free(c.memory);
    CHECK(!strcmp(p->name,"kernel")&&!strcmp(p->arguments[1].type_name,"uint"));
    nir_validate_shader((nir_shader *)stela_intel_air_nir(owner), "after all inputs destroyed");
    destroy(&owner);
    for(unsigned backend=0;backend<2;backend++) {
        context(&c, backend ? "bdw" : "skl");
        air = stela_air_test_bitcode(stela_air_test_store_body, "");
        library = fixture(air);
        LLVMDisposeMemoryBuffer(air);
        opts=options();struct stela_intel_air_options bad=opts;
        bad.max_code_bytes=4;CHECK(!compile(&c,library,0,&bad,STELA_INTEL_AIR_LIMIT));
        bad=opts;bad.max_instructions=1;CHECK(!compile(&c,library,0,&bad,STELA_INTEL_AIR_FRONTEND));
        bad=opts;bad.subgroup_size=3;CHECK(!compile(&c,library,0,&bad,STELA_INTEL_AIR_UNSUPPORTED));
        bad = opts;
        bad.workgroup_size[0] = 0;
        CHECK(!compile(&c, library, 0, &bad, STELA_INTEL_AIR_UNSUPPORTED));
        bad = opts;
        bad.workgroup_size[0] = 1024;
        bad.workgroup_size[1] = 2;
        CHECK(!compile(&c, library, 0, &bad, STELA_INTEL_AIR_UNSUPPORTED));
        bad = opts;
        bad.fp_profile = (enum stela_air_fp_profile)99;
        CHECK(!compile(&c, library, 0, &bad, STELA_INTEL_AIR_UNSUPPORTED));
        bad=opts;bad.abi++;CHECK(!compile(&c,library,0,&bad,STELA_INTEL_AIR_INVALID));
        CHECK(!compile(&c,library,1,&opts,STELA_INTEL_AIR_INVALID));
        if (c.brw) {
            c.brw->shader_perf_log = NULL;
            CHECK(!compile(&c, library, 0, &opts, STELA_INTEL_AIR_DEVICE));
            c.brw->shader_perf_log = logger;
        } else {
            c.elk->shader_perf_log = NULL;
            CHECK(!compile(&c, library, 0, &opts, STELA_INTEL_AIR_DEVICE));
            c.elk->shader_perf_log = logger;
        }
        if(c.brw) {
            const struct intel_device_info *saved=c.brw->isa.devinfo;c.brw->isa.devinfo=NULL;
            CHECK(!compile(&c,library,0,&opts,STELA_INTEL_AIR_DEVICE));c.brw->isa.devinfo=saved;
        } else {
            const struct intel_device_info *saved=c.elk->isa.devinfo;c.elk->isa.devinfo=NULL;
            CHECK(!compile(&c,library,0,&opts,STELA_INTEL_AIR_DEVICE));c.elk->isa.devinfo=saved;
        }
        nir_shader_compiler_options *actual_options = c.brw ?
            &c.brw->nir_options[MESA_SHADER_COMPUTE] :
            c.elk->nir_options[MESA_SHADER_COMPUTE];
        CHECK(!actual_options->cb_data);unsigned before_callback_refusal=allocations;
        actual_options->cb_data=&c;
        CHECK(!compile(&c, library, 0, &opts, STELA_INTEL_AIR_UNSUPPORTED) &&
            allocations == before_callback_refusal);
        actual_options->cb_data=NULL;
        for(unsigned width=8;width<=32;width*=2) {
            opts.subgroup_size=width;owner=compile(&c,library,0,&opts,STELA_INTEL_AIR_OK);
            char fixture_name[32];snprintf(fixture_name,sizeof(fixture_name),"subgroup-%u",width);
            expect_owned(fixture_name, c.name);
            validate(&c, library, owner, fixture_name);
            destroy(&owner);
        }
        opts=options();owner=compile(&c,library,0,&opts,STELA_INTEL_AIR_OK);
        struct stela_intel_air_compilation *preserved=owner;struct stela_intel_air_error error;
        CHECK(stela_intel_air_compile(c.brw, c.elk, NULL, library, 0, &opts, &owner, &error) ==
                STELA_INTEL_AIR_INVALID &&
            owner == preserved);
        destroy(&owner);
        expected_log_data=&c;callback_count=0;
        CHECK(stela_intel_air_compile(c.brw, c.elk, expected_log_data, library, 0, &opts, &owner,
                  &error) == STELA_INTEL_AIR_OK &&
            owner && callback_count);
        expected_log_data=NULL;destroy(&owner);
#ifdef STELA_INTEL_AIR_ALLOC_TEST
        allocations = 0;
        owner = compile(&c, library, 0, &opts, STELA_INTEL_AIR_OK);
        unsigned total = allocations;
        CHECK(total == (backend ? 5u : 4u));
        destroy(&owner);
        CHECK(!live_contexts);
        for (unsigned fail = 1; fail <= total; fail++) {
            allocations = 0;
            fail_allocation = fail;
            CHECK(!compile(&c, library, 0, &opts, STELA_INTEL_AIR_ALLOCATION) &&
                !live_allocations && !live_contexts);
        }
        fail_allocation=0;
#endif
        stela_metal_assembly_destroy(&library);ralloc_free(c.memory);
    }
    context(&c,"skl");opts=options();
    air = stela_air_test_bitcode("call void @unsupported()\nret void\n",
        "declare void @unsupported()\n");
    library=fixture(air);LLVMDisposeMemoryBuffer(air);
    CHECK(!compile(&c, library, 0, &opts, STELA_INTEL_AIR_FRONTEND));
    stela_metal_assembly_destroy(&library);
    /* Complete dynamic AS3 reflection reaches this owner's explicit missing
     * dispatch-specialization refusal, rather than the canonical inspector's
     * separate refusal for incomplete module-global reflection. */
    air = stela_air_test_custom_bitcode("target datalayout = \"e-p:64:64-i64:64-n8:16:32\"\n"
        "target triple = \"air64_v29-apple-macosx27.2.0\"\n"
        "define void @kernel(i32 %tid, ptr addrspace(3) %scratch) {\n",
        "store i32 %tid, ptr addrspace(3) %scratch, align 4\nret void\n",
        "}\n!air.version = !{!0}\n!air.language_version = !{!1}\n!air.kernel = !{!2}\n"
        "!0 = !{i32 2, i32 9, i32 0}\n!1 = !{!\"Metal\", i32 4, i32 1, i32 0}\n"
        "!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n!4 = !{!5,!6}\n"
        "!5 = !{i32 0, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\","
        " !\"air.arg_name\", !\"tid\"}\n"
        "!6 = !{i32 1, !\"air.buffer\", !\"air.location_index\", i32 7, i32 1, !\"air.read_write\","
        " !\"air.address_space\", i32 3, !\"air.arg_type_size\", i32 4,"
        " !\"air.arg_type_align_size\", i32 4, !\"air.arg_type_name\", !\"uint\","
        " !\"air.arg_name\", !\"scratch\"}\n",
        "");
    struct bytes shared=archive(LLVMGetBufferStart(air),LLVMGetBufferSize(air),"kernel",9,4,1,27,2);
    library=assemble(&shared);free(shared.data);LLVMDisposeMemoryBuffer(air);
    CHECK(!compile(&c,library,0,&opts,STELA_INTEL_AIR_UNSUPPORTED));
    stela_metal_assembly_destroy(&library);ralloc_free(c.memory);
}
static void source_input(int argc,char **argv)
{
    CHECK(argc==5); /* --source ORIGINAL_MSL ORIGINAL_ADAPTER_AIR INDEPENDENT_IDENTITY_208_BYTES */
    struct bytes source = read_file(argv[2]), air = read_file(argv[3]),
                 identity = read_file(argv[4]);
    CHECK(identity.size == 208);
    struct stela_msl_output compiled={.air=air.data,.air_bytes=air.size};
    memcpy(compiled.source_sha256,identity.data,32);memcpy(compiled.air_sha256,identity.data+32,32);
    memcpy(&compiled.build,identity.data+64,sizeof(compiled.build));
    struct stela_msl_apple_config config=stela_msl_apple_default_config();
    struct stela_msl_request request = {.source = source.data,
        .source_bytes = source.size,
        .language_version = 0x40001,
        .fast_math = true,
        .target_triple = "air64_v29-apple-macosx27.2.0"};
    struct stela_metal_assembly_options assembly_options=stela_metal_assembly_default_options();
    struct stela_metal_assembly_error error;struct stela_metal_assembly *library=NULL;
    CHECK(stela_metal_assemble_source(&assembly_options, &config, &request, &compiled, &library,
              &error) == STELA_METAL_ASSEMBLY_OK);
    struct context c;context(&c,"skl");
    struct stela_intel_air_options opts = options();
    opts.fp_profile = STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41;
    struct stela_intel_air_compilation *owner=compile(&c,library,0,&opts,STELA_INTEL_AIR_OK);
    expect_owned("original-source-owner",c.name);validate(&c,library,owner,"original-source-owner");
    free(air.data);free(source.data);stela_metal_assembly_destroy(&library);ralloc_free(c.memory);
    const struct stela_intel_air_provenance *p=stela_intel_air_provenance(owner);
    CHECK(p->library_flags == STELA_METAL_LIBRARY_SOURCE_COMPILED &&
        p->compiler_profile == config.profile && p->request_language == 0x40001 &&
        p->request_fast_math == 1 && !memcmp(p->source_sha256, identity.data, 32) &&
        !memcmp(p->input.original_sha256, identity.data + 32, 32) &&
        !memcmp(&p->build, identity.data + 64, sizeof(p->build)));
    free(identity.data);
    nir_validate_shader((nir_shader *)stela_intel_air_nir(owner),
        "source owner after input/compiler destruction");
    destroy(&owner);
}
static void requested_threadgroups(int argc, char **argv,
    struct stela_metal_threadgroup_request_row *rows)
{
    CHECK(argc>=6&&argc-5<=(int)AIR_MAX_ARGUMENTS);
    for(int i=5;i<argc;i++) {
        char *end;errno=0;CHECK(argv[i][0]>='0'&&argv[i][0]<='9');
        unsigned long long index = strtoull(argv[i], &end, 10);
        CHECK(!errno && index <= UINT32_MAX && *end == ':');
        const char *start=end+1;CHECK(*start>='0'&&*start<='9');errno=0;
        unsigned long long bytes=strtoull(start,&end,10);CHECK(!errno&&!*end);
        rows[i - 5] = (struct stela_metal_threadgroup_request_row){
            .index = (uint32_t)index, .bytes = (uint64_t)bytes};
    }
}
static void threadgroup_input(int argc,char **argv)
{
    struct stela_metal_threadgroup_request_row rows[AIR_MAX_ARGUMENTS] = {0};
    requested_threadgroups(argc, argv, rows);
    char *end;
    errno = 0;
    unsigned long workgroup = strtoul(argv[4], &end, 10);
    CHECK(!errno && !*end && workgroup && workgroup <= 1024);
    struct stela_metal_threadgroup_request request = {.size = sizeof(request),
        .abi = STELA_METAL_THREADGROUP_ABI,
        .count = (uint32_t)(argc - 5),
        .rows = rows};
    struct bytes air = read_file(argv[2]);
    struct facts f = {.name = argv[3]};
    struct stela_air_error air_error;
    CHECK(stela_air_inspect(air.data,air.size,256,inspect,&f,&air_error)&&f.found);
    struct bytes bytes=archive(air.data,air.size,f.name,f.air,f.major,f.minor,f.osmajor,f.osminor);
    struct stela_metal_assembly *library=assemble(&bytes);free(bytes.data);free(air.data);
    /* Gen7.0 refuses byte or misaligned shared access, which an input may use. */
    struct intel_device_info device;const char *name;
    STELA_INTEL_FOREACH_TARGET(name,device) {
        char target[64];owned_target(target,"threadgroup",name);
        if (device.verx10 == 70)
            record_expect_unless_refused(target, STELA_REFUSAL_INTEL_GEN7_BYTE_SHARED);
        else record_expect(target,stela_intel_hold(&device));
    }
    unsigned invalid_requests_checked[2]={0};
    STELA_INTEL_FOREACH_TARGET(name,device) {
        char target[64];owned_target(target,"threadgroup",name);
        struct context c;
        context(&c, name);
        struct stela_intel_air_options opts = options();
        opts.workgroup_size[0] = (uint32_t)workgroup;
        struct stela_intel_air_compilation *owner=NULL;struct stela_intel_air_error error;
        enum stela_intel_air_status status = stela_intel_air_compile_specialized(c.brw, c.elk, NULL,
            library, 0, &opts, &request, &owner, &error);
        if (c.device.ver == 35) {
            CHECK(status == STELA_INTEL_AIR_UNSUPPORTED && !owner && strstr(error.detail, "Gen35"));
            record_held(target, STELA_HOLD_INTEL_GEN35);
            ralloc_free(c.memory);
            continue;
        }
        if (status == STELA_INTEL_AIR_UNSUPPORTED && c.device.verx10 == 70 &&
            strstr(error.detail, "byte-scattered")) {
            CHECK(!owner && error.air.kind == STELA_AIR_OK);
            record_refused(target, STELA_REFUSAL_INTEL_GEN7_BYTE_SHARED);
            ralloc_free(c.memory);continue;
        }
        if (status)
            fprintf(stderr, "dynamic %s: status%u %s AIR%u %s\n", name, status, error.detail,
                error.air.kind, error.air.detail);
        CHECK(status==STELA_INTEL_AIR_OK&&owner);
        const struct stela_intel_air_provenance *p=stela_intel_air_provenance(owner);
        if(!invalid_requests_checked[c.elk!=NULL]++) {
            struct stela_metal_threadgroup_request bad_request=request;
            struct stela_intel_air_compilation *failed=NULL;
            bad_request.size--;
            CHECK(stela_intel_air_compile_specialized(c.brw, c.elk, NULL, library, 0, &opts,
                      &bad_request, &failed, &error) == STELA_INTEL_AIR_INVALID &&
                !failed);
            bad_request=request;bad_request.count=0;
            CHECK(stela_intel_air_compile_specialized(c.brw, c.elk, NULL, library, 0, &opts,
                      &bad_request, &failed, &error) == STELA_INTEL_AIR_UNSUPPORTED &&
                !failed);
            bad_request=request;
            struct stela_metal_threadgroup_request_row bad_rows[AIR_MAX_ARGUMENTS];
            memcpy(bad_rows, rows, sizeof(rows));
            bad_request.rows=bad_rows;bad_rows[0].bytes=0;
            CHECK(stela_intel_air_compile_specialized(c.brw, c.elk, NULL, library, 0, &opts,
                      &bad_request, &failed, &error) == STELA_INTEL_AIR_UNSUPPORTED &&
                !failed);
            bad_rows[0].bytes=UINT64_C(0x100000000);
            CHECK(stela_intel_air_compile_specialized(c.brw, c.elk, NULL, library, 0, &opts,
                      &bad_request, &failed, &error) == STELA_INTEL_AIR_LIMIT &&
                !failed);
#ifdef STELA_INTEL_AIR_ALLOC_TEST
            unsigned baseline=live_allocations;
            unsigned contexts_before=live_contexts;
            bad_request=request;
            for(unsigned fail=1;fail<=(c.elk?5u:4u);fail++) {
                allocations=0;fail_allocation=fail;
                CHECK(stela_intel_air_compile_specialized(c.brw, c.elk, NULL, library, 0, &opts,
                          &bad_request, &failed, &error) == STELA_INTEL_AIR_ALLOCATION &&
                    !failed && live_allocations == baseline);
                CHECK(live_contexts==contexts_before);
            }
            fail_allocation=0;
#endif
        }
        CHECK(p->threadgroup.count == request.count &&
            stela_metal_threadgroup_matches(&p->threadgroup, &request));
        struct stela_metal_threadgroup_request_row saved[AIR_MAX_ARGUMENTS];
        memcpy(saved, rows, sizeof(rows));
        rows[0].bytes+=16;CHECK(!stela_metal_threadgroup_matches(&p->threadgroup,&request));
        memset(rows,0,sizeof(rows));
        CHECK(p->threadgroup.bindings[0].bytes&&p->threadgroup.bindings[0].alignment>=16);
        memcpy(rows, saved, sizeof(rows));
        CHECK(stela_metal_threadgroup_matches(&p->threadgroup, &request));
        validate(&c,library,owner,"threadgroup");
        ralloc_free(c.memory);
        nir_validate_shader((nir_shader *)stela_intel_air_nir(owner),
            "dynamic result after compiler destruction");
        CHECK(stela_metal_threadgroup_matches(&p->threadgroup,&request));destroy(&owner);
    }
    stela_metal_assembly_destroy(&library);
}
static void shared_refusal(int argc,char **argv)
{
    CHECK(argc==4);
    struct bytes air = read_file(argv[2]);
    struct facts f = {.name = argv[3]};
    struct stela_air_error inspect_error;
    CHECK(stela_air_inspect(air.data,air.size,256,inspect,&f,&inspect_error)&&f.found);
    struct bytes bytes=archive(air.data,air.size,f.name,f.air,f.major,f.minor,f.osmajor,f.osminor);
    struct stela_metal_assembly *library=assemble(&bytes);free(bytes.data);free(air.data);
    struct intel_device_info device;const char *name;
    STELA_INTEL_FOREACH_TARGET(name,device) {
        char target[64];owned_target(target,"shared-refusal",name);
        if(stela_intel_hold(&device))record_expect(target,stela_intel_hold(&device));
        else record_expect_refusal(target,STELA_REFUSAL_DYNAMIC_THREADGROUP);
    }
    STELA_INTEL_FOREACH_TARGET(name,device) {
        struct context c;context(&c,name);struct stela_intel_air_options opts=options();
        struct stela_intel_air_compilation *owner=NULL;struct stela_intel_air_error error;
        CHECK(stela_intel_air_compile(c.brw, c.elk, NULL, library, 0, &opts, &owner, &error) ==
                STELA_INTEL_AIR_UNSUPPORTED &&
            !owner && error.status == STELA_INTEL_AIR_UNSUPPORTED &&
            error.air.kind == STELA_AIR_OK);
        char target[64];owned_target(target,"shared-refusal",name);
        if (c.device.ver == 35) {
            CHECK(strstr(error.detail, "Gen35"));
            record_held(target, STELA_HOLD_INTEL_GEN35);
        } else {
            CHECK(strstr(error.detail, "binding specialization"));
            record_refused(target, STELA_REFUSAL_DYNAMIC_THREADGROUP);
        }
        ralloc_free(c.memory);
    }
    stela_metal_assembly_destroy(&library);
}
/* Synthetic LLVM input, not Apple compiler output. Exercise actual owned
 * admission before the original ELK byte-scattered message path. */
static LLVMMemoryBufferRef gen7_shared_fixture(unsigned mode)
{
    const char *prefix="target datalayout = \"e-p:64:64-i64:64-n8:16:32\"\n"
        "target triple = \"air64_v29-apple-macosx27.2.0\"\n"
        "@storage = internal addrspace(3) global [8 x i8] undef,align 4\n"
        "define void @kernel(i32 %tid,ptr addrspace(1) %out) {\n";
    const char *metadata =
        "}\n!air.version=!{!0}\n!air.language_version=!{!1}\n!air.kernel=!{!2}\n"
        "!llvm.ident=!{!10}\n!llvm.module.flags=!{!11}\n"
        "!0=!{i32 2,i32 9,i32 0}\n!1=!{!\"Metal\",i32 4,i32 1,i32 0}\n"
        "!2=!{ptr @kernel,!3,!4}\n!3=!{}\n!4=!{!5,!6}\n"
        "!5=!{i32 0,!\"air.thread_position_in_grid\",!\"air.arg_type_name\",!\"uint\","
        "!\"air.arg_name\",!\"tid\"}\n"
        "!6=!{i32 1,!\"air.buffer\",!\"air.location_index\",i32 7,i32 1,!\"air.read_write\","
        "!\"air.address_space\",i32 1,!\"air.arg_type_size\",i32 4,"
        "!\"air.arg_type_align_size\",i32 4,!\"air.arg_type_name\",!\"uint\","
        "!\"air.arg_name\",!\"out\"}\n"
        "!10=!{!\"Apple metal version 32023.922 (metalfe-32023.922.4)\"}\n"
        "!11=!{i32 7,!\"air.max_threadgroup_buffers\",i32 31}\n";
    const char *bodies[] = {
        "store i8 17,ptr addrspace(3) @storage,align 1\n"
        "%v=load i8,ptr addrspace(3) @storage,align 1\n%x=zext i8 %v to i32\n"
        "store i32 %x,ptr addrspace(1) %out,align 4\nret void\n",
        "store i32 17,ptr addrspace(3) @storage,align 4\n"
        "%v=load i32,ptr addrspace(3) @storage,align 4\n"
        "store i32 %v,ptr addrspace(1) %out,align 4\nret void\n",
        "%p=getelementptr i8,ptr addrspace(3) @storage,i64 2\n"
        "store i32 17,ptr addrspace(3) %p,align 2\n%v=load i32,ptr addrspace(3) %p,align 2\n"
        "store i32 %v,ptr addrspace(1) %out,align 4\nret void\n"};
    return stela_air_test_custom_bitcode(prefix,bodies[mode],metadata,"");
}
static void gen7_shared_admission(void)
{
    /* Byte, aligned32 and misaligned32 shared access; Gen7.0 admits aligned32. */
    static const char *const modes[] = {
        "gen7-shared-byte", "gen7-shared-aligned32", "gen7-shared-misaligned32"};
    struct intel_device_info device;const char *name;
    for(unsigned mode=0;mode<ARRAY_SIZE(modes);mode++) {
        STELA_INTEL_FOREACH_TARGET(name,device) {
            if(!stela_intel_elk(&device))continue;
            char target[64];owned_target(target,modes[mode],name);
            if (device.verx10 == 70 && mode != 1)
                record_expect_refusal(target, STELA_REFUSAL_INTEL_GEN7_BYTE_SHARED);
            else record_expect(target,NULL);
        }
    }
    for(unsigned mode=0;mode<ARRAY_SIZE(modes);mode++) {
        LLVMMemoryBufferRef air=gen7_shared_fixture(mode);
        struct bytes bytes = archive(LLVMGetBufferStart(air), LLVMGetBufferSize(air), "kernel", 9,
            4, 1, 27, 2);
        struct stela_metal_assembly *library = assemble(&bytes);
        free(bytes.data);
        LLVMDisposeMemoryBuffer(air);
        STELA_INTEL_FOREACH_TARGET(name,device) {
            if(!stela_intel_elk(&device))continue;
            struct context c;context(&c,name);struct stela_intel_air_options opts=options();
            struct stela_intel_air_compilation *owner=NULL;struct stela_intel_air_error error;
            enum stela_intel_air_status status = stela_intel_air_compile(c.brw, c.elk, NULL,
                library, 0, &opts, &owner, &error);
            if(status==STELA_INTEL_AIR_UNSUPPORTED&&strstr(error.detail,"byte-scattered")) {
                CHECK(!owner&&error.status==status&&error.air.kind==STELA_AIR_OK);
                char target[64];owned_target(target,modes[mode],name);
                record_refused(target,STELA_REFUSAL_INTEL_GEN7_BYTE_SHARED);
            } else {
                CHECK(status == STELA_INTEL_AIR_OK && owner);
                validate(&c, library, owner, modes[mode]);
                destroy(&owner);
            }
            ralloc_free(c.memory);
        }
        stela_metal_assembly_destroy(&library);
    }
}

int main(int argc,char **argv)
{
    process_intel_debug_variable();
#ifdef STELA_INTEL_AIR_CAPTURE_TEST
    (void)argc;(void)argv;invalid_capture_tests();
#else
    if(argc==1)original_tests();
    else if(!strcmp(argv[1],"--source"))source_input(argc,argv);
    else if(!strcmp(argv[1],"--threadgroup"))threadgroup_input(argc,argv);
    else if(!strcmp(argv[1],"--shared-refusal"))shared_refusal(argc,argv);
    else if(!strcmp(argv[1],"--gen7-shared")) { CHECK(argc==2); gen7_shared_admission(); }
    else {
        CHECK((argc == 4 || argc == 5) && !strcmp(argv[1], "--input"));
        struct bytes air = read_file(argv[2]);
        struct facts f = {.name = argv[3]};
        struct stela_air_error error;
        CHECK(stela_air_inspect(air.data,air.size,256,inspect,&f,&error)&&f.found);
        struct bytes b=archive(air.data,air.size,f.name,f.air,f.major,f.minor,f.osmajor,f.osminor);
        struct stela_metal_assembly *library=assemble(&b);free(air.data);free(b.data);
        targets(library,
            argc == 5 ? (enum stela_air_fp_profile)strtoul(argv[4], NULL, 10) :
                        STELA_AIR_FP_IEEE_DEFAULT,
            "unchanged-original-file", 0);
        stela_metal_assembly_destroy(&library);
    }
#endif
#ifdef STELA_INTEL_AIR_ALLOC_TEST
    CHECK(!live_allocations&&!live_contexts);
#endif
    return 0;
}
