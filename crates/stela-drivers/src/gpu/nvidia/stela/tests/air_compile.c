/* SPDX-License-Identifier: MIT */
/* Hosted CPU compilation/table/QMD fixtures only. Device topology, GPU VAs and
 * resource owners are synthetic test models, never hardware qualification. */
#include "../hosted/air_compile.h"
#include "stela/tests/air_test_fixture.h"
#include "nouveau/compiler/nak_private.h"
#include "nouveau/headers/drf.h"
#include "clc5c0.h"
#include "clc6c0.h"
#include "clc7c0.h"
#include "clc9c0.h"
#include "clcbc0.h"
#include "clcdc0.h"
#include "clcec0.h"
#include "clc3c0qmd.h"
#include "clc6c0qmd.h"
#include "clcbc0qmd.h"
#include "clcdc0qmd.h"
#include "util/ralloc.h"
#include "util/u_math.h"
#include "util/mesa-blake3.h"
#include <CommonCrypto/CommonDigest.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef NDEBUG
#error "Owned NAK tests require assertions"
#endif
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #x); abort(); } } while (0)
static unsigned allocations, fail_allocation, live_allocations;
void *stela_nv_air_test_malloc(size_t);
void *stela_nv_air_test_calloc(size_t, size_t);
void stela_nv_air_test_free(void *);
void *stela_nv_air_test_malloc(size_t bytes) {
    if (++allocations == fail_allocation) return NULL;
    void *p = malloc(bytes); if (p) live_allocations++; return p;
}
void *stela_nv_air_test_calloc(size_t count, size_t bytes) {
    if (++allocations == fail_allocation) return NULL;
    void *p = calloc(count, bytes); if (p) live_allocations++; return p;
}
void stela_nv_air_test_free(void *p) {
    if (p) { CHECK(live_allocations); live_allocations--; } free(p);
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
   tag(&record, "VERS", versions, 8); append(&record, "ENDT", 4); little(record.data, record.size, 4);
   uint8_t header[88] = {0}; memcpy(header, "MTLB", 4);
   little(header + 4, 0x8001, 2); little(header + 6, 2, 2); little(header + 8, 9, 2);
   header[11] = 0x81; little(header + 12, os_major, 2); little(header + 14, os_minor, 2);
   size_t start = 92 + record.size;
   little(header + 16, start + size, 8); little(header + 24, 88, 8); little(header + 32, record.size, 8);
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
   struct bytes bytes = archive(LLVMGetBufferStart(air), LLVMGetBufferSize(air), "kernel", 8, 4, 0, 26, 7);
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
   va_list args; va_start(args, format); int bytes = vsnprintf(text + length, capacity - length, format, args);
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
      text_append(body, sizeof(body), "%%p%u = getelementptr i32, ptr addrspace(1) %%b%u, i64 %%index\n"
         "%%v%u = load i32, ptr addrspace(1) %%p%u, align 4\n"
         "%%x%u = add i32 %%v%u, %u\nstore i32 %%x%u, ptr addrspace(1) %%p%u, align 4\n",
         i, i, i, i, i, i, i + 1, i, i);
      text_append(metadata, sizeof(metadata), ",!%u", i + 6);
   }
   text_append(prefix, sizeof(prefix), ") {\n"); text_append(body, sizeof(body), "ret void\n");
   text_append(metadata, sizeof(metadata), "}\n!5 = !{i32 0, !\"air.thread_position_in_grid\","
      " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"tid\"}\n");
   for (unsigned i = 0; i < count; i++)
      text_append(metadata, sizeof(metadata), "!%u = !{i32 %u, !\"air.buffer\", !\"air.location_index\", i32 %u, i32 1,"
         " !\"air.read_write\", !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4,"
         " !\"air.arg_type_align_size\", i32 4, !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"buffer%u\"}\n",
         i + 6, i + 1, (i * 7 + 3) % 31, i);
   return stela_air_test_custom_bitcode(prefix, body, metadata, "");
}

static struct nv_device_info model(unsigned sm, unsigned cls)
{
    struct nv_device_info device = {.sm = (uint8_t)sm, .cls_compute = (uint16_t)cls};
    const uint16_t sizes[] = {0, 8, 16, 32, 64, 100, 132, 164, 196, 228};
    if (sm == 75) {
        device.max_warps_per_mp = 32; device.sm_smem_size_count = 2;
        device.sm_smem_sizes_kB[0] = 32; device.sm_smem_sizes_kB[1] = 64;
    } else {
        device.max_warps_per_mp = sm == 86 || sm == 87 || sm == 89 || sm == 120 ? 48 : 64;
        device.sm_smem_size_count = sm == 80 || sm == 87 ? 8 : sm >= 90 && sm < 120 ? 10 : 6;
        memcpy(device.sm_smem_sizes_kB, sizes, device.sm_smem_size_count * sizeof(sizes[0]));
    }
    device.max_smem_per_wg_kB = device.sm_smem_sizes_kB[device.sm_smem_size_count - 1];
    return device;
}
static struct nak_compiler *compiler(const struct nv_device_info *device)
{
    struct nak_compiler *nak = nak_compiler_create(device); CHECK(nak); return nak;
}
static struct stela_nv_air_options options(void)
{
    return (struct stela_nv_air_options) {.size = sizeof(struct stela_nv_air_options), .abi = STELA_NV_AIR_ABI,
        .workgroup_size = {32, 1, 1}, .max_instructions = 4096, .max_code_bytes = 1024 * 1024,
        .argument_cbuf = 1, .record_assembly = 1};
}
static struct stela_nv_air_compilation *compile(const struct nv_device_info *device,
    const struct nak_compiler *nak, struct stela_metal_assembly *library, uint32_t selected,
    const struct stela_nv_air_options *opts, enum stela_nv_air_status expected)
{
    struct stela_nv_air_compilation *owner = NULL; struct stela_nv_air_error error;
#ifdef STELA_NV_AIR_ALLOC_TEST
    unsigned baseline = live_allocations;
#endif
    enum stela_nv_air_status status = stela_nv_air_compile(device, nak, library, selected, opts, &owner, &error);
    if (status != expected) fprintf(stderr, "SM%u status%u expected%u: %s (AIR%u %s)\n",
        device->sm, status, expected, error.detail, error.air.kind, error.air.detail);
    CHECK(status == expected && error.status == status && (owner != NULL) == (status == STELA_NV_AIR_OK));
#ifdef STELA_NV_AIR_ALLOC_TEST
    if (status != STELA_NV_AIR_OK) CHECK(live_allocations == baseline);
#endif
    return owner;
}
static void destroy(struct stela_nv_air_compilation **owner)
{
    stela_nv_air_destroy(owner); CHECK(!*owner); stela_nv_air_destroy(owner); stela_nv_air_destroy(NULL);
}
struct reference {const struct stela_nv_air_provenance *p;};
static bool reference_threadgroup(const struct stela_air_buffer *buffer,
    struct stela_air_threadgroup_view *view,void *data)
{
    const struct reference *ref=data;
    for(unsigned i=0;i<ref->p->threadgroup.count;i++) {
        const struct stela_metal_threadgroup_binding *row=&ref->p->threadgroup.bindings[i];
        if(row->buffer.argument==buffer->argument) {
            CHECK(row->buffer.index==buffer->index&&buffer->address_space==3&&
                row->buffer.type_size==buffer->type_size&&row->buffer.type_alignment==buffer->type_alignment);
            *view=(struct stela_air_threadgroup_view){.size=row->bytes,.alignment=row->alignment,
                .available_access=STELA_AIR_READ_WRITE};return true;
        }
    }
    CHECK(false);return false;
}
static nir_def *reference_bind(nir_builder *b, const struct stela_air_buffer *buffer, void *data)
{
    struct reference *ref = data; unsigned row = 0;
    for (unsigned i = 0; i < ref->p->argument_count; i++) {
        const struct stela_air_argument_info *arg = &ref->p->arguments[i];
        if (arg->kind != 1 || arg->buffer.address_space != 1) continue;
        if (arg->buffer.argument == buffer->argument) {
            CHECK(arg->buffer.index == buffer->index && buffer->address_space == 1);
            if (!arg->used) return nir_undef(b, 1, 64);
            return nir_ldc_nv(b, 1, 64, nir_imm_int(b, (int)ref->p->options.argument_cbuf),
                nir_imm_int(b, 0), .base = row * 8, .align_mul = 8, .align_offset = 0);
        }
        if (arg->used) row++;
    }
    CHECK(false); return NULL;
}
static uint64_t get64(const uint8_t *bytes)
{
    uint64_t value = 0; for (unsigned i = 0; i < 8; i++) value |= (uint64_t)bytes[i] << (8 * i); return value;
}
static uint64_t bits(const uint32_t *words, unsigned start, unsigned end)
{
    CHECK(end >= start && end - start <= 64 && end <= NAK_MAX_QMD_SIZE_B * 8);
    uint64_t value = 0;
    for (unsigned i = start; i < end; i++) value |= (uint64_t)((words[i / 32] >> (i % 32)) & 1) << (i - start);
    return value;
}
static void qmd(const struct nv_device_info *device, const struct stela_nv_air_compilation *owner,
    uint32_t count, uint32_t table_bytes)
{
    const struct nak_shader_bin *bin = stela_nv_air_binary(owner);
    const struct stela_nv_air_provenance *p = stela_nv_air_provenance(owner);
    struct stela_nv_compute_dispatch dispatch = {.qmd = {.addr = 0x800000, .smem_size = bin->info.cs.smem_size,
        .global_size = {1, 2, 3}, .num_cbufs = count ? 1 : 0}, .qmd_addr = 0x900000, .va_bits = 40};
    if (count) dispatch.qmd.cbufs[0] = (struct nak_qmd_cbuf) {.index = p->options.argument_cbuf,
        .size = table_bytes, .addr = 0x400000};
    struct stela_nv_compute_encoded encoded; enum stela_nv_compute_error error;
    bool valid = stela_nv_compute_encode(device, bin, &dispatch, &encoded, &error);
    if (bin->info.slm_size || bin->info.crs_size) { CHECK(!valid && error == STELA_NV_COMPUTE_SCRATCH_UNSUPPORTED); return; }
    CHECK(valid && error == STELA_NV_COMPUTE_OK && encoded.push_dw == 3);
    uint32_t original[NAK_MAX_QMD_DWORDS] = {0}; nak_fill_qmd(device, &bin->info, &dispatch.qmd, original, encoded.qmd_size_B);
    CHECK(!memcmp(original, encoded.qmd, encoded.qmd_size_B));
    uint32_t shared, barriers;
    if (device->cls_compute >= BLACKWELL_COMPUTE_A) {
        shared = NVVAL_MW_GET(encoded.qmd, NVCDC0, QMDV05_00, SHARED_MEMORY_SIZE_SHIFTED7) << 7;
        barriers = NVVAL_MW_GET(encoded.qmd, NVCDC0, QMDV05_00, BARRIER_COUNT);
    } else if (device->cls_compute >= HOPPER_COMPUTE_A) {
        shared = NVVAL_MW_GET(encoded.qmd, NVCBC0, QMDV04_00, SHARED_MEMORY_SIZE);
        barriers = NVVAL_MW_GET(encoded.qmd, NVCBC0, QMDV04_00, BARRIER_COUNT);
    } else if (device->cls_compute >= AMPERE_COMPUTE_A) {
        shared = NVVAL_MW_GET(encoded.qmd, NVC6C0, QMDV03_00, SHARED_MEMORY_SIZE);
        barriers = NVVAL_MW_GET(encoded.qmd, NVC6C0, QMDV03_00, BARRIER_COUNT);
    } else {
        shared = NVVAL_MW_GET(encoded.qmd, NVC3C0, QMDV02_02, SHARED_MEMORY_SIZE);
        barriers = NVVAL_MW_GET(encoded.qmd, NVC3C0, QMDV02_02, BARRIER_COUNT);
    }
    CHECK(shared == ALIGN_POT((unsigned)bin->info.cs.smem_size, 256) && barriers == bin->info.num_control_barriers);
    if (!count) return;
    unsigned slot = p->options.argument_cbuf;
    struct nak_qmd_cbuf_desc_layout layout = nak_get_qmd_cbuf_desc_layout(device, (uint8_t)slot);
    uint64_t address = bits(encoded.qmd, layout.addr_lo_start, layout.addr_lo_end) |
        (bits(encoded.qmd, layout.addr_hi_start, layout.addr_hi_end) << (layout.addr_lo_end - layout.addr_lo_start));
    CHECK((address << layout.addr_shift) == dispatch.qmd.cbufs[0].addr);
    uint64_t size;
    if (device->cls_compute >= BLACKWELL_COMPUTE_A)
        size = NVVAL_MW_GET(encoded.qmd, NVCDC0, QMDV05_00, CONSTANT_BUFFER_SIZE_SHIFTED4, slot) << 4;
    else if (device->cls_compute >= HOPPER_COMPUTE_A)
        size = NVVAL_MW_GET(encoded.qmd, NVCBC0, QMDV04_00, CONSTANT_BUFFER_SIZE_SHIFTED4, slot) << 4;
    else if (device->cls_compute >= AMPERE_COMPUTE_A)
        size = NVVAL_MW_GET(encoded.qmd, NVC6C0, QMDV03_00, CONSTANT_BUFFER_SIZE_SHIFTED4, slot) << 4;
    else size = NVVAL_MW_GET(encoded.qmd, NVC3C0, QMDV02_02, CONSTANT_BUFFER_SIZE_SHIFTED4, slot) << 4;
    CHECK(size == table_bytes);
}
static void specialize(nir_shader *shader, const uint8_t *table, unsigned count,
    const uint64_t *addresses)
{
    nir_foreach_function_impl(impl, shader) {
        nir_builder b = nir_builder_create(impl);
        nir_foreach_block(block, impl) {
            nir_foreach_instr_safe(instr, block) {
                if (instr->type != nir_instr_type_intrinsic) continue;
                nir_intrinsic_instr *intr = nir_instr_as_intrinsic(instr); nir_def *value = NULL;
                b.cursor = nir_before_instr(instr);
                if (intr->intrinsic == nir_intrinsic_ldc_nv) {
                    CHECK(nir_intrinsic_base(intr) >= 0);
                    unsigned offset = (unsigned)nir_intrinsic_base(intr); CHECK(offset % 8 == 0 && offset / 8 < count);
                    value = nir_imm_int64(&b, (int64_t)get64(table + offset));
                } else if (intr->intrinsic == nir_intrinsic_load_global_invocation_id ||
                    intr->intrinsic == nir_intrinsic_load_workgroup_id || intr->intrinsic == nir_intrinsic_load_local_invocation_id)
                    value = nir_imm_ivec3(&b, 0, 0, 0);
                if (value) { nir_def_rewrite_uses(&intr->def, value); nir_instr_remove(instr); }
            }
        }
    }
    bool progress;
    do { progress = nir_opt_constant_folding(shader); progress |= nir_opt_copy_prop(shader);
         progress |= nir_opt_algebraic(shader); progress |= nir_opt_dce(shader); } while (progress);
    unsigned loads[AIR_MAX_ARGUMENTS] = {0}, stores[AIR_MAX_ARGUMENTS] = {0};
    nir_foreach_function_impl(impl, shader) {
        nir_foreach_block(block, impl) {
            nir_foreach_instr(instr, block) {
                if (instr->type != nir_instr_type_intrinsic) continue;
                nir_intrinsic_instr *intr = nir_instr_as_intrinsic(instr); nir_src *address; unsigned *seen;
                if (intr->intrinsic == nir_intrinsic_load_global) { address = &intr->src[0]; seen = loads; }
                else if (intr->intrinsic == nir_intrinsic_store_global) { address = &intr->src[1]; seen = stores; }
                else continue;
                CHECK(nir_src_is_const(*address)); unsigned row;
                for (row = 0; row < count; row++) if (nir_src_as_uint(*address) == addresses[row]) break;
                CHECK(row < count); seen[row]++;
            }
        }
    }
    for (unsigned i = 0; i < count; i++) CHECK(loads[i] == 1 && stores[i] == 1);
}
static void validate(const struct nv_device_info *device, const struct nak_compiler *nak,
    const struct stela_metal_assembly *library, struct stela_nv_air_compilation *owner,
    const char *label, bool semantic)
{
    const struct nak_shader_bin *bin = stela_nv_air_binary(owner);
    const struct stela_nv_air_provenance *p = stela_nv_air_provenance(owner);
    uint32_t count, table_bytes; const struct stela_nv_air_binding *map = stela_nv_air_bindings(owner, &count, &table_bytes);
    CHECK(bin && p && map && bin->code && bin->code_size && stela_nv_air_nir(owner)->options);
    CHECK(table_bytes == ((count * 8 + 63) & ~63u));
    struct stela_nv_air_buffer_view views[AIR_MAX_ARGUMENTS]; uint64_t addresses[AIR_MAX_ARGUMENTS];
    for (unsigned i = 0; i < count; i++) {
        unsigned reverse = count - 1 - i;
        CHECK(map[i].cbuf_offset == i * 8);
        views[reverse] = (struct stela_nv_air_buffer_view) {.device = device, .owner = &views[reverse],
            .argument = map[i].buffer.argument, .index = map[i].buffer.index, .available_access = STELA_AIR_READ_WRITE,
            .allocation_va = UINT64_C(0x100000) + i * 4096u, .allocation_bytes = 4096, .offset = 256, .bytes = 2048};
        addresses[i] = views[reverse].allocation_va + views[reverse].offset;
    }
    uint8_t table[2 * AIR_MAX_ARGUMENTS * 8], second[sizeof(table)]; memset(table, 0xa5, sizeof(table));
    CHECK(stela_nv_air_pack_arguments(owner, device, 40, views, count, table, sizeof(table)) == STELA_NV_AIR_OK);
    for (unsigned i = 0; i < count; i++) CHECK(get64(table + i * 8) == addresses[i]);
    for (unsigned i = count * 8; i < table_bytes; i++) CHECK(table[i] == 0);
    for (unsigned i = table_bytes; i < sizeof(table); i++) CHECK(table[i] == 0xa5);
    blake3_hash hash, after; _mesa_blake3_compute(bin->code, bin->code_size, hash);
    for (unsigned i = 0; i < count; i++) views[i].allocation_va += 0x1000000;
    CHECK(stela_nv_air_pack_arguments(owner, device, 40, views, count, second, sizeof(second)) == STELA_NV_AIR_OK);
    for (unsigned i = 0; i < count; i++) CHECK(get64(second + i * 8) == addresses[i] + 0x1000000);
    _mesa_blake3_compute(bin->code, bin->code_size, after); CHECK(!memcmp(hash, after, sizeof(hash)));
    struct stela_metal_input_view original = {.size = sizeof(original), .abi = STELA_METAL_INPUT_ABI};
    CHECK(stela_metal_assembly_original(library, &original, NULL) == STELA_METAL_ASSEMBLY_OK);
    struct reference ref = {.p = p}; const struct stela_air_options opts = {
        .workgroup_size = {p->options.workgroup_size[0], p->options.workgroup_size[1], p->options.workgroup_size[2]},
        .max_instructions = p->options.max_instructions, .fp_profile = p->options.fp_profile,
        .bind_buffer = reference_bind, .binding_data = &ref,
        .bind_threadgroup=p->threadgroup.count?reference_threadgroup:NULL,
        .max_threadgroup_bytes = MIN2((unsigned)device->max_smem_per_wg_kB * 1024, UINT16_MAX)};
    struct stela_air_error error;
    nir_shader *nir = stela_air_to_nir(original.bytes + p->air_offset, (size_t)p->air_bytes, p->name,
        stela_nv_air_nir(owner)->options, &opts, &error); CHECK(nir);
    if (semantic) { nir_shader *copy = nir_shader_clone(NULL, nir); CHECK(copy); specialize(copy, table, count, addresses); ralloc_free(copy); }
    nak_preprocess_nir(nir, nak);
    struct nak_shader_bin *original_bin = nak_compile_shader(nir, true, nak, 0, NULL, false);
    CHECK(original_bin && original_bin->code_size == bin->code_size && !memcmp(original_bin->code, bin->code, bin->code_size) &&
        !memcmp(&original_bin->info, &bin->info, sizeof(bin->info)));
    nak_shader_bin_destroy(original_bin); ralloc_free(nir);
    qmd(device, owner, count, table_bytes);
    char digest[BLAKE3_HEX_LEN]; _mesa_blake3_format(digest, hash);
    printf("owned-air-nak input=%s sm=%u buffers=%u cbuf=%u table_bytes=%u code_bytes=%u code_blake3=%s gprs=%u shared=%u barriers=%u scratch=%u stack=%u\n",
        label, device->sm, count, p->options.argument_cbuf, table_bytes, bin->code_size, digest, bin->info.num_gprs,
        bin->info.cs.smem_size, bin->info.num_control_barriers, bin->info.slm_size, bin->info.crs_size);
}
static void targets(struct stela_metal_assembly *library, enum stela_air_fp_profile fp, const char *label, bool semantic)
{
    const struct {unsigned sm, cls;} targets[] = {{75,TURING_COMPUTE_A},{80,AMPERE_COMPUTE_A},{86,AMPERE_COMPUTE_B},
        {87,AMPERE_COMPUTE_B},{89,ADA_COMPUTE_A},{90,HOPPER_COMPUTE_A},{100,BLACKWELL_COMPUTE_A},
        {104,BLACKWELL_COMPUTE_A},{120,BLACKWELL_COMPUTE_B}};
    for (unsigned i = 0; i < ARRAY_SIZE(targets); i++) {
        struct nv_device_info device = model(targets[i].sm, targets[i].cls); struct nak_compiler *nak = compiler(&device);
        struct stela_nv_air_options opts = options(); opts.fp_profile = fp;
        struct stela_nv_air_compilation *owner = compile(&device, nak, library, 0, &opts, STELA_NV_AIR_OK);
        validate(&device, nak, library, owner, label, semantic); nak_compiler_destroy(nak);
        nir_validate_shader((nir_shader *)stela_nv_air_nir(owner), "owned options after compiler destruction"); destroy(&owner);
    }
}
static void pack_failures(struct stela_nv_air_compilation *owner, const struct nv_device_info *device)
{
    uint32_t count, table_bytes; const struct stela_nv_air_binding *map = stela_nv_air_bindings(owner, &count, &table_bytes);
    CHECK(count == 1);
    struct stela_nv_air_buffer_view good = {.device=device,.owner=&good,.argument=map[0].buffer.argument,.index=map[0].buffer.index,
        .available_access=STELA_AIR_READ_WRITE,.allocation_va=0x100000,.allocation_bytes=4096,.offset=256,.bytes=2048};
    uint8_t output[2048], expected[sizeof(output)]; memset(expected, 0xa5, sizeof(expected));
    for (unsigned i = 0; i < 14; i++) {
        struct stela_nv_air_buffer_view bad = good;
        switch(i) {
        case 0: bad.argument++; break; case 1: bad.index++; break; case 2: bad.device=NULL; break;
        case 3: bad.owner=NULL; break; case 4: bad.available_access=STELA_AIR_READ; break;
        case 5: bad.available_access=7; break; case 6: bad.bytes=0; break; case 7: bad.bytes=4097; break;
        case 8: bad.offset=4097; break; case 9: bad.allocation_va=UINT64_MAX; break;
        case 10: bad.allocation_bytes=UINT64_MAX; break; case 11: bad.offset=1; break;
        case 12: bad.allocation_va=(UINT64_C(1)<<40)-2048; break; case 13: bad.bytes=1; break;
        }
        memcpy(output, expected, sizeof(output));
        CHECK(stela_nv_air_pack_arguments(owner, device, 40, &bad, 1, output, sizeof(output)) == STELA_NV_AIR_BINDING &&
            !memcmp(output, expected, sizeof(output)));
    }
    memcpy(output, expected, sizeof(output));
    CHECK(stela_nv_air_pack_arguments(owner, device, 40, &good, 1, output, table_bytes-1) == STELA_NV_AIR_BINDING &&
        !memcmp(output, expected, sizeof(output)));
    CHECK(stela_nv_air_pack_arguments(owner, device, 40, &good, 0, output, sizeof(output)) == STELA_NV_AIR_BINDING);
    CHECK(stela_nv_air_pack_arguments(owner, device, 0, &good, 1, output, sizeof(output)) == STELA_NV_AIR_INVALID);
    CHECK(stela_nv_air_pack_arguments(owner, device, 64, &good, 1, output, sizeof(output)) == STELA_NV_AIR_INVALID);
}
static void selected_and_binding_tests(void)
{
    struct nv_device_info device=model(89,ADA_COMPUTE_A); struct nak_compiler *nak=compiler(&device);
    struct stela_nv_air_options opts=options();
    const char *metadata="}\n!air.version = !{!0}\n!air.language_version = !{!1}\n"
        "!air.kernel = !{!2,!7}\n!0 = !{i32 2, i32 8, i32 0}\n"
        "!1 = !{!\"Metal\", i32 4, i32 0, i32 0}\n!2 = !{ptr @kernel, !3, !4}\n"
        "!3 = !{}\n!4 = !{!5,!6}\n!5 = !{i32 0, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\"}\n"
        "!6 = !{i32 1, !\"air.buffer\", !\"air.location_index\", i32 13, i32 1, !\"air.write\","
        " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"
        " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"result\"}\n!7 = !{ptr @other, !3, !4}\n";
    LLVMMemoryBufferRef air=stela_air_test_custom_bitcode(stela_air_test_prefix,
        "store i32 11, ptr addrspace(1) %out, align 4\nret void\n",metadata,
        "define void @other(i32 %tid, ptr addrspace(1) %out) {\nstore i32 99, ptr addrspace(1) %out, align 4\nret void\n}\n");
    struct stela_metal_assembly *library=two_entries(air); LLVMDisposeMemoryBuffer(air);
    struct stela_nv_air_compilation *owner=compile(&device,nak,library,1,&opts,STELA_NV_AIR_OK);
    const struct stela_nv_air_provenance *p=stela_nv_air_provenance(owner);
    CHECK(p->selected_entry==1&&!strcmp(p->name,"other")&&p->input.entry_count==2&&
        p->arguments[1].buffer.index==13&&p->arguments[1].buffer.access==STELA_AIR_WRITE&&
        !p->arguments[0].name&&!p->arguments[0].name_bytes);
    validate(&device,nak,library,owner,"selected-second-entry",false);
    unsigned stores=0;
    nir_foreach_function_impl(impl,(nir_shader *)stela_nv_air_nir(owner)) {
        nir_foreach_block(block,impl) {
            nir_foreach_instr(instr,block) {
                if(instr->type!=nir_instr_type_intrinsic)continue;
                nir_intrinsic_instr *intr=nir_instr_as_intrinsic(instr);
                if(intr->intrinsic==nir_intrinsic_store_global||intr->intrinsic==nir_intrinsic_store_global_nv) {
                    CHECK(nir_src_is_const(intr->src[0])&&nir_src_as_uint(intr->src[0])==99);stores++;
                }
            }
        }
    }
    CHECK(stores==1);
    stela_metal_assembly_destroy(&library);
    CHECK(!strcmp(p->name,"other")&&!strcmp(p->arguments[1].name,"result"));
    destroy(&owner);
    air=multibuffer(2); library=fixture(air); LLVMDisposeMemoryBuffer(air);
    /* Distinct compiled owners coexist, with independently stable NIR options.
     * Both extreme legal cbuf slots and genuine3D specialization reach QMD. */
    opts.argument_cbuf=0; opts.workgroup_size[0]=4;opts.workgroup_size[1]=2;opts.workgroup_size[2]=2;
    owner=compile(&device,nak,library,0,&opts,STELA_NV_AIR_OK);
    opts.argument_cbuf=7;
    struct stela_nv_air_compilation *other=compile(&device,nak,library,0,&opts,STELA_NV_AIR_OK);
    validate(&device,nak,library,other,"slot-seven-3d",true); destroy(&other);
    validate(&device,nak,library,owner,"slot-zero-after-other-owner-destroy",true);
    uint32_t count,extent;const struct stela_nv_air_binding *map=stela_nv_air_bindings(owner,&count,&extent);CHECK(count==2);
    struct stela_nv_air_buffer_view views[2];
    for(unsigned i=0;i<2;i++) views[i]=(struct stela_nv_air_buffer_view){.device=&device,.owner=&views[i],
        .argument=map[i].buffer.argument,.index=map[i].buffer.index,.available_access=STELA_AIR_READ_WRITE,
        .allocation_va=0x100000,.allocation_bytes=4096,.bytes=4096};
    uint8_t table[64],expected[64];memset(expected,0xa5,sizeof(expected));memcpy(table,expected,sizeof(table));
    views[1].argument=views[0].argument;views[1].index=views[0].index;
    CHECK(stela_nv_air_pack_arguments(owner,&device,40,views,2,table,sizeof(table))==STELA_NV_AIR_BINDING&&!memcmp(table,expected,sizeof(table)));
    views[1].argument=map[1].buffer.argument;views[1].index=map[1].buffer.index;
    /* Resource aliasing is permitted by this plain-buffer ABI; it is not
     * interpreted as a duplicate metadata key or a new ownership guarantee. */
    CHECK(stela_nv_air_pack_arguments(owner,&device,40,views,2,table,sizeof(table))==STELA_NV_AIR_OK&&get64(table)==get64(table+8));
    struct nv_device_info mismatch=device;mismatch.cls_compute=AMPERE_COMPUTE_B;
    memcpy(table,expected,sizeof(table));
    CHECK(stela_nv_air_pack_arguments(owner,&mismatch,40,views,2,table,sizeof(table))==STELA_NV_AIR_DEVICE&&!memcmp(table,expected,sizeof(table)));
    destroy(&owner);stela_metal_assembly_destroy(&library);nak_compiler_destroy(nak);
}
static void original_tests(void)
{
    selected_and_binding_tests();
    LLVMMemoryBufferRef air = stela_air_test_bitcode(stela_air_test_store_body, "");
    struct stela_metal_assembly *library = fixture(air); LLVMDisposeMemoryBuffer(air);
    targets(library, STELA_AIR_FP_IEEE_DEFAULT, "original-integer", false);
    struct nv_device_info device = model(89, ADA_COMPUTE_A); struct nak_compiler *nak = compiler(&device);
    struct stela_nv_air_options opts=options();
    CHECK(!nak->nir_options.cb_data);
    unsigned before_callback_refusal=allocations;
    nak->nir_options.cb_data=&device;
    CHECK(!compile(&device,nak,library,0,&opts,STELA_NV_AIR_UNSUPPORTED)&&allocations==before_callback_refusal);
    nak->nir_options.cb_data=NULL;
    struct stela_nv_air_compilation *owner=compile(&device,nak,library,0,&opts,STELA_NV_AIR_OK);
    pack_failures(owner,&device);
    const struct stela_nv_air_provenance *p=stela_nv_air_provenance(owner);
    const struct stela_metal_library_manifest *m=stela_metal_assembly_manifest(library);
    CHECK(!memcmp(&p->input,&m->input,sizeof(p->input)) && !memcmp(&p->entry,&m->entries[0].entry,sizeof(p->entry)) &&
        !memcmp(p->air_sha256,m->entries[0].air_sha256,32) && p->air_offset==m->entries[0].air_offset &&
        p->arguments[1].name!=m->entries[0].arguments[1].name && !strcmp(p->arguments[1].name,m->entries[0].arguments[1].name));
    stela_metal_assembly_destroy(&library); nak_compiler_destroy(nak);
    CHECK(!strcmp(p->name,"kernel") && !strcmp(p->arguments[1].type_name,"uint"));
    nir_validate_shader((nir_shader *)stela_nv_air_nir(owner),"after all input/compiler storage destruction");
    destroy(&owner);
    for(unsigned buffers=0;buffers<=31;buffers++) {
        air=multibuffer(buffers); library=fixture(air); LLVMDisposeMemoryBuffer(air);
        targets(library,STELA_AIR_FP_IEEE_DEFAULT,"generic-buffer-indices",true); stela_metal_assembly_destroy(&library);
    }
    air=stela_air_test_bitcode("ret void\n", ""); library=fixture(air); LLVMDisposeMemoryBuffer(air);
    targets(library,STELA_AIR_FP_IEEE_DEFAULT,"unused-buffer-no-effects",true); stela_metal_assembly_destroy(&library);
    air=stela_air_test_bitcode(stela_air_test_store_body, ""); library=fixture(air); LLVMDisposeMemoryBuffer(air); nak=compiler(&device);
    struct stela_nv_air_options bad=opts; bad.max_code_bytes=4; CHECK(!compile(&device,nak,library,0,&bad,STELA_NV_AIR_LIMIT));
    bad=opts; bad.max_instructions=1; CHECK(!compile(&device,nak,library,0,&bad,STELA_NV_AIR_FRONTEND));
    bad=opts; bad.argument_cbuf=8; CHECK(!compile(&device,nak,library,0,&bad,STELA_NV_AIR_UNSUPPORTED));
    bad=opts; bad.workgroup_size[2]=65; CHECK(!compile(&device,nak,library,0,&bad,STELA_NV_AIR_UNSUPPORTED));
    bad=opts; bad.fp_profile=(enum stela_air_fp_profile)99; CHECK(!compile(&device,nak,library,0,&bad,STELA_NV_AIR_UNSUPPORTED));
    struct nv_device_info mismatch=device; mismatch.sm=86; CHECK(!compile(&mismatch,nak,library,0,&opts,STELA_NV_AIR_DEVICE));
    mismatch=device; mismatch.max_warps_per_mp--; CHECK(!compile(&mismatch,nak,library,0,&opts,STELA_NV_AIR_DEVICE));
    CHECK(!compile(&device,nak,library,1,&opts,STELA_NV_AIR_INVALID));
    bad=opts;bad.size--;CHECK(!compile(&device,nak,library,0,&bad,STELA_NV_AIR_INVALID));
    bad=opts;bad.abi++;CHECK(!compile(&device,nak,library,0,&bad,STELA_NV_AIR_INVALID));
    bad=opts;bad.max_code_bytes=0;CHECK(!compile(&device,nak,library,0,&bad,STELA_NV_AIR_LIMIT));
    bad=opts;bad.max_code_bytes=UINT32_MAX;CHECK(!compile(&device,nak,library,0,&bad,STELA_NV_AIR_LIMIT));
    bad=opts;bad.record_assembly=2;CHECK(!compile(&device,nak,library,0,&bad,STELA_NV_AIR_UNSUPPORTED));
    bad=opts;bad.workgroup_size[0]=0;CHECK(!compile(&device,nak,library,0,&bad,STELA_NV_AIR_UNSUPPORTED));
    bad=opts;bad.workgroup_size[0]=1024;bad.workgroup_size[1]=2;CHECK(!compile(&device,nak,library,0,&bad,STELA_NV_AIR_UNSUPPORTED));
    mismatch=device;mismatch.sm_smem_size_count=0;CHECK(!compile(&mismatch,nak,library,0,&opts,STELA_NV_AIR_DEVICE));
    mismatch=device;mismatch.sm_smem_sizes_kB[1]++;CHECK(!compile(&mismatch,nak,library,0,&opts,STELA_NV_AIR_DEVICE));
    mismatch=device;mismatch.sm_smem_sizes_kB[1]=mismatch.sm_smem_sizes_kB[0];CHECK(!compile(&mismatch,nak,library,0,&opts,STELA_NV_AIR_DEVICE));
    owner=compile(&device,nak,library,0,&opts,STELA_NV_AIR_OK);
    struct stela_nv_air_compilation *retained=owner;struct stela_nv_air_error error;
    CHECK(stela_nv_air_compile(&device,nak,library,0,&opts,&owner,&error)==STELA_NV_AIR_INVALID&&owner==retained);
    CHECK(stela_nv_air_compile(NULL,nak,library,0,&opts,&owner,&error)==STELA_NV_AIR_INVALID&&owner==retained);
    destroy(&owner);
    bad=opts;bad.record_assembly=0;owner=compile(&device,nak,library,0,&bad,STELA_NV_AIR_OK);
    CHECK(!stela_nv_air_binary(owner)->asm_str);validate(&device,nak,library,owner,"without-assembly-text",false);destroy(&owner);
#ifdef STELA_NV_AIR_ALLOC_TEST
    allocations=0; owner=compile(&device,nak,library,0,&opts,STELA_NV_AIR_OK); CHECK(allocations==2); destroy(&owner);
    for(unsigned fail=1;fail<=2;fail++) { allocations=0;fail_allocation=fail;CHECK(!compile(&device,nak,library,0,&opts,STELA_NV_AIR_ALLOCATION)&&!live_allocations); }
    fail_allocation=0;
#endif
    stela_metal_assembly_destroy(&library);
    air=stela_air_test_bitcode("call void @unsupported()\nret void\n","declare void @unsupported()\n");
    library=fixture(air);LLVMDisposeMemoryBuffer(air);
    CHECK(!compile(&device,nak,library,0,&opts,STELA_NV_AIR_FRONTEND));
    stela_metal_assembly_destroy(&library);
    /* Complete dynamic AS3 reflection reaches this owner's explicit missing
     * dispatch-specialization refusal, rather than the canonical inspector's
     * separate refusal for incomplete module-global reflection. */
    air=stela_air_test_custom_bitcode(
        "target datalayout = \"e-p:64:64-i64:64-n8:16:32\"\n"
        "target triple = \"air64_v29-apple-macosx27.2.0\"\n"
        "define void @kernel(i32 %tid, ptr addrspace(3) %scratch) {\n",
        "store i32 %tid, ptr addrspace(3) %scratch, align 4\nret void\n",
        "}\n!air.version = !{!0}\n!air.language_version = !{!1}\n!air.kernel = !{!2}\n"
        "!0 = !{i32 2, i32 9, i32 0}\n!1 = !{!\"Metal\", i32 4, i32 1, i32 0}\n"
        "!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n!4 = !{!5,!6}\n"
        "!5 = !{i32 0, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"tid\"}\n"
        "!6 = !{i32 1, !\"air.buffer\", !\"air.location_index\", i32 7, i32 1, !\"air.read_write\","
        " !\"air.address_space\", i32 3, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"
        " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"scratch\"}\n","");
    struct bytes shared=archive(LLVMGetBufferStart(air),LLVMGetBufferSize(air),"kernel",9,4,1,27,2);
    library=assemble(&shared);free(shared.data);LLVMDisposeMemoryBuffer(air);
    CHECK(!compile(&device,nak,library,0,&opts,STELA_NV_AIR_UNSUPPORTED));
    nak_compiler_destroy(nak); stela_metal_assembly_destroy(&library);
    CHECK(!stela_nv_air_binary(NULL)&&!stela_nv_air_nir(NULL)&&!stela_nv_air_provenance(NULL));
    puts("owned NAK compiler/table/QMD/lifetime/failure fixtures passed; no hardware execution");
}
static struct bytes read_file(const char *path)
{
    FILE *f=fopen(path,"rb");CHECK(f&&!fseek(f,0,SEEK_END));long size=ftell(f);
    CHECK(size>0&&size<=AIR_MAX_BITCODE_BYTES&&!fseek(f,0,SEEK_SET));
    struct bytes b={.data=malloc((size_t)size),.size=(size_t)size};CHECK(b.data);
    CHECK(fread(b.data,1,b.size,f)==b.size&&fgetc(f)==EOF&&!ferror(f)&&!fclose(f));return b;
}
struct facts {const char *name;unsigned air,major,minor,osmajor,osminor;bool found;};
static bool inspect(const struct stela_air_inspection *i,const struct stela_air_entry *e,void *data)
{
    struct facts *f=data;if(strlen(f->name)!=e->name_bytes||memcmp(f->name,e->name,e->name_bytes))return true;
    f->found=true;f->air=i->air_minor;f->major=i->language_major;f->minor=i->language_minor;
    CHECK(sscanf(i->target,"air64_v%*u-apple-macosx%u.%u.",&f->osmajor,&f->osminor)==2);return true;
}
static void source_input(int argc,char **argv)
{
    CHECK(argc==5); /* --source ORIGINAL_MSL ORIGINAL_ADAPTER_AIR INDEPENDENT_IDENTITY_208_BYTES */
    struct bytes source=read_file(argv[2]),air=read_file(argv[3]),identity=read_file(argv[4]);CHECK(identity.size==208);
    struct stela_msl_output compiled={.air=air.data,.air_bytes=air.size};
    memcpy(compiled.source_sha256,identity.data,32);memcpy(compiled.air_sha256,identity.data+32,32);
    memcpy(&compiled.build,identity.data+64,sizeof(compiled.build));
    struct stela_msl_apple_config config=stela_msl_apple_default_config();
    struct stela_msl_request request={.source=source.data,.source_bytes=source.size,.language_version=0x40001,
        .fast_math=true,.target_triple="air64_v29-apple-macosx27.2.0"};
    struct stela_metal_assembly_options assembly_options=stela_metal_assembly_default_options();
    struct stela_metal_assembly_error error;struct stela_metal_assembly *library=NULL;
    CHECK(stela_metal_assemble_source(&assembly_options,&config,&request,&compiled,&library,&error)==STELA_METAL_ASSEMBLY_OK);
    struct nv_device_info device=model(89,ADA_COMPUTE_A);struct nak_compiler *nak=compiler(&device);
    struct stela_nv_air_options opts=options();opts.fp_profile=STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41;
    struct stela_nv_air_compilation *owner=compile(&device,nak,library,0,&opts,STELA_NV_AIR_OK);
    validate(&device,nak,library,owner,"original-source-owner",false);
    free(air.data);free(source.data);stela_metal_assembly_destroy(&library);nak_compiler_destroy(nak);
    const struct stela_nv_air_provenance *p=stela_nv_air_provenance(owner);
    CHECK(p->library_flags==STELA_METAL_LIBRARY_SOURCE_COMPILED&&p->compiler_profile==config.profile&&
        p->request_language==0x40001&&p->request_fast_math==1&&
        !memcmp(p->source_sha256,identity.data,32)&&!memcmp(p->input.original_sha256,identity.data+32,32)&&
        !memcmp(&p->build,identity.data+64,sizeof(p->build)));
    free(identity.data);nir_validate_shader((nir_shader *)stela_nv_air_nir(owner),"source owner after input/compiler destruction");destroy(&owner);
}
static void requested_threadgroups(int argc,char **argv,struct stela_metal_threadgroup_request_row *rows)
{
    CHECK(argc>=6&&argc-5<=(int)AIR_MAX_ARGUMENTS);
    for(int i=5;i<argc;i++) {
        char *end;errno=0;CHECK(argv[i][0]>='0'&&argv[i][0]<='9');
        unsigned long long index=strtoull(argv[i],&end,10);CHECK(!errno&&index<=UINT32_MAX&&*end==':');
        const char *start=end+1;CHECK(*start>='0'&&*start<='9');errno=0;
        unsigned long long bytes=strtoull(start,&end,10);CHECK(!errno&&!*end);
        rows[i-5]=(struct stela_metal_threadgroup_request_row){.index=(uint32_t)index,.bytes=(uint64_t)bytes};
    }
}
static void threadgroup_input(int argc,char **argv)
{
    struct stela_metal_threadgroup_request_row rows[AIR_MAX_ARGUMENTS]={0};requested_threadgroups(argc,argv,rows);
    char *end;errno=0;unsigned long workgroup=strtoul(argv[4],&end,10);CHECK(!errno&&!*end&&workgroup&&workgroup<=1024);
    struct stela_metal_threadgroup_request request={.size=sizeof(request),.abi=STELA_METAL_THREADGROUP_ABI,
        .count=(uint32_t)(argc-5),.rows=rows};
    struct bytes air=read_file(argv[2]);struct facts f={.name=argv[3]};struct stela_air_error air_error;
    CHECK(stela_air_inspect(air.data,air.size,256,inspect,&f,&air_error)&&f.found);
    struct bytes bytes=archive(air.data,air.size,f.name,f.air,f.major,f.minor,f.osmajor,f.osminor);
    struct stela_metal_assembly *library=assemble(&bytes);free(bytes.data);free(air.data);
    const struct {unsigned sm,cls;} targets[]={{75,TURING_COMPUTE_A},{80,AMPERE_COMPUTE_A},{86,AMPERE_COMPUTE_B},
        {87,AMPERE_COMPUTE_B},{89,ADA_COMPUTE_A},{90,HOPPER_COMPUTE_A},{100,BLACKWELL_COMPUTE_A},
        {104,BLACKWELL_COMPUTE_A},{120,BLACKWELL_COMPUTE_B}};
    for(unsigned i=0;i<ARRAY_SIZE(targets);i++) {
        struct nv_device_info device=model(targets[i].sm,targets[i].cls);struct nak_compiler *nak=compiler(&device);
        struct stela_nv_air_options opts=options();opts.workgroup_size[0]=(uint32_t)workgroup;
        struct stela_nv_air_compilation *owner=NULL;struct stela_nv_air_error error;
        CHECK(stela_nv_air_compile_specialized(&device,nak,library,0,&opts,&request,&owner,&error)==STELA_NV_AIR_OK&&owner);
        const struct stela_nv_air_provenance *p=stela_nv_air_provenance(owner);
        if(i==0) {
            struct stela_metal_threadgroup_request bad_request=request;
            struct stela_nv_air_compilation *failed=NULL;
            bad_request.size--;
            CHECK(stela_nv_air_compile_specialized(&device,nak,library,0,&opts,&bad_request,&failed,&error)==STELA_NV_AIR_INVALID&&!failed);
            bad_request=request;bad_request.count=0;
            CHECK(stela_nv_air_compile_specialized(&device,nak,library,0,&opts,&bad_request,&failed,&error)==STELA_NV_AIR_UNSUPPORTED&&!failed);
            bad_request=request;
            struct stela_metal_threadgroup_request_row bad_rows[AIR_MAX_ARGUMENTS];memcpy(bad_rows,rows,sizeof(rows));
            bad_request.rows=bad_rows;bad_rows[0].bytes=0;
            CHECK(stela_nv_air_compile_specialized(&device,nak,library,0,&opts,&bad_request,&failed,&error)==STELA_NV_AIR_UNSUPPORTED&&!failed);
            bad_rows[0].bytes=UINT64_C(0x100000000);
            CHECK(stela_nv_air_compile_specialized(&device,nak,library,0,&opts,&bad_request,&failed,&error)==STELA_NV_AIR_LIMIT&&!failed);
            bad_rows[0].bytes=65536;
            CHECK(stela_nv_air_compile_specialized(&device,nak,library,0,&opts,&bad_request,&failed,&error)==STELA_NV_AIR_LIMIT&&!failed); /* Before original u16 try_into(). */
#ifdef STELA_NV_AIR_ALLOC_TEST
            unsigned baseline=live_allocations;
            bad_request=request;
            for(unsigned fail=1;fail<=(2);fail++) {
                allocations=0;fail_allocation=fail;
                CHECK(stela_nv_air_compile_specialized(&device,nak,library,0,&opts,&bad_request,&failed,&error)==STELA_NV_AIR_ALLOCATION&&!failed&&live_allocations==baseline);
            }
            fail_allocation=0;
#endif
        }
        CHECK(p->threadgroup.count==request.count&&stela_metal_threadgroup_matches(&p->threadgroup,&request));
        struct stela_metal_threadgroup_request_row saved[AIR_MAX_ARGUMENTS];memcpy(saved,rows,sizeof(rows));
        rows[0].bytes+=16;CHECK(!stela_metal_threadgroup_matches(&p->threadgroup,&request));
        memset(rows,0,sizeof(rows));
        CHECK(p->threadgroup.bindings[0].bytes&&p->threadgroup.bindings[0].alignment>=16);
        memcpy(rows,saved,sizeof(rows));CHECK(stela_metal_threadgroup_matches(&p->threadgroup,&request));
        validate(&device,nak,library,owner,"dispatch-threadgroup-specialization",false);
        printf("owned-threadgroup-nak sm=%u count=%u total_shared=%u",device.sm,p->threadgroup.count,stela_nv_air_binary(owner)->info.cs.smem_size);
        for(unsigned r=0;r<p->threadgroup.count;r++)printf(" row=%u:%u:%llu:%u",p->threadgroup.bindings[r].buffer.argument,
            p->threadgroup.bindings[r].buffer.index,(unsigned long long)p->threadgroup.bindings[r].bytes,p->threadgroup.bindings[r].alignment);
        puts("");
        nak_compiler_destroy(nak);nir_validate_shader((nir_shader *)stela_nv_air_nir(owner),"dynamic options after compiler destruction");
        CHECK(stela_metal_threadgroup_matches(&p->threadgroup,&request));destroy(&owner);
    }
    stela_metal_assembly_destroy(&library);
}
static void shared_refusal(int argc,char **argv)
{
    CHECK(argc==4);
    struct bytes air=read_file(argv[2]);struct facts f={.name=argv[3]};struct stela_air_error inspect_error;
    CHECK(stela_air_inspect(air.data,air.size,256,inspect,&f,&inspect_error)&&f.found);
    struct bytes bytes=archive(air.data,air.size,f.name,f.air,f.major,f.minor,f.osmajor,f.osminor);
    struct stela_metal_assembly *library=assemble(&bytes);free(bytes.data);free(air.data);
    const struct {unsigned sm,cls;} targets[]={{75,TURING_COMPUTE_A},{80,AMPERE_COMPUTE_A},{86,AMPERE_COMPUTE_B},
        {87,AMPERE_COMPUTE_B},{89,ADA_COMPUTE_A},{90,HOPPER_COMPUTE_A},{100,BLACKWELL_COMPUTE_A},
        {104,BLACKWELL_COMPUTE_A},{120,BLACKWELL_COMPUTE_B}};
    for(unsigned i=0;i<ARRAY_SIZE(targets);i++) {
        struct nv_device_info device=model(targets[i].sm,targets[i].cls);struct nak_compiler *nak=compiler(&device);
        struct stela_nv_air_options opts=options();struct stela_nv_air_compilation *owner=NULL;struct stela_nv_air_error error;
        CHECK(stela_nv_air_compile(&device,nak,library,0,&opts,&owner,&error)==STELA_NV_AIR_UNSUPPORTED&&
            !owner&&error.status==STELA_NV_AIR_UNSUPPORTED&&error.air.kind==STELA_AIR_OK&&strstr(error.detail,"binding specialization"));
        printf("owned-air-nak entry=%s sm=%u shared_refusal=dynamic-specialization-unavailable\n",f.name,device.sm);
        nak_compiler_destroy(nak);
    }
    stela_metal_assembly_destroy(&library);
}
int main(int argc,char **argv)
{
    if(argc==1)original_tests();
    else if(!strcmp(argv[1],"--source"))source_input(argc,argv);
    else if(!strcmp(argv[1],"--threadgroup"))threadgroup_input(argc,argv);
    else if(!strcmp(argv[1],"--shared-refusal"))shared_refusal(argc,argv);
    else {
        CHECK((argc==4||argc==5)&&!strcmp(argv[1],"--input"));
        struct bytes air=read_file(argv[2]);struct facts f={.name=argv[3]};struct stela_air_error error;
        CHECK(stela_air_inspect(air.data,air.size,256,inspect,&f,&error)&&f.found);
        struct bytes bytes=archive(air.data,air.size,f.name,f.air,f.major,f.minor,f.osmajor,f.osminor);
        struct stela_metal_assembly *library=assemble(&bytes);free(air.data);free(bytes.data);
        targets(library,argc==5?(enum stela_air_fp_profile)strtoul(argv[4],NULL,10):STELA_AIR_FP_IEEE_DEFAULT,"unchanged-original-file",false);
        stela_metal_assembly_destroy(&library);
    }
#ifdef STELA_NV_AIR_ALLOC_TEST
    CHECK(!live_allocations);
#endif
    return 0;
}
