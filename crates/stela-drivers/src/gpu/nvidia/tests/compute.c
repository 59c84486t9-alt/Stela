/* SPDX-License-Identifier: MIT */
#include "../hosted/compute.h"
#include "air_to_nir.h"
#include "../../compiler/tests/air_test_fixture.h"
#include "nouveau/headers/drf.h"
#include "cl906f.h"
#include "cla0c0.h"
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
#include "../../compiler/tests/targets/nvidia.h"
#include "util/ralloc.h"

#define CHECK(condition) do { if (!(condition)) { \
   fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); exit(1); \
} } while (0)

static nir_def *
bind_buffer(nir_builder *b, const struct stela_air_buffer *buffer, void *data)
{
   CHECK(buffer->argument == 1 && buffer->index == 7 && buffer->address_space == 1 &&
         buffer->access == STELA_AIR_READ_WRITE && buffer->type_size == 4 && buffer->type_alignment == 4);
   /* Distinct from code/QMD/CB uploads; a compile fixture, not runtime memory. */
   return nir_imm_int64(b, 0x100000);
}

static uint64_t
field(const uint32_t *words, unsigned start, unsigned end)
{
   CHECK(start < end && end - start <= 32 && end <= NAK_MAX_QMD_SIZE_B * 8);
   unsigned width = end - start;
   uint64_t value = words[start / 32] >> (start % 32);
   if ((end - 1) / 32 != start / 32)
      value |= (uint64_t)words[(end - 1) / 32] << (32 - start % 32);
   return value & ((UINT64_C(1) << width) - 1);
}

static void
validate_qmd(const struct nv_device_info *dev, const struct nak_shader_info *info,
             const struct stela_nvidia_compute_dispatch *dispatch,
             const struct stela_nvidia_compute_encoded *encoded)
{
   CHECK(encoded->qmd_size_B == nak_qmd_size_B(dev));
   CHECK(encoded->qmd_size_B == (dev->sm >= 90 ? 384 : 256));
   struct nak_qmd_dispatch_size_layout sizes = nak_get_qmd_dispatch_size_layout(dev);
   CHECK(field(encoded->qmd, sizes.x_start, sizes.x_end) == dispatch->qmd.global_size[0]);
   CHECK(field(encoded->qmd, sizes.y_start, sizes.y_end) == dispatch->qmd.global_size[1]);
   CHECK(field(encoded->qmd, sizes.z_start, sizes.z_end) == dispatch->qmd.global_size[2]);
   CHECK(field(encoded->qmd, sizes.local_x_start, sizes.local_x_end) == info->cs.local_size[0]);
   CHECK(field(encoded->qmd, sizes.local_y_start, sizes.local_y_end) == info->cs.local_size[1]);
   CHECK(field(encoded->qmd, sizes.local_z_start, sizes.local_z_end) == info->cs.local_size[2]);
   for (unsigned i = 0; i < dispatch->qmd.num_cbufs; i++) {
      const struct nak_qmd_cbuf *cb = &dispatch->qmd.cbufs[i];
      struct nak_qmd_cbuf_desc_layout layout = nak_get_qmd_cbuf_desc_layout(dev, cb->index);
      uint64_t address = field(encoded->qmd, layout.addr_lo_start, layout.addr_lo_end) |
         field(encoded->qmd, layout.addr_hi_start, layout.addr_hi_end) << (layout.addr_lo_end - layout.addr_lo_start);
      CHECK(address << layout.addr_shift == cb->addr);
   }
   uint64_t program;
   if (dev->cls_compute >= BLACKWELL_COMPUTE_A) {
      CHECK(NVVAL_MW_GET(encoded->qmd, NVCDC0, QMDV05_00, QMD_MAJOR_VERSION) == 5);
      CHECK(NVVAL_MW_GET(encoded->qmd, NVCDC0, QMDV05_00, QMD_MINOR_VERSION) == 0);
      CHECK(NVVAL_MW_GET(encoded->qmd, NVCDC0, QMDV05_00, REGISTER_COUNT) == info->num_gprs);
      CHECK(NVVAL_MW_GET(encoded->qmd, NVCDC0, QMDV05_00, CONSTANT_BUFFER_SIZE_SHIFTED4, 7) * 16 == 64);
      program = (NVVAL_MW_GET(encoded->qmd, NVCDC0, QMDV05_00, PROGRAM_ADDRESS_LOWER_SHIFTED4) |
         NVVAL_MW_GET(encoded->qmd, NVCDC0, QMDV05_00, PROGRAM_ADDRESS_UPPER_SHIFTED4) << 32) << 4;
   } else if (dev->cls_compute >= HOPPER_COMPUTE_A) {
      CHECK(NVVAL_MW_GET(encoded->qmd, NVCBC0, QMDV04_00, QMD_MAJOR_VERSION) == 4);
      CHECK(NVVAL_MW_GET(encoded->qmd, NVCBC0, QMDV04_00, QMD_MINOR_VERSION) == 0);
      CHECK(NVVAL_MW_GET(encoded->qmd, NVCBC0, QMDV04_00, REGISTER_COUNT) == info->num_gprs);
      CHECK(NVVAL_MW_GET(encoded->qmd, NVCBC0, QMDV04_00, CONSTANT_BUFFER_SIZE_SHIFTED4, 7) * 16 == 64);
      program = NVVAL_MW_GET(encoded->qmd, NVCBC0, QMDV04_00, PROGRAM_ADDRESS_LOWER) |
         NVVAL_MW_GET(encoded->qmd, NVCBC0, QMDV04_00, PROGRAM_ADDRESS_UPPER) << 32;
   } else if (dev->cls_compute >= AMPERE_COMPUTE_A) {
      CHECK(NVVAL_MW_GET(encoded->qmd, NVC6C0, QMDV03_00, QMD_MAJOR_VERSION) == 3);
      CHECK(NVVAL_MW_GET(encoded->qmd, NVC6C0, QMDV03_00, QMD_VERSION) == 0);
      CHECK(NVVAL_MW_GET(encoded->qmd, NVC6C0, QMDV03_00, REGISTER_COUNT_V) == info->num_gprs);
      CHECK(NVVAL_MW_GET(encoded->qmd, NVC6C0, QMDV03_00, CONSTANT_BUFFER_SIZE_SHIFTED4, 7) * 16 == 64);
      program = NVVAL_MW_GET(encoded->qmd, NVC6C0, QMDV03_00, PROGRAM_ADDRESS_LOWER) |
         NVVAL_MW_GET(encoded->qmd, NVC6C0, QMDV03_00, PROGRAM_ADDRESS_UPPER) << 32;
   } else {
      CHECK(NVVAL_MW_GET(encoded->qmd, NVC3C0, QMDV02_02, QMD_MAJOR_VERSION) == 2);
      CHECK(NVVAL_MW_GET(encoded->qmd, NVC3C0, QMDV02_02, QMD_VERSION) == 2);
      CHECK(NVVAL_MW_GET(encoded->qmd, NVC3C0, QMDV02_02, REGISTER_COUNT_V) == info->num_gprs);
      CHECK(NVVAL_MW_GET(encoded->qmd, NVC3C0, QMDV02_02, CONSTANT_BUFFER_SIZE_SHIFTED4, 7) * 16 == 64);
      program = NVVAL_MW_GET(encoded->qmd, NVC3C0, QMDV02_02, PROGRAM_ADDRESS_LOWER) |
         NVVAL_MW_GET(encoded->qmd, NVC3C0, QMDV02_02, PROGRAM_ADDRESS_UPPER) << 32;
   }
   CHECK(program == dispatch->qmd.addr);
}

static void
validate_push(const struct nv_device_info *dev,
              const struct stela_nvidia_compute_dispatch *dispatch,
              const struct stela_nvidia_compute_encoded *encoded)
{
   CHECK(encoded->push_dw >= 3 && encoded->push_dw <= STELA_NVIDIA_COMPUTE_MAX_PUSH_DW);
   unsigned at = 0, methods = 0;
   while (at < encoded->push_dw) {
      uint32_t header = encoded->push[at++];
      unsigned method = NVVAL_GET(header, NV906F, DMA, METHOD_ADDRESS) * 4;
      CHECK(NVVAL_GET(header, NV906F, DMA, METHOD_SUBCHANNEL) == 1);
      unsigned op = NVVAL_GET(header, NV906F, DMA, SEC_OP);
      unsigned count = op == NV906F_DMA_SEC_OP_IMMD_DATA_METHOD ? 1 : NVVAL_GET(header, NV906F, DMA, METHOD_COUNT);
      CHECK(op == NV906F_DMA_SEC_OP_IMMD_DATA_METHOD || op == NV906F_DMA_SEC_OP_INC_METHOD);
      CHECK(count > 0 && count <= encoded->push_dw);
      for (unsigned i = 0; i < count; i++, method += 4) {
         CHECK(op == NV906F_DMA_SEC_OP_IMMD_DATA_METHOD || at < encoded->push_dw);
         uint32_t value = op == NV906F_DMA_SEC_OP_IMMD_DATA_METHOD ?
            NVVAL_GET(header, NV906F, DMA, IMMD_DATA) : encoded->push[at++];
         if (methods == 0) {
            CHECK(method == NVA0C0_SEND_PCAS_A && value == dispatch->qmd_addr >> 8);
         } else {
            CHECK(methods == 1);
            if (dev->cls_compute == TURING_COMPUTE_A) {
               CHECK(method == NVA0C0_SEND_SIGNALING_PCAS_B);
               CHECK(NVVAL_GET(value, NVA0C0, SEND_SIGNALING_PCAS_B, INVALIDATE) == NVA0C0_SEND_SIGNALING_PCAS_B_INVALIDATE_TRUE);
               CHECK(NVVAL_GET(value, NVA0C0, SEND_SIGNALING_PCAS_B, SCHEDULE) == NVA0C0_SEND_SIGNALING_PCAS_B_SCHEDULE_TRUE);
            } else {
               CHECK(method == NVC6C0_SEND_SIGNALING_PCAS2_B && value == NVC6C0_SEND_SIGNALING_PCAS2_B_PCAS_ACTION_INVALIDATE_COPY_SCHEDULE);
            }
         }
         methods++;
      }
   }
   CHECK(at == encoded->push_dw && methods == 2);
}

static void
refusal(const struct nv_device_info *dev, const struct nak_shader_bin *shader,
         const struct stela_nvidia_compute_dispatch *dispatch,
         enum stela_nvidia_compute_error expected)
{
   struct stela_nvidia_compute_encoded sentinel, encoded;
   memset(&sentinel, 0xa7, sizeof(sentinel));
   encoded = sentinel;
   enum stela_nvidia_compute_error error;
   CHECK(!stela_nvidia_compute_encode(dev, shader, dispatch, &encoded, &error));
   CHECK(error == expected && !memcmp(&encoded, &sentinel, sizeof(encoded)));
}

static void
refusals(const struct nv_device_info *dev, const struct nak_shader_bin *shader,
          const struct stela_nvidia_compute_dispatch *dispatch)
{
   struct nv_device_info bad_dev = *dev;
   bad_dev.cls_compute = 0xffff;
   refusal(&bad_dev, shader, dispatch, STELA_NVIDIA_COMPUTE_DEVICE);
   bad_dev = *dev;
   bad_dev.sm_smem_size_count = ARRAY_SIZE(bad_dev.sm_smem_sizes_kB) + 1;
   refusal(&bad_dev, shader, dispatch, STELA_NVIDIA_COMPUTE_DEVICE);
   bad_dev = *dev;
   bad_dev.sm_smem_sizes_kB[1] = 3;
   refusal(&bad_dev, shader, dispatch, STELA_NVIDIA_COMPUTE_SHARED_MEMORY);
   struct nak_shader_bin bad_shader = *shader;
   bad_shader.info.sm++;
   refusal(dev, &bad_shader, dispatch, STELA_NVIDIA_COMPUTE_SHADER);
   bad_shader = *shader;
   bad_shader.info.cs.local_size[0] = 0;
   refusal(dev, &bad_shader, dispatch, STELA_NVIDIA_COMPUTE_GEOMETRY);
   bad_shader = *shader;
   bad_shader.info.slm_size = 16;
   refusal(dev, &bad_shader, dispatch, STELA_NVIDIA_COMPUTE_SCRATCH_UNSUPPORTED);
   bad_shader = *shader;
   bad_shader.info.crs_size = 512;
   refusal(dev, &bad_shader, dispatch, STELA_NVIDIA_COMPUTE_SCRATCH_UNSUPPORTED);
   struct stela_nvidia_compute_dispatch bad = *dispatch;
   bad.qmd_addr++;
   refusal(dev, shader, &bad, STELA_NVIDIA_COMPUTE_ADDRESS);
   bad = *dispatch;
   bad.qmd_addr = UINT64_C(1) << 40;
   refusal(dev, shader, &bad, STELA_NVIDIA_COMPUTE_ADDRESS);
   bad = *dispatch;
   bad.qmd.addr = UINT64_C(1) << bad.va_bits;
   refusal(dev, shader, &bad, STELA_NVIDIA_COMPUTE_ADDRESS);
   bad = *dispatch;
   bad.qmd.addr = bad.qmd_addr;
   refusal(dev, shader, &bad, STELA_NVIDIA_COMPUTE_ADDRESS);
   bad = *dispatch;
   bad.qmd.smem_size = UINT32_MAX;
   refusal(dev, shader, &bad, STELA_NVIDIA_COMPUTE_SHARED_MEMORY);
   bad = *dispatch;
   bad.qmd.global_size[1] = 65536;
   refusal(dev, shader, &bad, STELA_NVIDIA_COMPUTE_GEOMETRY);
   bad = *dispatch;
   bad.qmd.num_cbufs = 9;
   refusal(dev, shader, &bad, STELA_NVIDIA_COMPUTE_CONSTANT_BUFFER);
   bad = *dispatch;
   bad.qmd.cbufs[1].index = bad.qmd.cbufs[0].index;
   refusal(dev, shader, &bad, STELA_NVIDIA_COMPUTE_CONSTANT_BUFFER);
   bad = *dispatch;
   bad.qmd.cbufs[1].size = 17;
   refusal(dev, shader, &bad, STELA_NVIDIA_COMPUTE_CONSTANT_BUFFER);
   bad = *dispatch;
   bad.qmd.cbufs[1].addr = UINT64_MAX;
   refusal(dev, shader, &bad, STELA_NVIDIA_COMPUTE_ADDRESS);
}

static void
compile_and_encode(LLVMMemoryBufferRef bitcode, unsigned sm, unsigned cls)
{
   struct nv_device_info dev = stela_nvidia_target_device(sm, cls);
   struct nak_compiler *compiler = nak_compiler_create(&dev);
   CHECK(compiler);
   const struct stela_air_options options = {
      .workgroup_size = {32, 1, 1}, .max_instructions = 100, .bind_buffer = bind_buffer,
   };
   struct stela_air_error air_error;
   nir_shader *nir = stela_air_to_nir(LLVMGetBufferStart(bitcode), LLVMGetBufferSize(bitcode),
      "kernel", nak_nir_options(compiler), &options, &air_error);
   CHECK(nir);
   nak_preprocess_nir(nir, compiler);
   /* nak_compile_shader runs the retained postprocessing itself. */
   struct nak_shader_bin *shader = nak_compile_shader(nir, true, compiler, 0, NULL, false);
   CHECK(shader && shader->code && shader->code_size && shader->info.num_instrs > 2);
   struct stela_nvidia_compute_dispatch dispatch = {
      .qmd = {
         .addr = 0x200000, .smem_size = 1024, .global_size = {7, 5, 3}, .num_cbufs = 2,
         .cbufs = {{.index = 0, .size = 256, .addr = 0x400000}, {.index = 7, .size = 64, .addr = 0x500000}},
      },
      .qmd_addr = 0x300000, .va_bits = sm >= 90 ? 57 : 49,
   };
   struct stela_nvidia_compute_encoded encoded;
   enum stela_nvidia_compute_error error;
   CHECK(stela_nvidia_compute_encode(&dev, shader, &dispatch, &encoded, &error));
   CHECK(error == STELA_NVIDIA_COMPUTE_OK);
   validate_qmd(&dev, &shader->info, &dispatch, &encoded);
   validate_push(&dev, &dispatch, &encoded);
   refusals(&dev, shader, &dispatch);
   /* Exercise high program/CB address bits independently of QMD's 40-bit VA. */
   dispatch.qmd.addr = UINT64_C(1) << (dispatch.va_bits - 1);
   dispatch.qmd.cbufs[0].addr = (UINT64_C(1) << (dispatch.va_bits - 1)) + 0x100000;
   CHECK(stela_nvidia_compute_encode(&dev, shader, &dispatch, &encoded, &error));
   validate_qmd(&dev, &shader->info, &dispatch, &encoded);
   printf("AIR->NAK->QMD SM%u class%04x: %u code bytes, %u QMD bytes, %u launch dwords; decoded/validated, no submission\n",
          sm, cls, shader->code_size, encoded.qmd_size_B, encoded.push_dw);
   nak_shader_bin_destroy(shader);
   ralloc_free(nir);
   nak_compiler_destroy(compiler);
}

int
main(void)
{
   glsl_type_singleton_init_or_ref();
   LLVMMemoryBufferRef bitcode = stela_air_test_bitcode(stela_air_test_store_body, "");
   static const struct {
      unsigned sm, compute_class;
   } targets[] = {STELA_NVIDIA_TARGETS(STELA_NVIDIA_TARGET)};
   for (unsigned i = 0; i < ARRAY_SIZE(targets); i++)
      compile_and_encode(bitcode, targets[i].sm, targets[i].compute_class);
   LLVMDisposeMemoryBuffer(bitcode);
   glsl_type_singleton_decref();
   return 0;
}
