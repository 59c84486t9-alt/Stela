/* SPDX-License-Identifier: MIT */
/* The unchanged amdgpu_discovery.c in Stela's environment, over modelled
 * registers, MM-index VRAM and firmware; CPU only. */
#include <stela/test.h>
#include "amdgpu.h"
#include "../ip_discovery.h"
#include "fixtures.h"

/* The registers discovery reads, in DWORDs, and a 512 KiB register BAR. */
enum {
   MM_INDEX = 0x0, MM_DATA = 0x1, MM_INDEX_HI = 0x6,
   DRIVER_SCRATCH_0 = 0x94, DRIVER_SCRATCH_2 = 0x96,
   RCC_CONFIG_MEMSIZE = 0xde3, RCC_IOV_FUNC_IDENTIFIER = 0xde5,
   MP0_SMN_C2PMSG_33 = 0x16061, REGISTERS = 0x20000,
};
/* 16 MiB of VRAM; Linux finds the table 64 KiB below its top. */
#define VRAM_MIB 16
#define TABLE ((uint64_t)VRAM_MIB * 1024 * 1024 - 64 * 1024)

struct model {
   uint32_t registers[REGISTERS];
   uint8_t vram[10 * 1024];
   uint32_t index, index_hi, index_hi_writes, sleeps;
   const uint8_t *file;
   size_t file_bytes;
   char requested[64];
};

static uint32_t read32(void *context, uint32_t reg)
{
   struct model *model = context;
   assert(reg < REGISTERS);
   if (reg != MM_DATA)
      return model->registers[reg];
   const uint64_t at = (uint64_t)model->index_hi << 31 | model->index;
   uint32_t value = 0;
   if (at >= TABLE && at - TABLE < sizeof(model->vram))
      memcpy(&value, model->vram + (at - TABLE), sizeof(value));
   return value;
}
static void write32(void *context, uint32_t reg, uint32_t value)
{
   struct model *model = context;
   assert(reg < REGISTERS && reg != MM_DATA);
   if (reg == MM_INDEX) {
      assert(value & 0x80000000);
      model->index = value & 0x7fffffff;
   } else if (reg == MM_INDEX_HI) {
      model->index_hi = value;
      model->index_hi_writes++;
   }
}
static void sleep_ms(void *context, uint32_t milliseconds)
{
   struct model *model = context;
   model->sleeps += milliseconds;
}
static int firmware(void *context, const char *name, const uint8_t **data, size_t *bytes)
{
   struct model *model = context;
   snprintf(model->requested, sizeof(model->requested), "%s", name);
   if (!model->file)
      return -1;
   *data = model->file;
   *bytes = model->file_bytes;
   return 0;
}

static struct model *model(void)
{
   struct model *model = calloc(1, sizeof(*model));
   model->registers[RCC_CONFIG_MEMSIZE] = VRAM_MIB;
   model->registers[MP0_SMN_C2PMSG_33] = 0x80000000;
   assert(stela_amd_test_discovery(model->vram, sizeof(model->vram)));
   return model;
}

/* Run discovery; the result is released by finish. */
static struct stela_amd_discovery *run(struct model *model, uint64_t register_bytes, int *status)
{
   static const struct stela_amd_discovery_io io = {read32, write32, sleep_ms, firmware};
   const struct stela_amd_discovery_device device = {
      .register_bytes = register_bytes, .asic_type = CHIP_IP_DISCOVERY,
      .pci_device = 0x73bf, .pci_revision = 0xc1,
   };
   const size_t align = stela_amd_discovery_alignment();
   const size_t bytes = (stela_amd_discovery_size() + align - 1) / align * align;
   struct stela_amd_discovery *state = aligned_alloc(align, bytes);
   *status = stela_amd_discovery_init(state, bytes, &io, model, &device);
   return state;
}
static void finish(struct stela_amd_discovery *state, int status)
{
   if (!status)
      stela_amd_discovery_fini(state);
   free(state);
}
static int fails(struct model *model, uint64_t register_bytes, const char **unsupported)
{
   int status;
   struct stela_amd_discovery *state = run(model, register_bytes, &status);
   assert(status < 0);
   *unsupported = stela_amd_discovery_unsupported(state);
   finish(state, status);
   free(model);
   return status;
}

static void check(const struct stela_amd_discovery *state)
{
   assert(stela_amd_discovery_version(state, GC_HWIP, 0) == IP_VERSION_FULL(10, 3, 0, 0, 1));
   assert(stela_amd_discovery_version(state, SDMA0_HWIP, 0) == IP_VERSION(5, 2, 0));
   assert(stela_amd_discovery_version(state, VCN_HWIP, 0) == IP_VERSION(3, 0, 0));
   assert(stela_amd_discovery_version(state, UMC_HWIP, 1) == IP_VERSION(8, 7, 0));
   assert(!stela_amd_discovery_version(state, MP1_HWIP, 0));
   assert(!stela_amd_discovery_version(state, MAX_HWIP, 0));
   uint32_t base = 0;
   assert(stela_amd_discovery_registers(state, GC_HWIP, 0, 1, &base) == 2 && base == 0xa000);
   assert(stela_amd_discovery_registers(state, GC_HWIP, 0, 2, &base) == 2 && base == 0xa000);
   assert(stela_amd_discovery_registers(state, UMC_HWIP, 1, 0, &base) == 1 && base == 0x54000);
   assert(stela_amd_discovery_registers(state, VCN_HWIP, 0, 0, NULL) == 1);
   assert(stela_amd_discovery_registers(state, MP1_HWIP, 0, 0, &base) == -1);

   struct stela_amd_discovery_facts facts;
   stela_amd_discovery_facts(state, &facts);
   assert(facts.xcc_mask == 1 && facts.sdma_count == 1 && facts.sdma_mask == 1);
   assert(facts.vcn_count == 1 && facts.vcn_mask == 1 && facts.jpeg_mask == 1);
   assert(facts.vcn_config[0] == 0x80 && facts.vcn_codec_disable[0] == 0x5);
   assert(!facts.harvest_ip_mask && !facts.vcn_harvest && !facts.jpeg_harvest);
   /* The harvest table removes UMC 1. */
   assert(facts.umc_nodes == 2 && facts.umc_count == 1 && facts.umc_active_mask == 1);
   assert(facts.mall_size == 2 << 20);
   assert(facts.gfx[STELA_AMD_GFX_MAX_SHADER_ENGINES] == 4);
   assert(facts.gfx[STELA_AMD_GFX_MAX_CU_PER_SH] == 10);
   assert(facts.gfx[STELA_AMD_GFX_MAX_SH_PER_SE] == 2);
   assert(facts.gfx[STELA_AMD_GFX_NUM_SC_PER_SH] == 2);
   assert(facts.gfx[STELA_AMD_GFX_WAVE_FRONT_SIZE] == 32);
   assert(facts.gfx[STELA_AMD_GFX_LDS_SIZE] == 64);
   /* GC table v1.0 has no cache sizes. */
   assert(!facts.gfx[STELA_AMD_GFX_GC_TCC_SIZE]);
}

int main(void)
{
   int status;
   /* From VRAM, through the MM index pair. */
   struct model *vram = model();
   struct stela_amd_discovery *state = run(vram, REGISTERS * 4, &status);
   assert(!status && !stela_amd_discovery_unsupported(state));
   check(state);
   /* The signature read and the table read each set the high index once. */
   assert(vram->index_hi_writes == 2 && !vram->sleeps && !vram->requested[0]);
   finish(state, status);
   free(vram);

   /* From the firmware the discovery parameter selects, which discovery
    * copies, after waiting out IFWI initialization. */
   amdgpu_discovery = 2;
   struct model *file = model();
   uint8_t image[1024];
   file->file_bytes = stela_amd_test_discovery(image, sizeof(image));
   file->file = image;
   memset(file->vram, 0, sizeof(file->vram));
   file->registers[MP0_SMN_C2PMSG_33] = 0;
   state = run(file, REGISTERS * 4, &status);
   assert(!status && !strcmp(file->requested, "amdgpu/ip_discovery.bin"));
   assert(file->sleeps == 2000);
   memset(image, 0, sizeof(image));
   check(state);
   finish(state, status);
   free(file);
   const char *unsupported;
   assert(fails(model(), REGISTERS * 4, &unsupported) == -ENOENT && !unsupported);
   amdgpu_discovery = -1;

   /* Linux checks the binary. */
   struct model *corrupt = model();
   corrupt->vram[0x50] ^= 1;
   assert(fails(corrupt, REGISTERS * 4, &unsupported) == -EINVAL && !unsupported);

   /* Accesses Stela cannot perform yet fail the discovery. */
   assert(fails(model(), 64 * 1024, &unsupported) == -EOPNOTSUPP);
   assert(!strcmp(unsupported, "indirect register access"));
   struct model *vf = model();
   vf->registers[RCC_IOV_FUNC_IDENTIFIER] = 1;
   assert(fails(vf, REGISTERS * 4, &unsupported) == -EOPNOTSUPP);
   assert(!strcmp(unsupported, "SR-IOV virtual function"));
   struct model *apu = model();
   apu->registers[RCC_CONFIG_MEMSIZE] = 0;
   apu->registers[DRIVER_SCRATCH_2] = 10 * 1024;
   apu->registers[DRIVER_SCRATCH_0] = 0x100000;
   fails(apu, REGISTERS * 4, &unsupported);
   assert(!strcmp(unsupported, "memremap"));

   /* Malformed calls change nothing. */
   const struct stela_amd_discovery_io io = {read32, write32, sleep_ms, NULL};
   const struct stela_amd_discovery_device device = {.asic_type = CHIP_IP_DISCOVERY};
   uint8_t small[16];
   assert(stela_amd_discovery_init(small, sizeof(small), &io, NULL, &device) == -EINVAL);
   printf("AMD IP discovery: VRAM and file sources, Linux's checks and unsupported services\n");
   return 0;
}
