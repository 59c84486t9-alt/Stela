/* SPDX-License-Identifier: GPL-2.0-only */
/* Actual production query/core plus independent frozen original donor. CPU only. */
#include "../stela/pci_match.c"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define PCI_DEVICE(vend,dev) \
   .vendor = (vend), .device = (dev), .subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID
#define CONFIG_DRM_AMDGPU_SI 1
#define CONFIG_DRM_AMDGPU_CIK 1
#define CONFIG_DRM_RADEON 1
static bool build_si, build_cik, build_radeon;
#define IS_ENABLED(x) enabled_##x
#define enabled_CONFIG_DRM_AMDGPU_SI build_si
#define enabled_CONFIG_DRM_AMDGPU_CIK build_cik
#define enabled_CONFIG_DRM_RADEON build_radeon
struct device { int unused; };
struct pci_dev { unsigned vendor, device, subsystem_vendor, subsystem_device, class, revision; struct device dev; };
enum amd_hw_ip_block_type {
	GC_HWIP = 1,
	HDP_HWIP,
	SDMA0_HWIP,
	SDMA1_HWIP,
	SDMA2_HWIP,
	SDMA3_HWIP,
	SDMA4_HWIP,
	SDMA5_HWIP,
	SDMA6_HWIP,
	SDMA7_HWIP,
	LSDMA_HWIP,
	MMHUB_HWIP,
	ATHUB_HWIP,
	NBIO_HWIP,
	MP0_HWIP,
	MP1_HWIP,
	UVD_HWIP,
	VCN_HWIP = UVD_HWIP,
	JPEG_HWIP = VCN_HWIP,
	VCN1_HWIP,
	VCE_HWIP,
	VPE_HWIP,
	DF_HWIP,
	DCE_HWIP,
	OSSSYS_HWIP,
	SMUIO_HWIP,
	PWR_HWIP,
	NBIF_HWIP,
	THM_HWIP,
	CLK_HWIP,
	UMC_HWIP,
	RSMU_HWIP,
	XGMI_HWIP,
	DCI_HWIP,
	PCIE_HWIP,
	ISP_HWIP,
	ATU_HWIP,
	AIGC_HWIP,
	MAX_HWIP
};

#define IP_VERSION(mj,mn,rv) (((unsigned)(mj)<<24)|((unsigned)(mn)<<16)|((unsigned)(rv)<<8))
struct amdgpu_device { unsigned long flags; enum amd_asic_type asic_type; unsigned long apu_flags; struct pci_dev *pdev; struct { bool reserve_tmr; } discovery; unsigned family, num_ip_blocks;
 struct { int num_instances; unsigned sdma_mask; } sdma;
 struct { int num_umc; } gmc; struct { unsigned xcc_mask; } gfx;
 struct { unsigned num_vcn_inst; } vcn; unsigned ip_versions[MAX_HWIP][48]; void *ddev; };
struct drm_device;
static int amdgpu_discovery, amdgpu_si_support, amdgpu_cik_support;
static int amdgpu_exp_hw_support, amdgpu_modeset, amdgpu_virtual_display;
static bool encrypted, firmware_only;
static bool drm_firmware_drivers_only(void) { return firmware_only; }
#define CC_ATTR_MEM_ENCRYPT 1
static bool cc_platform_has(int unused) { (void)unused; return encrypted; }
static bool amdgpu_device_asic_has_dc_support(struct pci_dev *p, unsigned f) { (void)p; (void)f; return false; }
static void dev_info(struct device *dev, const char *format, ...) { (void)dev; (void)format; }
#define ENOTSUPP 524
static int selected_path;
#define AMDGPU_FAMILY_SI 1
#define AMDGPU_FAMILY_KV 2
#define AMDGPU_FAMILY_CI 3
#define AMDGPU_FAMILY_CZ 4
#define AMDGPU_FAMILY_VI 5
static int si_set_ip_blocks(struct amdgpu_device *a) { (void)a; selected_path=AMDGPU_INITIAL_IP_SI; return 0; }
static int cik_set_ip_blocks(struct amdgpu_device *a) { (void)a; selected_path=AMDGPU_INITIAL_IP_CIK; return 0; }
static int vi_set_ip_blocks(struct amdgpu_device *a) { (void)a; selected_path=AMDGPU_INITIAL_IP_VI; return 0; }
static int amdgpu_discovery_set_ip_blocks(struct amdgpu_device *a) { (void)a; selected_path=AMDGPU_INITIAL_IP_DISCOVERY; return 0; }
static int acquisition_status, acquisition_calls;
static int amdgpu_discovery_init(struct amdgpu_device *a) { (void)a; acquisition_calls++; return acquisition_status; }
static int amdgpu_discovery_reg_base_init(struct amdgpu_device *a) { (void)a; acquisition_calls++; selected_path=STELA_AMD_IP_DYNAMIC; return acquisition_status; }
#define STATIC_INIT(name) static void name(struct amdgpu_device *a) { (void)a; selected_path=STELA_AMD_IP_SOC_STATIC; }
STATIC_INIT(vega10_reg_base_init)
STATIC_INIT(vega20_reg_base_init)
STATIC_INIT(arct_reg_base_init)
STATIC_INIT(aldebaran_reg_base_init)
STATIC_INIT(cyan_skillfish_reg_base_init)
static void amdgpu_discovery_harvest_ip(struct amdgpu_device *a) { (void)a; }
static void amdgpu_discovery_get_gfx_info(struct amdgpu_device *a) { (void)a; }
static void amdgpu_discovery_get_mall_info(struct amdgpu_device *a) { (void)a; }
static void amdgpu_discovery_get_vcn_info(struct amdgpu_device *a) { (void)a; }
static void drm_err(void *d, const char *f, ...) { (void)d; (void)f; }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic ignored "-Wunused-but-set-variable"
#include "pci_reference.h"
#pragma clang diagnostic pop
#define amdgpu_fix_asic_type linux_amdgpu_fix_asic_type
#define amdgpu_support_enabled linux_amdgpu_support_enabled
#define amdgpu_device_init_apu_flags linux_amdgpu_device_init_apu_flags
#define amdgpu_discovery_get_fw_name linux_amdgpu_discovery_get_fw_name
#include "pci-linux-wrappers.inc"
#undef amdgpu_fix_asic_type
#undef amdgpu_support_enabled
#undef amdgpu_device_init_apu_flags
#undef amdgpu_discovery_get_fw_name
#include "pci-linux-paths.inc"

static struct stela_amd_pci_policy policy(void)
{
   return (struct stela_amd_pci_policy){.si_built=1,.cik_built=1,.si_support=-1,
      .cik_support=-1,.discovery=-1,.force_asic=-1,.modeset=-1};
}
static void set_policy(struct stela_amd_pci_policy p)
{
   build_si=p.si_built;build_cik=p.cik_built;build_radeon=p.radeon_built;
   amdgpu_si_support=p.si_support;amdgpu_cik_support=p.cik_support;
   amdgpu_exp_hw_support=p.experimental;amdgpu_discovery=p.discovery;
   amdgpu_modeset=p.modeset;encrypted=p.memory_encrypted;firmware_only=p.firmware_drivers_only;
}
static struct pci_dev device(struct stela_amd_pci_identity i)
{
   return (struct pci_dev){.vendor=i.vendor,.device=i.device,.subsystem_vendor=i.subvendor,
      .subsystem_device=i.subdevice,.class=i.class_code,.revision=i.revision};
}
static size_t comparisons;
static void compare(struct stela_amd_pci_identity i, struct stela_amd_pci_policy p)
{
   set_policy(p);
   struct pci_dev dev=device(i);
   struct stela_amd_pci_match out, before;
   memset(&out,0xa5,sizeof(out));before=out;
   const struct pci_device_id *ref=ref_pci_match_id(ref_pciidlist,&dev);
   assert(linux_amdgpu_fix_asic_type(&dev,ref?ref->driver_data:0)==ref_amdgpu_fix_asic_type(&dev,ref?ref->driver_data:0));
   unsigned family=ref?ref->driver_data&AMD_ASIC_MASK:0;
   assert(linux_amdgpu_support_enabled(&dev.dev,family)==ref_amdgpu_support_enabled(&dev.dev,family));
   unsigned long flags=0;
   int expected=ref?ref_probe(&dev,ref,&flags):-ENODEV;
   int status=stela_amd_pci_match(&i,&p,&out);
   if (!expected && p.force_asic>=0 && p.force_asic<CHIP_LAST) {
      assert(status==STELA_AMD_PCI_OVERRIDE_UNAVAILABLE);
   } else {
      assert((status==0)==(expected==0));
   }
   if (status) {
      assert(!memcmp(&out,&before,sizeof(out)));
   } else {
      assert(out.row==(unsigned)(ref-ref_pciidlist));
      assert(out.original_flags==flags && out.asic_type==(flags&AMD_ASIC_MASK));
      struct amdgpu_device a={.flags=flags,.asic_type=flags&AMD_ASIC_MASK,.pdev=&dev};
      struct amdgpu_device b=a;
      ref_amdgpu_device_init_apu_flags(&a);
      linux_amdgpu_device_init_apu_flags(&b);
      assert(out.initial_apu_flags==a.apu_flags && a.apu_flags==b.apu_flags);
      ref_initial_path(&a);
      const char *name=NULL;
      if (selected_path==AMDGPU_INITIAL_IP_DISCOVERY) {
         acquisition_calls=0;
         assert(ref_discovery_path(&a)==0);
         assert(out.ip_path==(unsigned)selected_path);
         if (acquisition_calls) {
            name=ref_amdgpu_discovery_get_fw_name(&a);
            assert(out.discovery_source==(name?STELA_AMD_DISCOVERY_FILE:STELA_AMD_DISCOVERY_HARDWARE));
            assert((!name&&!out.filename)||(name&&out.filename&&!strcmp(name,out.filename)));
         } else {
            assert(out.discovery_source==STELA_AMD_DISCOVERY_NOT_USED && !out.filename);
         }
      } else {
         assert(out.discovery_source==STELA_AMD_DISCOVERY_NOT_USED && !out.filename);
         assert(out.ip_path==(unsigned)selected_path-1);
      }
   }
   comparisons++;
}
int main(void)
{
   assert(ARRAY_SIZE(pciidlist)==312 && ARRAY_SIZE(ref_pciidlist)==312);
   assert(ARRAY_SIZE(amdgpu_unsupported_pciidlist)==702);
   assert(!memcmp(pciidlist,ref_pciidlist,sizeof(pciidlist)));
   assert(!memcmp(amdgpu_unsupported_pciidlist,ref_amdgpu_unsupported_pciidlist,sizeof(amdgpu_unsupported_pciidlist)));
   assert(!memcmp(asic_type_quirks,ref_asic_type_quirks,sizeof(asic_type_quirks)));
   const unsigned classes[]={0x030000,0x038000,0x120000,0x020000,0x030001,0x120001};
   struct stela_amd_pci_policy p=policy();
   for (unsigned c=0;c<ARRAY_SIZE(classes);c++)
      for (unsigned id=0;id<=UINT16_MAX;id++)
         compare((struct stela_amd_pci_identity){0x1002,id,0xabcd,0x1234,classes[c],0},p);
   for (unsigned revision=0;revision<=UINT8_MAX;revision++)
      compare((struct stela_amd_pci_identity){0x1002,0x67ff,0,0,0x020000,revision},p);
   for (unsigned n=0;n<ARRAY_SIZE(pciidlist)-1;n++) {
      const struct pci_device_id *id=&pciidlist[n];
      struct stela_amd_pci_identity i={0x1002,id->device==UINT32_MAX?0xffff:id->device,0,0,id->class,0xe3};
      for (unsigned built=0;built<8;built++)
         for (int option=-2;option<=2;option++) {
            struct stela_amd_pci_policy q=policy();
            q.si_built=built&1;q.cik_built=(built>>1)&1;q.radeon_built=(built>>2)&1;
            q.si_support=option;q.cik_support=option;
            q.experimental=option;q.firmware_drivers_only=(unsigned)(option&1);
            q.memory_encrypted=(unsigned)(option&1);q.modeset=option;
            compare(i,q);
         }
   }
   for (int option=-2;option<=2;option++) {
      struct stela_amd_pci_policy q=policy();q.discovery=option;
      compare((struct stela_amd_pci_identity){0x1002,0x13db,0,0,0x020000,0},q);
   }
   /* Original predicate semantics beyond today's ANY-subsystem table rows. */
   for (unsigned bits=0;bits<64;bits++) {
      struct pci_device_id id={.vendor=bits&1?PCI_ANY_ID:0x1002,.device=bits&2?PCI_ANY_ID:0x1234,
         .subvendor=bits&4?PCI_ANY_ID:0xabcd,.subdevice=bits&8?PCI_ANY_ID:0x5678,
         .class=0x120003,.class_mask=bits&16?0xffff00:0xffffff};
      struct stela_amd_pci_identity i={0x1002,0x1234,0xabcd,0x5678,bits&32?0x120004:0x120003,0};
      struct pci_dev d=device(i);
      assert((match_one(&id,&i)!=NULL)==(ref_pci_match_one_device(&id,&d)!=NULL));
      i.subvendor++;d=device(i);
      assert((match_one(&id,&i)!=NULL)==(ref_pci_match_one_device(&id,&d)!=NULL));
   }
   /* Every original source/APU state branch, including later RAVEN2 precedence
    * and seeded flags, independently of current PCI row coverage. */
   for (unsigned asic=0;asic<CHIP_LAST;asic++)
      for (unsigned flags=0;flags<128;flags++)
         for (int option=-2;option<4;option++) {
            struct amdgpu_device a={.asic_type=asic,.apu_flags=flags};
            amdgpu_discovery=option;
            const char *ref=ref_amdgpu_discovery_get_fw_name(&a);
            struct amdgpu_device b={.asic_type=asic,.apu_flags=flags};
            const char *actual=linux_amdgpu_discovery_get_fw_name(&b);
            assert(a.discovery.reserve_tmr==b.discovery.reserve_tmr);
            assert((!ref&&!actual)||(ref&&actual&&!strcmp(ref,actual)));
            assert(a.discovery.reserve_tmr==(option==2));
         }
   const unsigned apu_ids[]={0,0x15dd,0x15d8,0x1636,0x164c,0x13fe,0x143f,0xffff};
   for (unsigned asic=0;asic<CHIP_LAST;asic++)
      for (unsigned k=0;k<ARRAY_SIZE(apu_ids);k++)
         for (unsigned apu=0;apu<2;apu++) {
            struct pci_dev d={.device=apu_ids[k]};
            struct amdgpu_device a={.asic_type=asic,.flags=apu?AMD_IS_APU:0,.apu_flags=0xa5a5a5a500000000UL,.pdev=&d};
            ref_amdgpu_device_init_apu_flags(&a);
            assert(a.apu_flags==amdgpu_initial_apu_flags(apu?AMD_IS_APU:0,asic,apu_ids[k],0xa5a5a5a500000000UL));
            ref_initial_path(&a);
            int selected=selected_path;
            assert(linux_initial_path(&a)==0 && selected_path==selected);
            assert(selected_path==(int)amdgpu_initial_ip_path(asic));
         }
   for (unsigned asic=0;asic<CHIP_LAST;asic++)
      for (unsigned flag=0;flag<2;flag++)
         for (int failure=0;failure<2;failure++) {
            struct amdgpu_device a={.asic_type=asic,.apu_flags=flag?AMD_APU_IS_CYAN_SKILLFISH2:0};
            acquisition_status=failure?-EIO:0;
            struct amdgpu_device b=a;
            acquisition_calls=0;
            int status=ref_discovery_path(&a);
            int selected=selected_path, acquired=acquisition_calls;
            acquisition_calls=0;
            assert(linux_discovery_path(&b)==status && acquisition_calls==acquired);
            assert(selected_path==selected && !memcmp(a.ip_versions,b.ip_versions,sizeof(a.ip_versions)));
            bool dynamic=amdgpu_discovery_static_asic(asic)==CHIP_LAST ||
               (asic==CHIP_CYAN_SKILLFISH && flag);
            assert((selected_path==STELA_AMD_IP_DYNAMIC)==dynamic);
            assert((status!=0)==(dynamic&&failure));
         }
   acquisition_status=0;
   /* Current original rows have no experimental flag. Exercise its exact
    * shared predicate with the independent original preflight and synthetic
    * driver_data; this does not create a production table row/device. */
   for (int option=-2;option<=2;option++) {
      amdgpu_exp_hw_support=option;firmware_only=false;encrypted=false;
      struct pci_dev d={.vendor=0x1002,.device=0xffff,.class=0x120000};
      for (unsigned experiment=0;experiment<2;experiment++) {
         struct pci_device_id id={.driver_data=CHIP_IP_DISCOVERY|(experiment?AMD_EXP_HW_SUPPORT:0)};
         unsigned long flags=0;
         assert((ref_probe(&d,&id,&flags)==0)==amdgpu_pci_experimental_allowed(id.driver_data,option));
      }
   }
   struct stela_amd_pci_identity valid={0x1002,0xffff,0,0,0x120000,0};
   for (int override=-2;override<=CHIP_LAST;override++) {p=policy();p.force_asic=override;compare(valid,p);}
   struct stela_amd_pci_match out,before;memset(&out,0x6d,sizeof(out));before=out;
   assert(stela_amd_pci_match(NULL,&p,&out)==STELA_AMD_PCI_INVALID);
   assert(stela_amd_pci_match(&valid,NULL,&out)==STELA_AMD_PCI_INVALID);
   assert(stela_amd_pci_match(&valid,&p,NULL)==STELA_AMD_PCI_INVALID);
   valid.revision=256;assert(stela_amd_pci_match(&valid,&p,&out)==STELA_AMD_PCI_INVALID);
   assert(!memcmp(&out,&before,sizeof(out)));
   printf("AMD PCI: %zu frozen original probe/match comparisons, exact tables, predicates/APU/source/static policy; CPU only\n",comparisons);
}
