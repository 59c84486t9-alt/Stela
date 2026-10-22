/* SPDX-License-Identifier: MIT */
/*
 * Copyright 2008, 2022 Advanced Micro Devices, Inc.
 * Copyright 2008 Red Hat Inc.
 * Copyright 2009 Jerome Glisse.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: Dave Airlie
 *          Alex Deucher
 *          Jerome Glisse
 */
/* CPU fixtures only: exact retained Linux policy donors with minimal model
 * containers. These do not initialize a device or create production BOs.
 */
#include "../stela/native_bar.h"

#ifdef __KERNEL__
_Static_assert(sizeof(struct amdgpu_asic_type_quirk) == 6, "kernel quirk size");
_Static_assert(__builtin_offsetof(struct amdgpu_asic_type_quirk, revision) == 2,
               "kernel revision offset");
_Static_assert(__builtin_offsetof(struct amdgpu_asic_type_quirk, type) == 4,
               "kernel type offset");
_Static_assert(sizeof(enum amd_asic_type) == 4, "kernel enum ABI");
unsigned stela_amd_test_kernel_bar(enum amd_asic_type asic);
unsigned stela_amd_test_kernel_bar(enum amd_asic_type asic)
{
   return amdgpu_native_register_bar(asic);
}
#else
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

_Static_assert(sizeof(struct amdgpu_asic_type_quirk) == 6, "original quirk ABI");
_Static_assert(offsetof(struct amdgpu_asic_type_quirk, revision) == 2, "revision ABI");
_Static_assert(offsetof(struct amdgpu_asic_type_quirk, type) == 4, "type ABI");
_Static_assert(sizeof(enum amd_asic_type) == 4, "original ASIC enum ABI");

typedef uint32_t u32;
struct pci_dev {
   uint64_t base[6], bytes[6];
   unsigned flags;
};
struct amdgpu_device {
   enum amd_asic_type asic_type;
   uint64_t rmmio_base, rmmio_size;
   struct pci_dev *pdev;
   void *dev;
   struct {
      uint64_t base, size;
      uint32_t num_kernel_doorbells;
      void *kernel_doorbells, *cpu_addr;
   } doorbell;
   struct { uint32_t max_assignment; } doorbell_index;
   struct { unsigned db_start_dw_offset; } mes;
};
static uint64_t fixture_page, allocation_bytes;
#define PAGE_SIZE fixture_page
#define IORESOURCE_UNSET 1
#define AMDGPU_GEM_DOMAIN_DOORBELL 0x1234
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define ALIGN(v, a) (((v) + (a) - 1) & ~((a) - 1))
#define dev_err(...) ((void)0)
static uint64_t pci_resource_start(struct pci_dev *p, unsigned n)
{
   assert(n < 6);
   return p->base[n];
}
static uint64_t pci_resource_len(struct pci_dev *p, unsigned n)
{
   assert(n < 6);
   return p->bytes[n];
}
static unsigned pci_resource_flags(struct pci_dev *p, unsigned n)
{
   assert(n == 2);
   return p->flags;
}
static void amdgpu_asic_init_doorbell_index(struct amdgpu_device *a)
{
   (void)a; /* Fixture supplies the exact scalar assignment under comparison. */
}
static int amdgpu_bo_create_kernel(struct amdgpu_device *a, uint64_t bytes, uint64_t alignment,
                                  unsigned domain, void **bo, void *gpu, void **cpu)
{
   (void)a;
   (void)bo;
   (void)gpu;
   (void)cpu;
   assert(alignment == fixture_page && domain == AMDGPU_GEM_DOMAIN_DOORBELL);
   allocation_bytes = bytes;
   return 0;
}
/* Test-only symbol namespace: unchanged donor bodies below must never replace
 * original production device entry points when the full driver is linked. */
#define amdgpu_doorbell_init stela_amd_test_donor_doorbell_init
#define amdgpu_doorbell_create_kernel_doorbells stela_amd_test_donor_create_kernel_doorbells
int amdgpu_doorbell_init(struct amdgpu_device *adev);
int amdgpu_doorbell_create_kernel_doorbells(struct amdgpu_device *adev);
uint32_t stela_amd_test_original_asic(unsigned which);
uint32_t stela_amd_test_original_asic(unsigned which)
{
   const uint32_t values[] = {CHIP_TAHITI, CHIP_BONAIRE, CHIP_VEGA10, CHIP_IP_DISCOVERY};
   assert(which < sizeof(values) / sizeof(values[0]));
   return values[which];
}

/* Original register selection SHA256 f0303f65c788eb07dc545ef9da651a5b41d95c0141af21e83638a06ed16e683a */
static void donor_register_bar(struct amdgpu_device *adev)
{
	if (adev->asic_type >= CHIP_BONAIRE) {
		adev->rmmio_base = pci_resource_start(adev->pdev, 5);
		adev->rmmio_size = pci_resource_len(adev->pdev, 5);
	} else {
		adev->rmmio_base = pci_resource_start(adev->pdev, 2);
		adev->rmmio_size = pci_resource_len(adev->pdev, 2);
	}
}

/* Original amdgpu_doorbell_create_kernel_doorbells SHA256 f0c7e8fcd31289c8718df9bd6bc6a410219e9be168d3492dc1f25ccaffa87193 */
int amdgpu_doorbell_create_kernel_doorbells(struct amdgpu_device *adev)
{
	int r;
	int size;

	/* SI HW does not have doorbells, skip allocation */
	if (adev->doorbell.num_kernel_doorbells == 0)
		return 0;

	/* Reserve first num_kernel_doorbells (page-aligned) for kernel ops */
	size = ALIGN(adev->doorbell.num_kernel_doorbells * sizeof(u32), PAGE_SIZE);

	/* Allocate an extra page for MES kernel usages (ring test) */
	adev->mes.db_start_dw_offset = size / sizeof(u32);
	size += PAGE_SIZE;

	r = amdgpu_bo_create_kernel(adev,
				    size,
				    PAGE_SIZE,
				    AMDGPU_GEM_DOMAIN_DOORBELL,
				    &adev->doorbell.kernel_doorbells,
				    NULL,
				    (void **)&adev->doorbell.cpu_addr);
	if (r) {
		dev_err(adev->dev,
			"Failed to allocate kernel doorbells, err=%d\n", r);
		return r;
	}

	adev->doorbell.num_kernel_doorbells = size / sizeof(u32);
	return 0;
}

/* Original amdgpu_doorbell_init SHA256 acab9b44336a9785900012350b38d0c1da0c2ed235dcc988b7af8b104ba6d917 */
int amdgpu_doorbell_init(struct amdgpu_device *adev)
{

	/* No doorbell on SI hardware generation */
	if (adev->asic_type < CHIP_BONAIRE) {
		adev->doorbell.base = 0;
		adev->doorbell.size = 0;
		adev->doorbell.num_kernel_doorbells = 0;
		return 0;
	}

	if (pci_resource_flags(adev->pdev, 2) & IORESOURCE_UNSET)
		return -EINVAL;

	amdgpu_asic_init_doorbell_index(adev);

	/* doorbell bar mapping */
	adev->doorbell.base = pci_resource_start(adev->pdev, 2);
	adev->doorbell.size = pci_resource_len(adev->pdev, 2);

	adev->doorbell.num_kernel_doorbells =
		min_t(u32, adev->doorbell.size / sizeof(u32),
		      adev->doorbell_index.max_assignment + 1);
	if (adev->doorbell.num_kernel_doorbells == 0)
		return -EINVAL;

	/*
	 * For Vega, reserve and map two pages on doorbell BAR since SDMA
	 * paging queue doorbell use the second page. The
	 * AMDGPU_DOORBELL64_MAX_ASSIGNMENT definition assumes all the
	 * doorbells are in the first page. So with paging queue enabled,
	 * the max num_kernel_doorbells should + 1 page (0x400 in dword)
	 */
	if (adev->asic_type >= CHIP_VEGA10)
		adev->doorbell.num_kernel_doorbells += 0x400;

	return 0;
}

#ifndef STELA_AMD_BAR_TEST_LIBRARY
int main(void)
{
   unsigned cases = 0;
   const uint32_t assignments[] = {0, 31, 255, 1023, 2047, 4095};
   const uint64_t pages[] = {4096, 65536};
   for (unsigned asic = 0; asic < CHIP_LAST; asic++) {
      for (unsigned p = 0; p < 2; p++) {
         for (unsigned m = 0; m < 6; m++) {
            fixture_page = pages[p];
            struct pci_dev pci = {
               .base = {0, 0, 0x100000, 0, 0, 0x200000},
               .bytes = {0, 0, 0x100000, 0, 0, 0x40000},
            };
            struct amdgpu_device device = {
               .asic_type = asic, .pdev = &pci, .doorbell_index = {assignments[m]},
            };
            donor_register_bar(&device);
            assert(!amdgpu_doorbell_init(&device));
            allocation_bytes = 0;
            assert(!amdgpu_doorbell_create_kernel_doorbells(&device));
            struct stela_amd_bar_layout layout;
            assert(stela_amd_native_bar_layout(asic, asic < CHIP_BONAIRE ? 0 : pci.bytes[2],
                                              asic < CHIP_BONAIRE ? 0 : assignments[m],
                                              fixture_page, &layout) == STELA_AMD_BAR_OK);
            uint32_t bar = UINT32_MAX;
            assert(stela_amd_native_register_bar(asic, &bar) == STELA_AMD_BAR_OK);
            assert(bar == layout.register_bar);
            assert(device.rmmio_base == pci.base[layout.register_bar]);
            assert(device.rmmio_size == pci.bytes[layout.register_bar]);
            assert(device.doorbell.num_kernel_doorbells == layout.kernel_doorbells);
            assert(allocation_bytes == layout.kernel_doorbell_bytes);
            if (layout.kernel_doorbells)
               assert(device.mes.db_start_dw_offset * 4 == allocation_bytes - fixture_page);
            cases++;
         }
      }
   }
   struct stela_amd_bar_layout output, saved;
   memset(&output, 0xa5, sizeof(output));
   saved = output;
   const struct {
      uint32_t asic;
      uint64_t bytes;
      uint32_t max;
      uint64_t page;
   } bad[] = {
      {CHIP_LAST, 65536, 1023, 4096}, {CHIP_BONAIRE, 65536, 1023, 0},
      {CHIP_BONAIRE, 65536, 1023, 8191}, {CHIP_BONAIRE, 65536, 1023, UINT64_MAX},
      {CHIP_BONAIRE, 0, 1023, 4096}, {CHIP_BONAIRE, 3, 1023, 4096},
      {CHIP_BONAIRE, UINT64_MAX, 1023, 4096}, {CHIP_BONAIRE, 65536, UINT32_MAX, 4096},
      {CHIP_VEGA10, 65536, UINT32_MAX - 1, 4096}, {CHIP_VEGA10, 4096, 1023, 4096},
      {CHIP_BONAIRE, UINT64_C(0xffffffff) * 4, UINT32_C(0x7ffffffe), 4096},
      {CHIP_TAHITI, 4096, 0, 4096}, {CHIP_TAHITI, 0, 1, 4096},
   };
   for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
      assert(stela_amd_native_bar_layout(bad[i].asic, bad[i].bytes, bad[i].max,
                                        bad[i].page, &output) != STELA_AMD_BAR_OK);
      assert(!memcmp(&output, &saved, sizeof(output)));
   }
   assert(stela_amd_native_bar_layout(CHIP_TAHITI, 0, 0, 4096, NULL) == STELA_AMD_BAR_INVALID);
   uint32_t bar = UINT32_MAX;
   assert(stela_amd_native_register_bar(CHIP_LAST, &bar) == STELA_AMD_BAR_INVALID);
   assert(bar == UINT32_MAX);
   assert(stela_amd_native_register_bar(CHIP_TAHITI, NULL) == STELA_AMD_BAR_INVALID);
   printf("AMD native BAR: %u exact original donor layouts, ABI and atomic bounds passed; no hardware\n", cases);
   return 0;
}
#endif

#endif /* !__KERNEL__ */
