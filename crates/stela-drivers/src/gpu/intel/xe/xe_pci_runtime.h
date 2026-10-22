// SPDX-License-Identifier: MIT
/*
 * Copyright © 2021 Intel Corporation
 */
#ifndef XE_PCI_RUNTIME_H
#define XE_PCI_RUNTIME_H
static const struct xe_subplatform_desc *
find_subplatform(const struct xe_device_desc *desc, u16 devid)
{
	const struct xe_subplatform_desc *sp;
	const u16 *id;

	for (sp = desc->subplatforms; sp && sp->subplatform; sp++)
		for (id = sp->pciidlist; *id; id++)
			if (*id == devid)
				return sp;

	return NULL;
}

static inline struct xe_reg xe_pci_gmdid_register(bool media)
{
	struct xe_reg reg = GMD_ID;
	if (media)
		reg.addr += MEDIA_GT_GSI_OFFSET;
	return reg;
}

static inline void xe_pci_decode_gmdid(u32 val, u32 *ver, u32 *revid)
{
	*ver = REG_FIELD_GET(GMD_ID_ARCH_MASK, val) * 100 + REG_FIELD_GET(GMD_ID_RELEASE_MASK, val);
	*revid = REG_FIELD_GET(GMD_ID_REVID, val);
}

static inline u8 xe_pci_runtime_tile_count(u8 maximum, u32 mtcfg)
{
	u8 tile_count = REG_FIELD_GET(TILE_COUNT, mtcfg) + 1;
	return tile_count < maximum ? tile_count : maximum;
}

static const struct xe_ip *find_graphics_ip(unsigned int verx100)
{
#ifndef STELA_NATIVE
	KUNIT_STATIC_STUB_REDIRECT(find_graphics_ip, verx100);
#endif

	for (int i = 0; i < ARRAY_SIZE(graphics_ips); i++)
		if (graphics_ips[i].verx100 == verx100)
			return &graphics_ips[i];
	return NULL;
}

static const struct xe_ip *find_media_ip(unsigned int verx100)
{
#ifndef STELA_NATIVE
	KUNIT_STATIC_STUB_REDIRECT(find_media_ip, verx100);
#endif

	for (int i = 0; i < ARRAY_SIZE(media_ips); i++)
		if (media_ips[i].verx100 == verx100)
			return &media_ips[i];
	return NULL;
}

#endif
