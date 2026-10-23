/* SPDX-License-Identifier: MIT */
/* Bounded parser/geometry tests, not a nouveau device or firmware-boot test.
 * The source-only generator binds complete actual patched helper bodies and
 * metadata into one ignored include. No original firmware input is required.
 * No parser, allocator, DMA, CRC or device-service substitute is provided here. */
#include <stela/test.h>
#include <linux/crc32.h>
#include <linux/elf.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/string.h>
#include <nvfw/fw.h>
#include <nvkm/subdev/gsp.h>
#include <rm/r535/nvrm/gsp.h>
#include "nouveau_firmware_helpers.inc"

static unsigned int cases;

static void elf_fixture(u8 *bytes, size_t shoff)
{
	static const char names[] = "\0.fwimage\0.sig\0";
	struct elf64_hdr hdr = {
		.e_version = EV_CURRENT, .e_ehsize = sizeof(hdr), .e_shoff = shoff,
		.e_shentsize = sizeof(struct elf64_shdr), .e_shnum = 4, .e_shstrndx = 1,
	};
	struct elf64_shdr shdr[4] = {
		{}, {.sh_type = SHT_STRTAB, .sh_offset = 340, .sh_size = sizeof(names)},
		{.sh_name = 1, .sh_type = SHT_PROGBITS, .sh_offset = 400, .sh_size = 7},
		{.sh_name = 10, .sh_type = SHT_PROGBITS, .sh_offset = 420, .sh_size = 3},
	};

	memset(bytes, 0, 512);
	memcpy(hdr.e_ident, ELFMAG, SELFMAG);
	hdr.e_ident[EI_CLASS] = ELFCLASS64;
	hdr.e_ident[EI_DATA] = ELFDATA2LSB;
	hdr.e_ident[EI_VERSION] = EV_CURRENT;
	memcpy(bytes, &hdr, sizeof(hdr));
	memcpy(bytes + shoff, shdr, sizeof(shdr));
	memcpy(bytes + 340, names, sizeof(names));
}

static void elf_result(const u8 *bytes, size_t size, const char *name, int expected)
{
	const u8 *data = (const u8 *)1UL;
	u64 length = U64_MAX;

	assert(r535_gsp_elf_section(bytes, size, name, &data, &length) == expected);
	if (expected)
		assert(data == (const u8 *)1UL && length == U64_MAX);
	else
		assert(data == bytes + 400 && length == 7);
	cases++;
}

static void elf_cases(void)
{
	u8 storage[520] __aligned(8), *bytes = storage + 1;
	struct elf64_hdr hdr;
	struct elf64_shdr shdr;

	/* Both the image base and the section table may be unaligned. */
	for (size_t base = 0; base < 8; base++) {
		for (size_t shoff = 64; shoff < 72; shoff++) {
			elf_fixture(storage + base, shoff);
			elf_result(storage + base, 512, ".fwimage", 0);
		}
	}
	elf_fixture(bytes, 65);
	for (size_t size = 0; size < sizeof(hdr); size++)
		elf_result(bytes, size, ".fwimage", -EINVAL);
	elf_result(bytes, 65 + 4 * sizeof(shdr) - 1, ".fwimage", -EINVAL);
	elf_result(bytes, 512, ".missing", -ENOENT);

	for (unsigned int field = 0; field < 10; field++) {
		elf_fixture(bytes, 65);
		memcpy(&hdr, bytes, sizeof(hdr));
		switch (field) {
		case 0: hdr.e_shoff = U64_MAX; break;
		case 1: hdr.e_shnum = U16_MAX; break;
		case 2: hdr.e_shnum = 0; break;
		case 3: hdr.e_shstrndx = hdr.e_shnum; break;
		case 4: hdr.e_shentsize--; break;
		case 5: hdr.e_ehsize--; break;
		case 6: hdr.e_ident[EI_CLASS] = ELFCLASS32; break;
		case 7: hdr.e_ident[EI_DATA] = ELFDATA2MSB; break;
		case 8: hdr.e_ident[EI_VERSION] = EV_NONE; break;
		case 9: hdr.e_version = EV_NONE; break;
		}
		memcpy(bytes, &hdr, sizeof(hdr));
		elf_result(bytes, 512, ".fwimage", -EINVAL);
	}
	for (unsigned int field = 0; field < 8; field++) {
		size_t index = field < 3 ? 1 : 2;

		elf_fixture(bytes, 65);
		memcpy(&shdr, bytes + 65 + index * sizeof(shdr), sizeof(shdr));
		switch (field) {
		case 0: shdr.sh_type = SHT_PROGBITS; break;
		case 1: shdr.sh_offset = U64_MAX; break;
		case 2: shdr.sh_size = U64_MAX; break;
		case 3: shdr.sh_name = U32_MAX; break;
		case 4: shdr.sh_offset = U64_MAX; break;
		case 5: shdr.sh_size = U64_MAX; break;
		case 6: shdr.sh_type = SHT_NOBITS; break;
		case 7: shdr.sh_offset = 512; shdr.sh_size = 1; break;
		}
		memcpy(bytes + 65 + index * sizeof(shdr), &shdr, sizeof(shdr));
		elf_result(bytes, 512, ".fwimage", -EINVAL);
	}
	elf_fixture(bytes, 65);
	/* Remove every terminator after the selected name's starting offset. */
	memset(bytes + 341, 'x', 15);
	elf_result(bytes, 512, ".fwimage", -EINVAL);
	elf_fixture(bytes, 65);
	memcpy(&shdr, bytes + 65 + 3 * sizeof(shdr), sizeof(shdr));
	shdr.sh_name = 1;
	memcpy(bytes + 65 + 3 * sizeof(shdr), &shdr, sizeof(shdr));
	elf_result(bytes, 512, ".fwimage", -EINVAL);
}

static void geometry_cases(void)
{
	const struct { u64 bytes; size_t table_bytes; } valid[] = {
		{1, 4096}, {4095, 4096}, {4096, 4096}, {4097, 4096},
		{512ULL * 4096 - 1, 4096}, {512ULL * 4096, 4096},
		{512ULL * 4096 + 1, 8192}, {1ULL << 30, 2UL << 20},
	};
	const u64 invalid[] = {0, (1ULL << 30) + 1, U64_MAX};
	size_t output;
	const size_t largest_signature = SIZE_MAX - (PAGE_SIZE - 1);
	int image;

	for (size_t i = 0; i < ARRAY_SIZE(valid); i++) {
		assert(!r535_gsp_radix3_size(valid[i].bytes, &output));
		assert(output == valid[i].table_bytes);
		cases++;
	}
	for (size_t i = 0; i < ARRAY_SIZE(invalid); i++) {
		output = 17;
		assert(r535_gsp_radix3_size(invalid[i], &output) == -EINVAL && output == 17);
		cases++;
	}
	assert(!r535_gsp_fw_sizes(4097, 257, &image, &output));
	assert(image == 4097 && output == 512);
	assert(!r535_gsp_fw_sizes(1ULL << 30, largest_signature, &image, &output));
	assert(image == (1 << 30) && output == largest_signature);
	assert(!r535_gsp_fw_sizes(1, largest_signature - 255, &image, &output));
	assert(image == 1 && output == largest_signature);
	const struct { u64 image, signature; } bad[] = {
		{0, 1}, {1, 0}, {U64_MAX, 1}, {INT_MAX, 1},
		{(1ULL << 30) + 1, 1}, {1, largest_signature + 1},
		{1, SIZE_MAX - 255}, {1, SIZE_MAX - 254}, {1, U64_MAX},
	};
	for (size_t i = 0; i < ARRAY_SIZE(bad); i++) {
		image = 19;
		output = 17;
		assert(r535_gsp_fw_sizes(bad[i].image, bad[i].signature,
					&image, &output) == -EINVAL);
		assert(image == 19 && output == 17);
		cases++;
	}
	cases += 3;
}

static void boot_cases(void)
{
	enum { HEADER_OFFSET = 25, PREFIX_SIZE = 56, DATA_OFFSET = 81,
	       DATA_SIZE = 128, IMAGE_SIZE = DATA_OFFSET + DATA_SIZE };
	u8 storage[IMAGE_SIZE + 8] __aligned(8), *bytes;
	struct nvfw_bin_hdr hdr, input = {
		.bin_magic = 17, .bin_ver = 99, .bin_size = U32_MAX,
		.header_offset = HEADER_OFFSET, .data_offset = DATA_OFFSET,
		.data_size = DATA_SIZE,
	};
	RM_RISCV_UCODE_DESC desc, original = {
		.version = 1, .manifestOffset = 0, .manifestSize = 16,
		.monitorDataOffset = 16, .monitorDataSize = 32,
		.monitorCodeOffset = 48, .monitorCodeSize = 80,
		.swbromCodeOffset = U32_MAX,
	};
	const size_t prefix = offsetof(RM_RISCV_UCODE_DESC, monitorCodeSize) +
			      sizeof(desc.monitorCodeSize);

	assert(prefix == PREFIX_SIZE);
	for (size_t base = 0; base < 8; base++) {
		bytes = storage + base;
		memset(bytes, 0xa5, IMAGE_SIZE);
		memcpy(bytes, &input, sizeof(input));
		memcpy(bytes + input.header_offset, &original, prefix);
		assert(!r535_gsp_rm_boot_parse(bytes, IMAGE_SIZE, &hdr, &desc));
		assert(hdr.bin_size == U32_MAX && hdr.data_size == DATA_SIZE);
		assert(desc.manifestSize == 16 && desc.monitorDataOffset == 16);
		assert(desc.monitorDataSize == 32 && desc.monitorCodeOffset == 48);
		assert(desc.monitorCodeSize == 80);
		cases++;
	}
	bytes = storage + 1;
	memset(bytes, 0xa5, IMAGE_SIZE);
	memcpy(bytes, &input, sizeof(input));
	memcpy(bytes + input.header_offset, &original, prefix);
	for (size_t length = 0; length < sizeof(hdr); length++) {
		assert(r535_gsp_rm_boot_parse(bytes, length, &hdr, &desc) == -EINVAL);
		cases++;
	}
	for (unsigned int field = 0; field < 9; field++) {
		struct nvfw_bin_hdr changed = input;
		RM_RISCV_UCODE_DESC monitor = original;

		switch (field) {
		case 0: changed.header_offset = U32_MAX; break;
		case 1: changed.data_offset = U32_MAX; break;
		case 2: changed.data_size = U32_MAX; break;
		case 3: monitor.monitorCodeOffset = U32_MAX; break;
		case 4: monitor.monitorCodeSize = U32_MAX; break;
		case 5: monitor.monitorDataOffset = U32_MAX; break;
		case 6: monitor.monitorDataSize = U32_MAX; break;
		case 7: monitor.manifestOffset = U32_MAX; break;
		case 8: monitor.manifestSize = U32_MAX; break;
		}
		memcpy(bytes, &changed, sizeof(changed));
		memcpy(bytes + input.header_offset, &monitor, prefix);
		assert(r535_gsp_rm_boot_parse(bytes, IMAGE_SIZE, &hdr, &desc) == -EINVAL);
		cases++;
	}
	/* The declared tail is not consumed, and need not exist. No invented
	 * magic/version gate or SwBrom extent rule may enter this bounds helper. */
	input = (struct nvfw_bin_hdr){
		.bin_magic = 17, .bin_ver = 99, .bin_size = U32_MAX,
		.header_offset = 24, .data_offset = 24 + (u32)prefix, .data_size = 1,
	};
	original = (RM_RISCV_UCODE_DESC){.version = 1, .swbromCodeOffset = U32_MAX};
	memcpy(bytes, &input, sizeof(input));
	memcpy(bytes + input.header_offset, &original, prefix);
	assert(!r535_gsp_rm_boot_parse(bytes, input.data_offset + 1, &hdr, &desc));
	assert(r535_gsp_rm_boot_parse(bytes, input.data_offset, &hdr, &desc) == -EINVAL);
	input.data_offset--;
	memcpy(bytes, &input, sizeof(input));
	assert(r535_gsp_rm_boot_parse(bytes, 24 + prefix - 1, &hdr, &desc) == -EINVAL);
	cases += 3;
}

static void fmc_fixture(u8 *bytes)
{
	static const char names[] = ".shstrtab\0hash\0signature\0publickey\0image\0";
	struct elf32_shdr shdr[FMC_NUM_SECTIONS] = {
		{}, {.sh_name = 0, .sh_type = SHT_STRTAB, .sh_flags = SHF_STRINGS,
		     .sh_offset = 292, .sh_size = sizeof(names)},
		{.sh_name = 10, .sh_type = SHT_PROGBITS, .sh_flags = FMC_SHF_FLAGS,
		 .sh_offset = 400, .sh_size = 48},
		{.sh_name = 15, .sh_type = SHT_PROGBITS, .sh_flags = FMC_SHF_FLAGS,
		 .sh_offset = 448, .sh_size = 96},
		{.sh_name = 25, .sh_type = SHT_PROGBITS, .sh_flags = FMC_SHF_FLAGS,
		 .sh_offset = 544, .sh_size = 97},
		{.sh_name = 35, .sh_type = SHT_PROGBITS, .sh_flags = FMC_SHF_FLAGS,
		 .sh_offset = 641, .sh_size = 129},
	};

	memset(bytes, 0xa5, 1024);
	memcpy(bytes, elf_header, sizeof(elf_header));
	memcpy(bytes + 292, names, sizeof(names));
	for (unsigned int i = 2; i < FMC_NUM_SECTIONS; i++)
		shdr[i].sh_info = crc32_le(U32_MAX, bytes + shdr[i].sh_offset,
					 shdr[i].sh_size) ^ U32_MAX;
	memcpy(bytes + ELF_HDR_SIZE, shdr, sizeof(shdr));
}

static void fmc_cases(void)
{
	u8 storage[1032] __aligned(8), *bytes = storage + 1;
	struct elf32_shdr shdr;
	unsigned int length;

	for (size_t base = 0; base < 8; base++) {
		fmc_fixture(storage + base);
		assert(elf_validate_sections(storage + base, 1024));
		assert(elf_section(storage + base, "image", &length) == storage + base + 641);
		assert(length == 129);
		cases++;
	}
	fmc_fixture(bytes);
	for (size_t size = 0; size < 292; size++) {
		assert(!elf_validate_sections(bytes, size));
		cases++;
	}
	for (size_t byte = 0; byte < sizeof(elf_header); byte++) {
		fmc_fixture(bytes);
		bytes[byte] ^= 1;
		assert(!elf_validate_sections(bytes, 1024));
		cases++;
	}
	for (unsigned int field = 0; field < 7; field++) {
		fmc_fixture(bytes);
		memcpy(&shdr, bytes + ELF_HDR_SIZE + 5 * sizeof(shdr), sizeof(shdr));
		switch (field) {
		case 0: shdr.sh_name = U32_MAX; break;
		case 1: shdr.sh_offset = U32_MAX; break;
		case 2: shdr.sh_size = U32_MAX; break;
		case 3: shdr.sh_offset = 291; break;
		case 4: shdr.sh_type = SHT_STRTAB; break;
		case 5: shdr.sh_flags ^= SHF_ALLOC; break;
		case 6: shdr.sh_info ^= 1; break;
		}
		memcpy(bytes + ELF_HDR_SIZE + 5 * sizeof(shdr), &shdr, sizeof(shdr));
		assert(!elf_validate_sections(bytes, 1024));
		cases++;
	}
	fmc_fixture(bytes);
	bytes[769] ^= 1;
	assert(!elf_validate_sections(bytes, 1024));
	fmc_fixture(bytes);
	memset(bytes + 292 + 35, 'x', 7);
	assert(!elf_validate_sections(bytes, 1024));
	fmc_fixture(bytes);
	length = 17;
	assert(elf_validate_sections(bytes, 1024));
	assert(!elf_section(bytes, "missing", &length) && length == 17);
	/* Duplicate required names fail lookup, before the caller allocates. */
	memcpy(&shdr, bytes + ELF_HDR_SIZE + 3 * sizeof(shdr), sizeof(shdr));
	shdr.sh_name = 10;
	memcpy(bytes + ELF_HDR_SIZE + 3 * sizeof(shdr), &shdr, sizeof(shdr));
	assert(elf_validate_sections(bytes, 1024));
	assert(!elf_section(bytes, "hash", &length) && length == 17);
	cases += 4;
}

static void authored_cases(void)
{
	static_assert(sizeof(struct elf64_hdr) == 64);
	static_assert(sizeof(struct elf64_shdr) == 64);
	static_assert(sizeof(struct elf32_hdr) == 52);
	static_assert(sizeof(struct elf32_shdr) == 40);
	static_assert(sizeof(struct nvfw_bin_hdr) == 24);
	static_assert(GSP_PAGE_SIZE == 4096 && PAGE_SIZE == 4096);
	cases = 0;
	elf_cases();
	geometry_cases();
	boot_cases();
	fmc_cases();
	printf("nouveau_firmware_authored: %u synthetic parser/geometry cases\n", cases);
}

#ifndef STELA_NOUVEAU_FIRMWARE_NO_MAIN
int main(void)
{
	authored_cases();
	return 0;
}
#endif
