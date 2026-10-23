/* SPDX-License-Identifier: MIT */
/* Separate opt-in entry: unchanged retained input, parser acceptance only.
 * Build only after the source generator checks the explicitly selected input.
 * Absence is not an executed/pass result and has no replacement bytes. */
#define STELA_NOUVEAU_FIRMWARE_NO_MAIN
#include "firmware.c"
#include "nouveau_firmware_real_boot.inc"

int main(void)
{
	const size_t size = sizeof(nouveau_real_bootloader);
	u8 *storage = calloc(size + 8, 1);
	struct nvfw_bin_hdr hdr;
	RM_RISCV_UCODE_DESC desc;
	unsigned int retained_cases = 0;

	authored_cases();
	assert(storage && size == 200812);
	for (size_t base = 0; base < 8; base++) {
		u8 *bytes = storage + base;

		memcpy(bytes, nouveau_real_bootloader, size);
		assert(!r535_gsp_rm_boot_parse(bytes, size, &hdr, &desc));
		assert(hdr.bin_size == size + 148 && hdr.data_size == 200704);
		assert(hdr.header_offset == 24 && hdr.data_offset == 108);
		assert(desc.manifestSize == 2560 && desc.monitorDataOffset == 2560);
		assert(desc.monitorDataSize == 43008 && desc.monitorCodeOffset == 45568);
		assert(desc.monitorCodeSize == 153600);
		assert(!memcmp(bytes, nouveau_real_bootloader, size));
		retained_cases++;
	}
	free(storage);
	printf("nouveau_firmware_retained: %u unchanged-input parser cases; no firmware execution\n",
	       retained_cases);
	return 0;
}
