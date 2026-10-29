// SPDX-License-Identifier: MIT
/* Actual Linux/EFI literal ABI, independent of the host C library's wchar.
 * This fixture qualifies compiler data representation, never firmware calls. */
#include <linux/efi.h>
#include <stela/test.h>

_Static_assert(sizeof(*L"A") == sizeof(efi_char16_t), "Linux wide literal width");
_Static_assert(__builtin_types_compatible_p(__typeof__(*L"A"), efi_char16_t),
	       "Linux wide literal element type");
static const efi_char16_t firmware_name[] = L"A\U0001f600";
static const efi_char16_t *identity(const efi_char16_t *value) { return value; }

int main(void)
{
	const efi_char16_t *value = identity(L"A\U0001f600");
	assert(sizeof(firmware_name) == 4 * sizeof(efi_char16_t));
	assert(value[0] == 'A' && value[1] == 0xd83d && value[2] == 0xde00 && !value[3]);
	for (size_t i = 0; i < 4; i++)
		assert(value[i] == firmware_name[i]);
	printf("Linux compiler ABI: UTF-16 wide literals match original EFI types\n");
	return 0;
}