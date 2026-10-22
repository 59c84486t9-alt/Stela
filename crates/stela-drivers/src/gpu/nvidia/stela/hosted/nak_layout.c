/* SPDX-License-Identifier: MIT */
/* NAK reads its frontend's constant-buffer layout from these two globals,
 * which NVK defines for Vulkan. Stela keeps the sample locations and masks
 * and the printf buffer address in constant buffer 0 for every stage. */
#include "nouveau/compiler/nak.h"

const struct nak_constant_offset_info nak_const_offsets_base = {
    .sample_info_cb = 0,
    .sample_locations_offset = 0,
    .sample_masks_offset = 256,
    .printf_cb = 0,
    .printf_buffer_offset = 512,
};

const struct nak_constant_offset_info nak_const_offsets_turing_graphics = {
    .sample_info_cb = 0,
    .sample_locations_offset = 0,
    .sample_masks_offset = 256,
    .printf_cb = 0,
    .printf_buffer_offset = 512,
};
