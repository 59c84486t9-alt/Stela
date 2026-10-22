/* SPDX-License-Identifier: GPL-2.0-only */
/* Original Linux PCI matching functions retain their GPL-2.0 license. */
/*
 * Copyright 2008 Advanced Micro Devices, Inc.
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


/*
 * Copyright 2018-2024 Advanced Micro Devices, Inc. All rights reserved.
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
 */


/*
 * Copyright 2000 VA Linux Systems, Inc., Sunnyvale, California.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * VA LINUX SYSTEMS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/* Frozen original Linux 8d3ae59288f1e7d58d76558a6ee96d533bc5019f donor.
 * Test-only original declarations/consumers; no runtime provider.
 */
#define amdgpu_unsupported_pciidlist ref_amdgpu_unsupported_pciidlist
#define pciidlist ref_pciidlist
#define asic_type_quirks ref_asic_type_quirks
#define amdgpu_fix_asic_type ref_amdgpu_fix_asic_type
#define amdgpu_support_enabled ref_amdgpu_support_enabled
#define amdgpu_device_init_apu_flags ref_amdgpu_device_init_apu_flags
#define amdgpu_discovery_get_fw_name ref_amdgpu_discovery_get_fw_name
#define pci_match_one_device ref_pci_match_one_device
#define pci_match_id ref_pci_match_id

static const u16 amdgpu_unsupported_pciidlist[] = {
	/* mach64 */
	0x4354,
	0x4358,
	0x4554,
	0x4742,
	0x4744,
	0x4749,
	0x474C,
	0x474D,
	0x474E,
	0x474F,
	0x4750,
	0x4751,
	0x4752,
	0x4753,
	0x4754,
	0x4755,
	0x4756,
	0x4757,
	0x4758,
	0x4759,
	0x475A,
	0x4C42,
	0x4C44,
	0x4C47,
	0x4C49,
	0x4C4D,
	0x4C4E,
	0x4C50,
	0x4C51,
	0x4C52,
	0x4C53,
	0x5654,
	0x5655,
	0x5656,
	/* r128 */
	0x4c45,
	0x4c46,
	0x4d46,
	0x4d4c,
	0x5041,
	0x5042,
	0x5043,
	0x5044,
	0x5045,
	0x5046,
	0x5047,
	0x5048,
	0x5049,
	0x504A,
	0x504B,
	0x504C,
	0x504D,
	0x504E,
	0x504F,
	0x5050,
	0x5051,
	0x5052,
	0x5053,
	0x5054,
	0x5055,
	0x5056,
	0x5057,
	0x5058,
	0x5245,
	0x5246,
	0x5247,
	0x524b,
	0x524c,
	0x534d,
	0x5446,
	0x544C,
	0x5452,
	/* radeon */
	0x3150,
	0x3151,
	0x3152,
	0x3154,
	0x3155,
	0x3E50,
	0x3E54,
	0x4136,
	0x4137,
	0x4144,
	0x4145,
	0x4146,
	0x4147,
	0x4148,
	0x4149,
	0x414A,
	0x414B,
	0x4150,
	0x4151,
	0x4152,
	0x4153,
	0x4154,
	0x4155,
	0x4156,
	0x4237,
	0x4242,
	0x4336,
	0x4337,
	0x4437,
	0x4966,
	0x4967,
	0x4A48,
	0x4A49,
	0x4A4A,
	0x4A4B,
	0x4A4C,
	0x4A4D,
	0x4A4E,
	0x4A4F,
	0x4A50,
	0x4A54,
	0x4B48,
	0x4B49,
	0x4B4A,
	0x4B4B,
	0x4B4C,
	0x4C57,
	0x4C58,
	0x4C59,
	0x4C5A,
	0x4C64,
	0x4C66,
	0x4C67,
	0x4E44,
	0x4E45,
	0x4E46,
	0x4E47,
	0x4E48,
	0x4E49,
	0x4E4A,
	0x4E4B,
	0x4E50,
	0x4E51,
	0x4E52,
	0x4E53,
	0x4E54,
	0x4E56,
	0x5144,
	0x5145,
	0x5146,
	0x5147,
	0x5148,
	0x514C,
	0x514D,
	0x5157,
	0x5158,
	0x5159,
	0x515A,
	0x515E,
	0x5460,
	0x5462,
	0x5464,
	0x5548,
	0x5549,
	0x554A,
	0x554B,
	0x554C,
	0x554D,
	0x554E,
	0x554F,
	0x5550,
	0x5551,
	0x5552,
	0x5554,
	0x564A,
	0x564B,
	0x564F,
	0x5652,
	0x5653,
	0x5657,
	0x5834,
	0x5835,
	0x5954,
	0x5955,
	0x5974,
	0x5975,
	0x5960,
	0x5961,
	0x5962,
	0x5964,
	0x5965,
	0x5969,
	0x5a41,
	0x5a42,
	0x5a61,
	0x5a62,
	0x5b60,
	0x5b62,
	0x5b63,
	0x5b64,
	0x5b65,
	0x5c61,
	0x5c63,
	0x5d48,
	0x5d49,
	0x5d4a,
	0x5d4c,
	0x5d4d,
	0x5d4e,
	0x5d4f,
	0x5d50,
	0x5d52,
	0x5d57,
	0x5e48,
	0x5e4a,
	0x5e4b,
	0x5e4c,
	0x5e4d,
	0x5e4f,
	0x6700,
	0x6701,
	0x6702,
	0x6703,
	0x6704,
	0x6705,
	0x6706,
	0x6707,
	0x6708,
	0x6709,
	0x6718,
	0x6719,
	0x671c,
	0x671d,
	0x671f,
	0x6720,
	0x6721,
	0x6722,
	0x6723,
	0x6724,
	0x6725,
	0x6726,
	0x6727,
	0x6728,
	0x6729,
	0x6738,
	0x6739,
	0x673e,
	0x6740,
	0x6741,
	0x6742,
	0x6743,
	0x6744,
	0x6745,
	0x6746,
	0x6747,
	0x6748,
	0x6749,
	0x674A,
	0x6750,
	0x6751,
	0x6758,
	0x6759,
	0x675B,
	0x675D,
	0x675F,
	0x6760,
	0x6761,
	0x6762,
	0x6763,
	0x6764,
	0x6765,
	0x6766,
	0x6767,
	0x6768,
	0x6770,
	0x6771,
	0x6772,
	0x6778,
	0x6779,
	0x677B,
	0x6840,
	0x6841,
	0x6842,
	0x6843,
	0x6849,
	0x684C,
	0x6850,
	0x6858,
	0x6859,
	0x6880,
	0x6888,
	0x6889,
	0x688A,
	0x688C,
	0x688D,
	0x6898,
	0x6899,
	0x689b,
	0x689c,
	0x689d,
	0x689e,
	0x68a0,
	0x68a1,
	0x68a8,
	0x68a9,
	0x68b0,
	0x68b8,
	0x68b9,
	0x68ba,
	0x68be,
	0x68bf,
	0x68c0,
	0x68c1,
	0x68c7,
	0x68c8,
	0x68c9,
	0x68d8,
	0x68d9,
	0x68da,
	0x68de,
	0x68e0,
	0x68e1,
	0x68e4,
	0x68e5,
	0x68e8,
	0x68e9,
	0x68f1,
	0x68f2,
	0x68f8,
	0x68f9,
	0x68fa,
	0x68fe,
	0x7100,
	0x7101,
	0x7102,
	0x7103,
	0x7104,
	0x7105,
	0x7106,
	0x7108,
	0x7109,
	0x710A,
	0x710B,
	0x710C,
	0x710E,
	0x710F,
	0x7140,
	0x7141,
	0x7142,
	0x7143,
	0x7144,
	0x7145,
	0x7146,
	0x7147,
	0x7149,
	0x714A,
	0x714B,
	0x714C,
	0x714D,
	0x714E,
	0x714F,
	0x7151,
	0x7152,
	0x7153,
	0x715E,
	0x715F,
	0x7180,
	0x7181,
	0x7183,
	0x7186,
	0x7187,
	0x7188,
	0x718A,
	0x718B,
	0x718C,
	0x718D,
	0x718F,
	0x7193,
	0x7196,
	0x719B,
	0x719F,
	0x71C0,
	0x71C1,
	0x71C2,
	0x71C3,
	0x71C4,
	0x71C5,
	0x71C6,
	0x71C7,
	0x71CD,
	0x71CE,
	0x71D2,
	0x71D4,
	0x71D5,
	0x71D6,
	0x71DA,
	0x71DE,
	0x7200,
	0x7210,
	0x7211,
	0x7240,
	0x7243,
	0x7244,
	0x7245,
	0x7246,
	0x7247,
	0x7248,
	0x7249,
	0x724A,
	0x724B,
	0x724C,
	0x724D,
	0x724E,
	0x724F,
	0x7280,
	0x7281,
	0x7283,
	0x7284,
	0x7287,
	0x7288,
	0x7289,
	0x728B,
	0x728C,
	0x7290,
	0x7291,
	0x7293,
	0x7297,
	0x7834,
	0x7835,
	0x791e,
	0x791f,
	0x793f,
	0x7941,
	0x7942,
	0x796c,
	0x796d,
	0x796e,
	0x796f,
	0x9400,
	0x9401,
	0x9402,
	0x9403,
	0x9405,
	0x940A,
	0x940B,
	0x940F,
	0x94A0,
	0x94A1,
	0x94A3,
	0x94B1,
	0x94B3,
	0x94B4,
	0x94B5,
	0x94B9,
	0x9440,
	0x9441,
	0x9442,
	0x9443,
	0x9444,
	0x9446,
	0x944A,
	0x944B,
	0x944C,
	0x944E,
	0x9450,
	0x9452,
	0x9456,
	0x945A,
	0x945B,
	0x945E,
	0x9460,
	0x9462,
	0x946A,
	0x946B,
	0x947A,
	0x947B,
	0x9480,
	0x9487,
	0x9488,
	0x9489,
	0x948A,
	0x948F,
	0x9490,
	0x9491,
	0x9495,
	0x9498,
	0x949C,
	0x949E,
	0x949F,
	0x94C0,
	0x94C1,
	0x94C3,
	0x94C4,
	0x94C5,
	0x94C6,
	0x94C7,
	0x94C8,
	0x94C9,
	0x94CB,
	0x94CC,
	0x94CD,
	0x9500,
	0x9501,
	0x9504,
	0x9505,
	0x9506,
	0x9507,
	0x9508,
	0x9509,
	0x950F,
	0x9511,
	0x9515,
	0x9517,
	0x9519,
	0x9540,
	0x9541,
	0x9542,
	0x954E,
	0x954F,
	0x9552,
	0x9553,
	0x9555,
	0x9557,
	0x955f,
	0x9580,
	0x9581,
	0x9583,
	0x9586,
	0x9587,
	0x9588,
	0x9589,
	0x958A,
	0x958B,
	0x958C,
	0x958D,
	0x958E,
	0x958F,
	0x9590,
	0x9591,
	0x9593,
	0x9595,
	0x9596,
	0x9597,
	0x9598,
	0x9599,
	0x959B,
	0x95C0,
	0x95C2,
	0x95C4,
	0x95C5,
	0x95C6,
	0x95C7,
	0x95C9,
	0x95CC,
	0x95CD,
	0x95CE,
	0x95CF,
	0x9610,
	0x9611,
	0x9612,
	0x9613,
	0x9614,
	0x9615,
	0x9616,
	0x9640,
	0x9641,
	0x9642,
	0x9643,
	0x9644,
	0x9645,
	0x9647,
	0x9648,
	0x9649,
	0x964a,
	0x964b,
	0x964c,
	0x964e,
	0x964f,
	0x9710,
	0x9711,
	0x9712,
	0x9713,
	0x9714,
	0x9715,
	0x9802,
	0x9803,
	0x9804,
	0x9805,
	0x9806,
	0x9807,
	0x9808,
	0x9809,
	0x980A,
	0x9900,
	0x9901,
	0x9903,
	0x9904,
	0x9905,
	0x9906,
	0x9907,
	0x9908,
	0x9909,
	0x990A,
	0x990B,
	0x990C,
	0x990D,
	0x990E,
	0x990F,
	0x9910,
	0x9913,
	0x9917,
	0x9918,
	0x9919,
	0x9990,
	0x9991,
	0x9992,
	0x9993,
	0x9994,
	0x9995,
	0x9996,
	0x9997,
	0x9998,
	0x9999,
	0x999A,
	0x999B,
	0x999C,
	0x999D,
	0x99A0,
	0x99A2,
	0x99A4,
	/* radeon secondary ids */
	0x3171,
	0x3e70,
	0x4164,
	0x4165,
	0x4166,
	0x4168,
	0x4170,
	0x4171,
	0x4172,
	0x4173,
	0x496e,
	0x4a69,
	0x4a6a,
	0x4a6b,
	0x4a70,
	0x4a74,
	0x4b69,
	0x4b6b,
	0x4b6c,
	0x4c6e,
	0x4e64,
	0x4e65,
	0x4e66,
	0x4e67,
	0x4e68,
	0x4e69,
	0x4e6a,
	0x4e71,
	0x4f73,
	0x5569,
	0x556b,
	0x556d,
	0x556f,
	0x5571,
	0x5854,
	0x5874,
	0x5940,
	0x5941,
	0x5b70,
	0x5b72,
	0x5b73,
	0x5b74,
	0x5b75,
	0x5d44,
	0x5d45,
	0x5d6d,
	0x5d6f,
	0x5d72,
	0x5d77,
	0x5e6b,
	0x5e6d,
	0x7120,
	0x7124,
	0x7129,
	0x712e,
	0x712f,
	0x7162,
	0x7163,
	0x7166,
	0x7167,
	0x7172,
	0x7173,
	0x71a0,
	0x71a1,
	0x71a3,
	0x71a7,
	0x71bb,
	0x71e0,
	0x71e1,
	0x71e2,
	0x71e6,
	0x71e7,
	0x71f2,
	0x7269,
	0x726b,
	0x726e,
	0x72a0,
	0x72a8,
	0x72b1,
	0x72b3,
	0x793f,
};


static const struct pci_device_id pciidlist[] = {
	{0x1002, 0x6780, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TAHITI},
	{0x1002, 0x6784, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TAHITI},
	{0x1002, 0x6788, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TAHITI},
	{0x1002, 0x678A, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TAHITI},
	{0x1002, 0x6790, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TAHITI},
	{0x1002, 0x6791, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TAHITI},
	{0x1002, 0x6792, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TAHITI},
	{0x1002, 0x6798, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TAHITI},
	{0x1002, 0x6799, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TAHITI},
	{0x1002, 0x679A, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TAHITI},
	{0x1002, 0x679B, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TAHITI},
	{0x1002, 0x679E, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TAHITI},
	{0x1002, 0x679F, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TAHITI},
	{0x1002, 0x6800, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_PITCAIRN|AMD_IS_MOBILITY},
	{0x1002, 0x6801, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_PITCAIRN|AMD_IS_MOBILITY},
	{0x1002, 0x6802, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_PITCAIRN|AMD_IS_MOBILITY},
	{0x1002, 0x6806, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_PITCAIRN},
	{0x1002, 0x6808, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_PITCAIRN},
	{0x1002, 0x6809, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_PITCAIRN},
	{0x1002, 0x6810, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_PITCAIRN},
	{0x1002, 0x6811, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_PITCAIRN},
	{0x1002, 0x6816, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_PITCAIRN},
	{0x1002, 0x6817, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_PITCAIRN},
	{0x1002, 0x6818, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_PITCAIRN},
	{0x1002, 0x6819, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_PITCAIRN},
	{0x1002, 0x6600, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_OLAND|AMD_IS_MOBILITY},
	{0x1002, 0x6601, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_OLAND|AMD_IS_MOBILITY},
	{0x1002, 0x6602, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_OLAND|AMD_IS_MOBILITY},
	{0x1002, 0x6603, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_OLAND|AMD_IS_MOBILITY},
	{0x1002, 0x6604, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_OLAND|AMD_IS_MOBILITY},
	{0x1002, 0x6605, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_OLAND|AMD_IS_MOBILITY},
	{0x1002, 0x6606, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_OLAND|AMD_IS_MOBILITY},
	{0x1002, 0x6607, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_OLAND|AMD_IS_MOBILITY},
	{0x1002, 0x6608, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_OLAND},
	{0x1002, 0x6610, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_OLAND},
	{0x1002, 0x6611, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_OLAND},
	{0x1002, 0x6613, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_OLAND},
	{0x1002, 0x6617, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_OLAND|AMD_IS_MOBILITY},
	{0x1002, 0x6620, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_OLAND|AMD_IS_MOBILITY},
	{0x1002, 0x6621, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_OLAND|AMD_IS_MOBILITY},
	{0x1002, 0x6623, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_OLAND|AMD_IS_MOBILITY},
	{0x1002, 0x6631, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_OLAND},
	{0x1002, 0x6820, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE|AMD_IS_MOBILITY},
	{0x1002, 0x6821, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE|AMD_IS_MOBILITY},
	{0x1002, 0x6822, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE|AMD_IS_MOBILITY},
	{0x1002, 0x6823, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE|AMD_IS_MOBILITY},
	{0x1002, 0x6824, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE|AMD_IS_MOBILITY},
	{0x1002, 0x6825, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE|AMD_IS_MOBILITY},
	{0x1002, 0x6826, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE|AMD_IS_MOBILITY},
	{0x1002, 0x6827, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE|AMD_IS_MOBILITY},
	{0x1002, 0x6828, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE},
	{0x1002, 0x6829, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE},
	{0x1002, 0x682A, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE|AMD_IS_MOBILITY},
	{0x1002, 0x682B, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE|AMD_IS_MOBILITY},
	{0x1002, 0x682C, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE},
	{0x1002, 0x682D, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE|AMD_IS_MOBILITY},
	{0x1002, 0x682F, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE|AMD_IS_MOBILITY},
	{0x1002, 0x6830, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE|AMD_IS_MOBILITY},
	{0x1002, 0x6831, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE|AMD_IS_MOBILITY},
	{0x1002, 0x6835, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE},
	{0x1002, 0x6837, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE},
	{0x1002, 0x6838, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE},
	{0x1002, 0x6839, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE},
	{0x1002, 0x683B, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE},
	{0x1002, 0x683D, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE},
	{0x1002, 0x683F, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VERDE},
	{0x1002, 0x6660, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_HAINAN|AMD_IS_MOBILITY},
	{0x1002, 0x6663, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_HAINAN|AMD_IS_MOBILITY},
	{0x1002, 0x6664, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_HAINAN|AMD_IS_MOBILITY},
	{0x1002, 0x6665, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_HAINAN|AMD_IS_MOBILITY},
	{0x1002, 0x6667, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_HAINAN|AMD_IS_MOBILITY},
	{0x1002, 0x666F, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_HAINAN|AMD_IS_MOBILITY},
	/* Kaveri */
	{0x1002, 0x1304, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x1305, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_APU},
	{0x1002, 0x1306, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x1307, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_APU},
	{0x1002, 0x1309, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x130A, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x130B, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x130C, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x130D, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x130E, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x130F, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_APU},
	{0x1002, 0x1310, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_APU},
	{0x1002, 0x1311, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_APU},
	{0x1002, 0x1312, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_APU},
	{0x1002, 0x1313, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_APU},
	{0x1002, 0x1315, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_APU},
	{0x1002, 0x1316, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_APU},
	{0x1002, 0x1317, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x1318, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x131B, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_APU},
	{0x1002, 0x131C, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_APU},
	{0x1002, 0x131D, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KAVERI|AMD_IS_APU},
	/* Bonaire */
	{0x1002, 0x6640, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_BONAIRE|AMD_IS_MOBILITY},
	{0x1002, 0x6641, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_BONAIRE|AMD_IS_MOBILITY},
	{0x1002, 0x6646, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_BONAIRE|AMD_IS_MOBILITY},
	{0x1002, 0x6647, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_BONAIRE|AMD_IS_MOBILITY},
	{0x1002, 0x6649, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_BONAIRE},
	{0x1002, 0x6650, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_BONAIRE},
	{0x1002, 0x6651, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_BONAIRE},
	{0x1002, 0x6658, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_BONAIRE},
	{0x1002, 0x665c, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_BONAIRE},
	{0x1002, 0x665d, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_BONAIRE},
	{0x1002, 0x665f, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_BONAIRE},
	/* Hawaii */
	{0x1002, 0x67A0, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_HAWAII},
	{0x1002, 0x67A1, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_HAWAII},
	{0x1002, 0x67A2, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_HAWAII},
	{0x1002, 0x67A8, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_HAWAII},
	{0x1002, 0x67A9, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_HAWAII},
	{0x1002, 0x67AA, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_HAWAII},
	{0x1002, 0x67B0, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_HAWAII},
	{0x1002, 0x67B1, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_HAWAII},
	{0x1002, 0x67B8, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_HAWAII},
	{0x1002, 0x67B9, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_HAWAII},
	{0x1002, 0x67BA, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_HAWAII},
	{0x1002, 0x67BE, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_HAWAII},
	/* Kabini */
	{0x1002, 0x9830, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KABINI|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x9831, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KABINI|AMD_IS_APU},
	{0x1002, 0x9832, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KABINI|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x9833, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KABINI|AMD_IS_APU},
	{0x1002, 0x9834, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KABINI|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x9835, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KABINI|AMD_IS_APU},
	{0x1002, 0x9836, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KABINI|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x9837, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KABINI|AMD_IS_APU},
	{0x1002, 0x9838, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KABINI|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x9839, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KABINI|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x983a, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KABINI|AMD_IS_APU},
	{0x1002, 0x983b, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KABINI|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x983c, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KABINI|AMD_IS_APU},
	{0x1002, 0x983d, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KABINI|AMD_IS_APU},
	{0x1002, 0x983e, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KABINI|AMD_IS_APU},
	{0x1002, 0x983f, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_KABINI|AMD_IS_APU},
	/* mullins */
	{0x1002, 0x9850, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_MULLINS|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x9851, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_MULLINS|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x9852, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_MULLINS|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x9853, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_MULLINS|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x9854, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_MULLINS|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x9855, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_MULLINS|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x9856, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_MULLINS|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x9857, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_MULLINS|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x9858, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_MULLINS|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x9859, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_MULLINS|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x985A, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_MULLINS|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x985B, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_MULLINS|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x985C, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_MULLINS|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x985D, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_MULLINS|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x985E, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_MULLINS|AMD_IS_MOBILITY|AMD_IS_APU},
	{0x1002, 0x985F, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_MULLINS|AMD_IS_MOBILITY|AMD_IS_APU},
	/* topaz */
	{0x1002, 0x6900, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TOPAZ},
	{0x1002, 0x6901, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TOPAZ},
	{0x1002, 0x6902, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TOPAZ},
	{0x1002, 0x6903, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TOPAZ},
	{0x1002, 0x6907, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TOPAZ},
	/* tonga */
	{0x1002, 0x6920, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TONGA},
	{0x1002, 0x6921, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TONGA},
	{0x1002, 0x6928, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TONGA},
	{0x1002, 0x6929, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TONGA},
	{0x1002, 0x692B, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TONGA},
	{0x1002, 0x692F, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TONGA},
	{0x1002, 0x6930, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TONGA},
	{0x1002, 0x6938, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TONGA},
	{0x1002, 0x6939, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_TONGA},
	/* fiji */
	{0x1002, 0x7300, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_FIJI},
	{0x1002, 0x730F, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_FIJI},
	/* carrizo */
	{0x1002, 0x9870, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_CARRIZO|AMD_IS_APU},
	{0x1002, 0x9874, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_CARRIZO|AMD_IS_APU},
	{0x1002, 0x9875, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_CARRIZO|AMD_IS_APU},
	{0x1002, 0x9876, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_CARRIZO|AMD_IS_APU},
	{0x1002, 0x9877, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_CARRIZO|AMD_IS_APU},
	/* stoney */
	{0x1002, 0x98E4, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_STONEY|AMD_IS_APU},
	/* Polaris11 */
	{0x1002, 0x67E0, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS11},
	{0x1002, 0x67E3, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS11},
	{0x1002, 0x67E8, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS11},
	{0x1002, 0x67EB, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS11},
	{0x1002, 0x67EF, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS11},
	{0x1002, 0x67FF, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS11},
	{0x1002, 0x67E1, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS11},
	{0x1002, 0x67E7, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS11},
	{0x1002, 0x67E9, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS11},
	/* Polaris10 */
	{0x1002, 0x67C0, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS10},
	{0x1002, 0x67C1, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS10},
	{0x1002, 0x67C2, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS10},
	{0x1002, 0x67C4, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS10},
	{0x1002, 0x67C7, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS10},
	{0x1002, 0x67D0, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS10},
	{0x1002, 0x67DF, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS10},
	{0x1002, 0x67C8, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS10},
	{0x1002, 0x67C9, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS10},
	{0x1002, 0x67CA, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS10},
	{0x1002, 0x67CC, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS10},
	{0x1002, 0x67CF, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS10},
	{0x1002, 0x6FDF, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS10},
	/* Polaris12 */
	{0x1002, 0x6980, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS12},
	{0x1002, 0x6981, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS12},
	{0x1002, 0x6985, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS12},
	{0x1002, 0x6986, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS12},
	{0x1002, 0x6987, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS12},
	{0x1002, 0x6995, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS12},
	{0x1002, 0x6997, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS12},
	{0x1002, 0x699F, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_POLARIS12},
	/* VEGAM */
	{0x1002, 0x694C, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGAM},
	{0x1002, 0x694E, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGAM},
	{0x1002, 0x694F, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGAM},
	/* Vega 10 */
	{0x1002, 0x6860, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA10},
	{0x1002, 0x6861, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA10},
	{0x1002, 0x6862, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA10},
	{0x1002, 0x6863, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA10},
	{0x1002, 0x6864, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA10},
	{0x1002, 0x6867, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA10},
	{0x1002, 0x6868, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA10},
	{0x1002, 0x6869, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA10},
	{0x1002, 0x686a, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA10},
	{0x1002, 0x686b, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA10},
	{0x1002, 0x686c, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA10},
	{0x1002, 0x686d, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA10},
	{0x1002, 0x686e, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA10},
	{0x1002, 0x686f, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA10},
	{0x1002, 0x687f, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA10},
	/* Vega 12 */
	{0x1002, 0x69A0, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA12},
	{0x1002, 0x69A1, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA12},
	{0x1002, 0x69A2, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA12},
	{0x1002, 0x69A3, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA12},
	{0x1002, 0x69AF, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA12},
	/* Vega 20 */
	{0x1002, 0x66A0, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA20},
	{0x1002, 0x66A1, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA20},
	{0x1002, 0x66A2, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA20},
	{0x1002, 0x66A3, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA20},
	{0x1002, 0x66A4, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA20},
	{0x1002, 0x66A7, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA20},
	{0x1002, 0x66AF, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_VEGA20},
	/* Raven */
	{0x1002, 0x15dd, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_RAVEN|AMD_IS_APU},
	{0x1002, 0x15d8, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_RAVEN|AMD_IS_APU},
	/* Arcturus */
	{0x1002, 0x738C, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_ARCTURUS},
	{0x1002, 0x7388, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_ARCTURUS},
	{0x1002, 0x738E, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_ARCTURUS},
	{0x1002, 0x7390, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_ARCTURUS},
	/* Navi10 */
	{0x1002, 0x7310, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVI10},
	{0x1002, 0x7312, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVI10},
	{0x1002, 0x7318, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVI10},
	{0x1002, 0x7319, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVI10},
	{0x1002, 0x731A, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVI10},
	{0x1002, 0x731B, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVI10},
	{0x1002, 0x731E, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVI10},
	{0x1002, 0x731F, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVI10},
	/* Navi14 */
	{0x1002, 0x7340, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVI14},
	{0x1002, 0x7341, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVI14},
	{0x1002, 0x7347, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVI14},
	{0x1002, 0x734F, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVI14},

	/* Renoir */
	{0x1002, 0x15E7, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_RENOIR|AMD_IS_APU},
	{0x1002, 0x1636, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_RENOIR|AMD_IS_APU},
	{0x1002, 0x1638, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_RENOIR|AMD_IS_APU},
	{0x1002, 0x164C, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_RENOIR|AMD_IS_APU},

	/* Navi12 */
	{0x1002, 0x7360, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVI12},
	{0x1002, 0x7362, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVI12},

	/* Sienna_Cichlid */
	{0x1002, 0x73A0, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_SIENNA_CICHLID},
	{0x1002, 0x73A1, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_SIENNA_CICHLID},
	{0x1002, 0x73A2, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_SIENNA_CICHLID},
	{0x1002, 0x73A3, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_SIENNA_CICHLID},
	{0x1002, 0x73A5, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_SIENNA_CICHLID},
	{0x1002, 0x73A8, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_SIENNA_CICHLID},
	{0x1002, 0x73A9, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_SIENNA_CICHLID},
	{0x1002, 0x73AB, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_SIENNA_CICHLID},
	{0x1002, 0x73AC, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_SIENNA_CICHLID},
	{0x1002, 0x73AD, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_SIENNA_CICHLID},
	{0x1002, 0x73AE, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_SIENNA_CICHLID},
	{0x1002, 0x73AF, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_SIENNA_CICHLID},
	{0x1002, 0x73BF, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_SIENNA_CICHLID},

	/* Yellow Carp */
	{0x1002, 0x164D, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_YELLOW_CARP|AMD_IS_APU},
	{0x1002, 0x1681, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_YELLOW_CARP|AMD_IS_APU},

	/* Navy_Flounder */
	{0x1002, 0x73C0, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVY_FLOUNDER},
	{0x1002, 0x73C1, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVY_FLOUNDER},
	{0x1002, 0x73C3, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVY_FLOUNDER},
	{0x1002, 0x73DA, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVY_FLOUNDER},
	{0x1002, 0x73DB, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVY_FLOUNDER},
	{0x1002, 0x73DC, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVY_FLOUNDER},
	{0x1002, 0x73DD, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVY_FLOUNDER},
	{0x1002, 0x73DE, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVY_FLOUNDER},
	{0x1002, 0x73DF, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_NAVY_FLOUNDER},

	/* DIMGREY_CAVEFISH */
	{0x1002, 0x73E0, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_DIMGREY_CAVEFISH},
	{0x1002, 0x73E1, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_DIMGREY_CAVEFISH},
	{0x1002, 0x73E2, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_DIMGREY_CAVEFISH},
	{0x1002, 0x73E3, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_DIMGREY_CAVEFISH},
	{0x1002, 0x73E8, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_DIMGREY_CAVEFISH},
	{0x1002, 0x73E9, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_DIMGREY_CAVEFISH},
	{0x1002, 0x73EA, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_DIMGREY_CAVEFISH},
	{0x1002, 0x73EB, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_DIMGREY_CAVEFISH},
	{0x1002, 0x73EC, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_DIMGREY_CAVEFISH},
	{0x1002, 0x73ED, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_DIMGREY_CAVEFISH},
	{0x1002, 0x73EF, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_DIMGREY_CAVEFISH},
	{0x1002, 0x73FF, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_DIMGREY_CAVEFISH},

	/* Aldebaran */
	{0x1002, 0x7408, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_ALDEBARAN},
	{0x1002, 0x740C, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_ALDEBARAN},
	{0x1002, 0x740F, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_ALDEBARAN},
	{0x1002, 0x7410, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_ALDEBARAN},

	/* CYAN_SKILLFISH */
	{0x1002, 0x13DB, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_CYAN_SKILLFISH|AMD_IS_APU},
	{0x1002, 0x13F9, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_CYAN_SKILLFISH|AMD_IS_APU},
	{0x1002, 0x13FA, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_CYAN_SKILLFISH|AMD_IS_APU},
	{0x1002, 0x13FB, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_CYAN_SKILLFISH|AMD_IS_APU},
	{0x1002, 0x13FC, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_CYAN_SKILLFISH|AMD_IS_APU},
	{0x1002, 0x13FE, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_CYAN_SKILLFISH|AMD_IS_APU},
	{0x1002, 0x143F, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_CYAN_SKILLFISH|AMD_IS_APU},

	/* BEIGE_GOBY */
	{0x1002, 0x7420, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_BEIGE_GOBY},
	{0x1002, 0x7421, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_BEIGE_GOBY},
	{0x1002, 0x7422, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_BEIGE_GOBY},
	{0x1002, 0x7423, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_BEIGE_GOBY},
	{0x1002, 0x7424, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_BEIGE_GOBY},
	{0x1002, 0x743F, PCI_ANY_ID, PCI_ANY_ID, 0, 0, CHIP_BEIGE_GOBY},

	{ PCI_DEVICE(0x1002, PCI_ANY_ID),
	  .class = PCI_CLASS_DISPLAY_VGA << 8,
	  .class_mask = 0xffffff,
	  .driver_data = CHIP_IP_DISCOVERY },

	{ PCI_DEVICE(0x1002, PCI_ANY_ID),
	  .class = PCI_CLASS_DISPLAY_OTHER << 8,
	  .class_mask = 0xffffff,
	  .driver_data = CHIP_IP_DISCOVERY },

	{ PCI_DEVICE(0x1002, PCI_ANY_ID),
	  .class = PCI_CLASS_ACCELERATOR_PROCESSING << 8,
	  .class_mask = 0xffffff,
	  .driver_data = CHIP_IP_DISCOVERY },

	{0, 0, 0}
};


static const struct amdgpu_asic_type_quirk asic_type_quirks[] = {
	/* differentiate between P10 and P11 asics with the same DID */
	{0x67FF, 0xE3, CHIP_POLARIS10},
	{0x67FF, 0xE7, CHIP_POLARIS10},
	{0x67FF, 0xF3, CHIP_POLARIS10},
	{0x67FF, 0xF7, CHIP_POLARIS10},
};


static unsigned long amdgpu_fix_asic_type(struct pci_dev *pdev, unsigned long flags)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(asic_type_quirks); i++) {
		if (pdev->device == asic_type_quirks[i].device &&
			pdev->revision == asic_type_quirks[i].revision) {
				flags &= ~AMD_ASIC_MASK;
				flags |= asic_type_quirks[i].type;
				break;
			}
	}

	return flags;
}


static bool amdgpu_support_enabled(struct device *dev,
				   const enum amd_asic_type family)
{
	const char *gen;
	const char *param;
	int module_param = -1;
	bool radeon_support_built = IS_ENABLED(CONFIG_DRM_RADEON);
	bool amdgpu_support_built = false;
	bool support_by_default = false;

	switch (family) {
	case CHIP_TAHITI:
	case CHIP_PITCAIRN:
	case CHIP_VERDE:
	case CHIP_OLAND:
	case CHIP_HAINAN:
		gen = "SI";
		param = "si_support";
		module_param = amdgpu_si_support;
		amdgpu_support_built = IS_ENABLED(CONFIG_DRM_AMDGPU_SI);
		support_by_default = true;
		break;

	case CHIP_BONAIRE:
	case CHIP_HAWAII:
	case CHIP_KAVERI:
	case CHIP_KABINI:
	case CHIP_MULLINS:
		gen = "CIK";
		param = "cik_support";
		module_param = amdgpu_cik_support;
		amdgpu_support_built = IS_ENABLED(CONFIG_DRM_AMDGPU_CIK);
		support_by_default = true;
		break;

	default:
		/* All other chips are supported by amdgpu only */
		return true;
	}

	if (!amdgpu_support_built) {
		dev_info(dev, "amdgpu built without %s support\n", gen);
		return false;
	}

	if ((module_param == -1 && (support_by_default || !radeon_support_built)) ||
	    module_param == 1) {
		if (radeon_support_built)
			dev_info(dev, "%s support provided by amdgpu.\n"
				 "Use radeon.%s=1 amdgpu.%s=0 to override.\n",
				 gen, param, param);

		return true;
	}

	if (radeon_support_built)
		dev_info(dev, "%s support provided by radeon.\n"
			 "Use radeon.%s=0 amdgpu.%s=1 to override.\n",
			 gen, param, param);
	else if (module_param == 0)
		dev_info(dev, "%s support disabled by module param\n", gen);

	return false;
}


static int amdgpu_device_init_apu_flags(struct amdgpu_device *adev)
{
	if (!(adev->flags & AMD_IS_APU) ||
	    adev->asic_type < CHIP_RAVEN)
		return 0;

	switch (adev->asic_type) {
	case CHIP_RAVEN:
		if (adev->pdev->device == 0x15dd)
			adev->apu_flags |= AMD_APU_IS_RAVEN;
		if (adev->pdev->device == 0x15d8)
			adev->apu_flags |= AMD_APU_IS_PICASSO;
		break;
	case CHIP_RENOIR:
		if ((adev->pdev->device == 0x1636) ||
		    (adev->pdev->device == 0x164c))
			adev->apu_flags |= AMD_APU_IS_RENOIR;
		else
			adev->apu_flags |= AMD_APU_IS_GREEN_SARDINE;
		break;
	case CHIP_VANGOGH:
		adev->apu_flags |= AMD_APU_IS_VANGOGH;
		break;
	case CHIP_YELLOW_CARP:
		break;
	case CHIP_CYAN_SKILLFISH:
		if ((adev->pdev->device == 0x13FE) ||
		    (adev->pdev->device == 0x143F))
			adev->apu_flags |= AMD_APU_IS_CYAN_SKILLFISH2;
		break;
	default:
		break;
	}

	return 0;
}


static const char *amdgpu_discovery_get_fw_name(struct amdgpu_device *adev)
{
	if (amdgpu_discovery == 2) {
		/* Assume there is valid discovery TMR in VRAM even if binary is sideloaded */
		adev->discovery.reserve_tmr = true;
		return "amdgpu/ip_discovery.bin";
	}

	switch (adev->asic_type) {
	case CHIP_VEGA10:
		return "amdgpu/vega10_ip_discovery.bin";
	case CHIP_VEGA12:
		return "amdgpu/vega12_ip_discovery.bin";
	case CHIP_RAVEN:
		if (adev->apu_flags & AMD_APU_IS_RAVEN2)
			return "amdgpu/raven2_ip_discovery.bin";
		else if (adev->apu_flags & AMD_APU_IS_PICASSO)
			return "amdgpu/picasso_ip_discovery.bin";
		else
			return "amdgpu/raven_ip_discovery.bin";
	case CHIP_VEGA20:
		return "amdgpu/vega20_ip_discovery.bin";
	case CHIP_ARCTURUS:
		return "amdgpu/arcturus_ip_discovery.bin";
	case CHIP_ALDEBARAN:
		return "amdgpu/aldebaran_ip_discovery.bin";
	default:
		return NULL;
	}
}


static inline const struct pci_device_id *
pci_match_one_device(const struct pci_device_id *id, const struct pci_dev *dev)
{
	if ((id->vendor == PCI_ANY_ID || id->vendor == dev->vendor) &&
	    (id->device == PCI_ANY_ID || id->device == dev->device) &&
	    (id->subvendor == PCI_ANY_ID || id->subvendor == dev->subsystem_vendor) &&
	    (id->subdevice == PCI_ANY_ID || id->subdevice == dev->subsystem_device) &&
	    !((id->class ^ dev->class) & id->class_mask))
		return id;
	return NULL;
}


const struct pci_device_id *pci_match_id(const struct pci_device_id *ids,
					 struct pci_dev *dev)
{
	if (ids) {
		while (ids->vendor || ids->subvendor || ids->class_mask) {
			if (pci_match_one_device(ids, dev))
				return ids;
			ids++;
		}
	}
	return NULL;
}


static int ref_probe(struct pci_dev *pdev, const struct pci_device_id *ent, unsigned long *flags_out)
{
	struct drm_device *ddev;
	struct amdgpu_device *adev;
	unsigned long flags = ent->driver_data;
	int ret, retry = 0, i;
	bool supports_atomic = false;

	if ((pdev->class >> 8) == PCI_CLASS_DISPLAY_VGA ||
	    (pdev->class >> 8) == PCI_CLASS_DISPLAY_OTHER) {
		if (drm_firmware_drivers_only() && amdgpu_modeset == -1)
			return -EINVAL;
	}

	/* skip devices which are owned by radeon */
	for (i = 0; i < ARRAY_SIZE(amdgpu_unsupported_pciidlist); i++) {
		if (amdgpu_unsupported_pciidlist[i] == pdev->device)
			return -ENODEV;
	}

	if (amdgpu_virtual_display ||
	    amdgpu_device_asic_has_dc_support(pdev, flags & AMD_ASIC_MASK))
		supports_atomic = true;

	if ((flags & AMD_EXP_HW_SUPPORT) && !amdgpu_exp_hw_support) {
		dev_info(&pdev->dev, "This hardware requires experimental hardware support.\n"
			 "See modparam exp_hw_support\n");
		return -ENODEV;
	}

	flags = amdgpu_fix_asic_type(pdev, flags);

	/* Due to hardware bugs, S/G Display on raven requires a 1:1 IOMMU mapping,
	 * however, SME requires an indirect IOMMU mapping because the encryption
	 * bit is beyond the DMA mask of the chip.
	 */
	if (cc_platform_has(CC_ATTR_MEM_ENCRYPT) &&
	    ((flags & AMD_ASIC_MASK) == CHIP_RAVEN)) {
		dev_info(&pdev->dev,
			 "SME is not compatible with RAVEN\n");
		return -ENOTSUPP;
	}

	if (!amdgpu_support_enabled(&pdev->dev, flags & AMD_ASIC_MASK))
		return -ENODEV;

	*flags_out = flags;
	return 0;
}

static int ref_initial_path(struct amdgpu_device *adev)
{
	int r;
	switch (adev->asic_type) {
#ifdef CONFIG_DRM_AMDGPU_SI
	case CHIP_VERDE:
	case CHIP_TAHITI:
	case CHIP_PITCAIRN:
	case CHIP_OLAND:
	case CHIP_HAINAN:
		adev->family = AMDGPU_FAMILY_SI;
		r = si_set_ip_blocks(adev);
		if (r)
			return r;
		break;
#endif
#ifdef CONFIG_DRM_AMDGPU_CIK
	case CHIP_BONAIRE:
	case CHIP_HAWAII:
	case CHIP_KAVERI:
	case CHIP_KABINI:
	case CHIP_MULLINS:
		if (adev->flags & AMD_IS_APU)
			adev->family = AMDGPU_FAMILY_KV;
		else
			adev->family = AMDGPU_FAMILY_CI;

		r = cik_set_ip_blocks(adev);
		if (r)
			return r;
		break;
#endif
	case CHIP_TOPAZ:
	case CHIP_TONGA:
	case CHIP_FIJI:
	case CHIP_POLARIS10:
	case CHIP_POLARIS11:
	case CHIP_POLARIS12:
	case CHIP_VEGAM:
	case CHIP_CARRIZO:
	case CHIP_STONEY:
		if (adev->flags & AMD_IS_APU)
			adev->family = AMDGPU_FAMILY_CZ;
		else
			adev->family = AMDGPU_FAMILY_VI;

		r = vi_set_ip_blocks(adev);
		if (r)
			return r;
		break;
	default:
		r = amdgpu_discovery_set_ip_blocks(adev);
		if (r) {
			adev->num_ip_blocks = 0;
			return r;
		}
		break;
	}

	return 0;
}

static int ref_discovery_path(struct amdgpu_device *adev)
{
	int r;
	switch (adev->asic_type) {
	case CHIP_VEGA10:
		/* This is not fatal.  We only need the discovery
		 * binary for sysfs.  We don't need it for a
		 * functional system.
		 */
		amdgpu_discovery_init(adev);
		vega10_reg_base_init(adev);
		adev->sdma.num_instances = 2;
		adev->sdma.sdma_mask = 3;
		adev->gmc.num_umc = 4;
		adev->gfx.xcc_mask = 1;
		adev->ip_versions[MMHUB_HWIP][0] = IP_VERSION(9, 0, 0);
		adev->ip_versions[ATHUB_HWIP][0] = IP_VERSION(9, 0, 0);
		adev->ip_versions[OSSSYS_HWIP][0] = IP_VERSION(4, 0, 0);
		adev->ip_versions[HDP_HWIP][0] = IP_VERSION(4, 0, 0);
		adev->ip_versions[SDMA0_HWIP][0] = IP_VERSION(4, 0, 0);
		adev->ip_versions[SDMA1_HWIP][0] = IP_VERSION(4, 0, 0);
		adev->ip_versions[DF_HWIP][0] = IP_VERSION(2, 1, 0);
		adev->ip_versions[NBIO_HWIP][0] = IP_VERSION(6, 1, 0);
		adev->ip_versions[UMC_HWIP][0] = IP_VERSION(6, 0, 0);
		adev->ip_versions[MP0_HWIP][0] = IP_VERSION(9, 0, 0);
		adev->ip_versions[MP1_HWIP][0] = IP_VERSION(9, 0, 0);
		adev->ip_versions[THM_HWIP][0] = IP_VERSION(9, 0, 0);
		adev->ip_versions[SMUIO_HWIP][0] = IP_VERSION(9, 0, 0);
		adev->ip_versions[GC_HWIP][0] = IP_VERSION(9, 0, 1);
		adev->ip_versions[UVD_HWIP][0] = IP_VERSION(7, 0, 0);
		adev->ip_versions[VCE_HWIP][0] = IP_VERSION(4, 0, 0);
		adev->ip_versions[DCI_HWIP][0] = IP_VERSION(12, 0, 0);
		break;
	case CHIP_VEGA12:
		/* This is not fatal.  We only need the discovery
		 * binary for sysfs.  We don't need it for a
		 * functional system.
		 */
		amdgpu_discovery_init(adev);
		vega10_reg_base_init(adev);
		adev->sdma.num_instances = 2;
		adev->sdma.sdma_mask = 3;
		adev->gmc.num_umc = 4;
		adev->gfx.xcc_mask = 1;
		adev->ip_versions[MMHUB_HWIP][0] = IP_VERSION(9, 3, 0);
		adev->ip_versions[ATHUB_HWIP][0] = IP_VERSION(9, 3, 0);
		adev->ip_versions[OSSSYS_HWIP][0] = IP_VERSION(4, 0, 1);
		adev->ip_versions[HDP_HWIP][0] = IP_VERSION(4, 0, 1);
		adev->ip_versions[SDMA0_HWIP][0] = IP_VERSION(4, 0, 1);
		adev->ip_versions[SDMA1_HWIP][0] = IP_VERSION(4, 0, 1);
		adev->ip_versions[DF_HWIP][0] = IP_VERSION(2, 5, 0);
		adev->ip_versions[NBIO_HWIP][0] = IP_VERSION(6, 2, 0);
		adev->ip_versions[UMC_HWIP][0] = IP_VERSION(6, 1, 0);
		adev->ip_versions[MP0_HWIP][0] = IP_VERSION(9, 0, 0);
		adev->ip_versions[MP1_HWIP][0] = IP_VERSION(9, 0, 0);
		adev->ip_versions[THM_HWIP][0] = IP_VERSION(9, 0, 0);
		adev->ip_versions[SMUIO_HWIP][0] = IP_VERSION(9, 0, 1);
		adev->ip_versions[GC_HWIP][0] = IP_VERSION(9, 2, 1);
		adev->ip_versions[UVD_HWIP][0] = IP_VERSION(7, 0, 0);
		adev->ip_versions[VCE_HWIP][0] = IP_VERSION(4, 0, 0);
		adev->ip_versions[DCI_HWIP][0] = IP_VERSION(12, 0, 1);
		break;
	case CHIP_RAVEN:
		/* This is not fatal.  We only need the discovery
		 * binary for sysfs.  We don't need it for a
		 * functional system.
		 */
		amdgpu_discovery_init(adev);
		vega10_reg_base_init(adev);
		adev->sdma.num_instances = 1;
		adev->sdma.sdma_mask = 1;
		adev->vcn.num_vcn_inst = 1;
		adev->gmc.num_umc = 2;
		adev->gfx.xcc_mask = 1;
		if (adev->apu_flags & AMD_APU_IS_RAVEN2) {
			adev->ip_versions[MMHUB_HWIP][0] = IP_VERSION(9, 2, 0);
			adev->ip_versions[ATHUB_HWIP][0] = IP_VERSION(9, 2, 0);
			adev->ip_versions[OSSSYS_HWIP][0] = IP_VERSION(4, 1, 1);
			adev->ip_versions[HDP_HWIP][0] = IP_VERSION(4, 1, 1);
			adev->ip_versions[SDMA0_HWIP][0] = IP_VERSION(4, 1, 1);
			adev->ip_versions[DF_HWIP][0] = IP_VERSION(2, 1, 1);
			adev->ip_versions[NBIO_HWIP][0] = IP_VERSION(7, 0, 1);
			adev->ip_versions[UMC_HWIP][0] = IP_VERSION(7, 5, 0);
			adev->ip_versions[MP0_HWIP][0] = IP_VERSION(10, 0, 1);
			adev->ip_versions[MP1_HWIP][0] = IP_VERSION(10, 0, 1);
			adev->ip_versions[THM_HWIP][0] = IP_VERSION(10, 1, 0);
			adev->ip_versions[SMUIO_HWIP][0] = IP_VERSION(10, 0, 1);
			adev->ip_versions[GC_HWIP][0] = IP_VERSION(9, 2, 2);
			adev->ip_versions[UVD_HWIP][0] = IP_VERSION(1, 0, 1);
			adev->ip_versions[DCE_HWIP][0] = IP_VERSION(1, 0, 1);
			adev->ip_versions[ISP_HWIP][0] = IP_VERSION(2, 0, 0);
		} else {
			adev->ip_versions[MMHUB_HWIP][0] = IP_VERSION(9, 1, 0);
			adev->ip_versions[ATHUB_HWIP][0] = IP_VERSION(9, 1, 0);
			adev->ip_versions[OSSSYS_HWIP][0] = IP_VERSION(4, 1, 0);
			adev->ip_versions[HDP_HWIP][0] = IP_VERSION(4, 1, 0);
			adev->ip_versions[SDMA0_HWIP][0] = IP_VERSION(4, 1, 0);
			adev->ip_versions[DF_HWIP][0] = IP_VERSION(2, 1, 0);
			adev->ip_versions[NBIO_HWIP][0] = IP_VERSION(7, 0, 0);
			adev->ip_versions[UMC_HWIP][0] = IP_VERSION(7, 0, 0);
			adev->ip_versions[MP0_HWIP][0] = IP_VERSION(10, 0, 0);
			adev->ip_versions[MP1_HWIP][0] = IP_VERSION(10, 0, 0);
			adev->ip_versions[THM_HWIP][0] = IP_VERSION(10, 0, 0);
			adev->ip_versions[SMUIO_HWIP][0] = IP_VERSION(10, 0, 0);
			adev->ip_versions[GC_HWIP][0] = IP_VERSION(9, 1, 0);
			adev->ip_versions[UVD_HWIP][0] = IP_VERSION(1, 0, 0);
			adev->ip_versions[DCE_HWIP][0] = IP_VERSION(1, 0, 0);
			adev->ip_versions[ISP_HWIP][0] = IP_VERSION(2, 0, 0);
		}
		break;
	case CHIP_VEGA20:
		/* This is not fatal.  We only need the discovery
		 * binary for sysfs.  We don't need it for a
		 * functional system.
		 */
		amdgpu_discovery_init(adev);
		vega20_reg_base_init(adev);
		adev->sdma.num_instances = 2;
		adev->sdma.sdma_mask = 3;
		adev->gmc.num_umc = 8;
		adev->gfx.xcc_mask = 1;
		adev->ip_versions[MMHUB_HWIP][0] = IP_VERSION(9, 4, 0);
		adev->ip_versions[ATHUB_HWIP][0] = IP_VERSION(9, 4, 0);
		adev->ip_versions[OSSSYS_HWIP][0] = IP_VERSION(4, 2, 0);
		adev->ip_versions[HDP_HWIP][0] = IP_VERSION(4, 2, 0);
		adev->ip_versions[SDMA0_HWIP][0] = IP_VERSION(4, 2, 0);
		adev->ip_versions[SDMA1_HWIP][0] = IP_VERSION(4, 2, 0);
		adev->ip_versions[DF_HWIP][0] = IP_VERSION(3, 6, 0);
		adev->ip_versions[NBIO_HWIP][0] = IP_VERSION(7, 4, 0);
		adev->ip_versions[UMC_HWIP][0] = IP_VERSION(6, 1, 1);
		adev->ip_versions[MP0_HWIP][0] = IP_VERSION(11, 0, 2);
		adev->ip_versions[MP1_HWIP][0] = IP_VERSION(11, 0, 2);
		adev->ip_versions[THM_HWIP][0] = IP_VERSION(11, 0, 2);
		adev->ip_versions[SMUIO_HWIP][0] = IP_VERSION(11, 0, 2);
		adev->ip_versions[GC_HWIP][0] = IP_VERSION(9, 4, 0);
		adev->ip_versions[UVD_HWIP][0] = IP_VERSION(7, 2, 0);
		adev->ip_versions[UVD_HWIP][1] = IP_VERSION(7, 2, 0);
		adev->ip_versions[VCE_HWIP][0] = IP_VERSION(4, 1, 0);
		adev->ip_versions[DCI_HWIP][0] = IP_VERSION(12, 1, 0);
		break;
	case CHIP_ARCTURUS:
		/* This is not fatal.  We only need the discovery
		 * binary for sysfs.  We don't need it for a
		 * functional system.
		 */
		amdgpu_discovery_init(adev);
		arct_reg_base_init(adev);
		adev->sdma.num_instances = 8;
		adev->sdma.sdma_mask = 0xff;
		adev->vcn.num_vcn_inst = 2;
		adev->gmc.num_umc = 8;
		adev->gfx.xcc_mask = 1;
		adev->ip_versions[MMHUB_HWIP][0] = IP_VERSION(9, 4, 1);
		adev->ip_versions[ATHUB_HWIP][0] = IP_VERSION(9, 4, 1);
		adev->ip_versions[OSSSYS_HWIP][0] = IP_VERSION(4, 2, 1);
		adev->ip_versions[HDP_HWIP][0] = IP_VERSION(4, 2, 1);
		adev->ip_versions[SDMA0_HWIP][0] = IP_VERSION(4, 2, 2);
		adev->ip_versions[SDMA1_HWIP][0] = IP_VERSION(4, 2, 2);
		adev->ip_versions[SDMA1_HWIP][1] = IP_VERSION(4, 2, 2);
		adev->ip_versions[SDMA1_HWIP][2] = IP_VERSION(4, 2, 2);
		adev->ip_versions[SDMA1_HWIP][3] = IP_VERSION(4, 2, 2);
		adev->ip_versions[SDMA1_HWIP][4] = IP_VERSION(4, 2, 2);
		adev->ip_versions[SDMA1_HWIP][5] = IP_VERSION(4, 2, 2);
		adev->ip_versions[SDMA1_HWIP][6] = IP_VERSION(4, 2, 2);
		adev->ip_versions[DF_HWIP][0] = IP_VERSION(3, 6, 1);
		adev->ip_versions[NBIO_HWIP][0] = IP_VERSION(7, 4, 1);
		adev->ip_versions[UMC_HWIP][0] = IP_VERSION(6, 1, 2);
		adev->ip_versions[MP0_HWIP][0] = IP_VERSION(11, 0, 4);
		adev->ip_versions[MP1_HWIP][0] = IP_VERSION(11, 0, 2);
		adev->ip_versions[THM_HWIP][0] = IP_VERSION(11, 0, 3);
		adev->ip_versions[SMUIO_HWIP][0] = IP_VERSION(11, 0, 3);
		adev->ip_versions[GC_HWIP][0] = IP_VERSION(9, 4, 1);
		adev->ip_versions[UVD_HWIP][0] = IP_VERSION(2, 5, 0);
		adev->ip_versions[UVD_HWIP][1] = IP_VERSION(2, 5, 0);
		break;
	case CHIP_ALDEBARAN:
		/* This is not fatal.  We only need the discovery
		 * binary for sysfs.  We don't need it for a
		 * functional system.
		 */
		amdgpu_discovery_init(adev);
		aldebaran_reg_base_init(adev);
		adev->sdma.num_instances = 5;
		adev->sdma.sdma_mask = 0x1f;
		adev->vcn.num_vcn_inst = 2;
		adev->gmc.num_umc = 4;
		adev->gfx.xcc_mask = 1;
		adev->ip_versions[MMHUB_HWIP][0] = IP_VERSION(9, 4, 2);
		adev->ip_versions[ATHUB_HWIP][0] = IP_VERSION(9, 4, 2);
		adev->ip_versions[OSSSYS_HWIP][0] = IP_VERSION(4, 4, 0);
		adev->ip_versions[HDP_HWIP][0] = IP_VERSION(4, 4, 0);
		adev->ip_versions[SDMA0_HWIP][0] = IP_VERSION(4, 4, 0);
		adev->ip_versions[SDMA0_HWIP][1] = IP_VERSION(4, 4, 0);
		adev->ip_versions[SDMA0_HWIP][2] = IP_VERSION(4, 4, 0);
		adev->ip_versions[SDMA0_HWIP][3] = IP_VERSION(4, 4, 0);
		adev->ip_versions[SDMA0_HWIP][4] = IP_VERSION(4, 4, 0);
		adev->ip_versions[DF_HWIP][0] = IP_VERSION(3, 6, 2);
		adev->ip_versions[NBIO_HWIP][0] = IP_VERSION(7, 4, 4);
		adev->ip_versions[UMC_HWIP][0] = IP_VERSION(6, 7, 0);
		adev->ip_versions[MP0_HWIP][0] = IP_VERSION(13, 0, 2);
		adev->ip_versions[MP1_HWIP][0] = IP_VERSION(13, 0, 2);
		adev->ip_versions[THM_HWIP][0] = IP_VERSION(13, 0, 2);
		adev->ip_versions[SMUIO_HWIP][0] = IP_VERSION(13, 0, 2);
		adev->ip_versions[GC_HWIP][0] = IP_VERSION(9, 4, 2);
		adev->ip_versions[UVD_HWIP][0] = IP_VERSION(2, 6, 0);
		adev->ip_versions[UVD_HWIP][1] = IP_VERSION(2, 6, 0);
		adev->ip_versions[XGMI_HWIP][0] = IP_VERSION(6, 1, 0);
		break;
	case CHIP_CYAN_SKILLFISH:
		if (adev->apu_flags & AMD_APU_IS_CYAN_SKILLFISH2) {
			r = amdgpu_discovery_reg_base_init(adev);
			if (r)
				return -EINVAL;

			amdgpu_discovery_harvest_ip(adev);
			amdgpu_discovery_get_gfx_info(adev);
			amdgpu_discovery_get_mall_info(adev);
			amdgpu_discovery_get_vcn_info(adev);
		} else {
			cyan_skillfish_reg_base_init(adev);
			adev->sdma.num_instances = 2;
			adev->sdma.sdma_mask = 3;
			adev->gfx.xcc_mask = 1;
			adev->ip_versions[MMHUB_HWIP][0] = IP_VERSION(2, 0, 3);
			adev->ip_versions[ATHUB_HWIP][0] = IP_VERSION(2, 0, 3);
			adev->ip_versions[OSSSYS_HWIP][0] = IP_VERSION(5, 0, 1);
			adev->ip_versions[HDP_HWIP][0] = IP_VERSION(5, 0, 1);
			adev->ip_versions[SDMA0_HWIP][0] = IP_VERSION(5, 0, 1);
			adev->ip_versions[SDMA1_HWIP][1] = IP_VERSION(5, 0, 1);
			adev->ip_versions[DF_HWIP][0] = IP_VERSION(3, 5, 0);
			adev->ip_versions[NBIO_HWIP][0] = IP_VERSION(2, 1, 1);
			adev->ip_versions[UMC_HWIP][0] = IP_VERSION(8, 1, 1);
			adev->ip_versions[MP0_HWIP][0] = IP_VERSION(11, 0, 8);
			adev->ip_versions[MP1_HWIP][0] = IP_VERSION(11, 0, 8);
			adev->ip_versions[THM_HWIP][0] = IP_VERSION(11, 0, 1);
			adev->ip_versions[SMUIO_HWIP][0] = IP_VERSION(11, 0, 8);
			adev->ip_versions[GC_HWIP][0] = IP_VERSION(10, 1, 3);
			adev->ip_versions[UVD_HWIP][0] = IP_VERSION(2, 0, 3);
		}
		break;
	default:
		r = amdgpu_discovery_reg_base_init(adev);
		if (r) {
			drm_err(&adev->ddev, "discovery failed: %d\n", r);
			return r;
		}

		amdgpu_discovery_harvest_ip(adev);
		amdgpu_discovery_get_gfx_info(adev);
		amdgpu_discovery_get_mall_info(adev);
		amdgpu_discovery_get_vcn_info(adev);
		break;
	}

	return 0;
}

#undef amdgpu_unsupported_pciidlist
#undef pciidlist
#undef asic_type_quirks
#undef amdgpu_fix_asic_type
#undef amdgpu_support_enabled
#undef amdgpu_device_init_apu_flags
#undef amdgpu_discovery_get_fw_name
#undef pci_match_one_device
#undef pci_match_id