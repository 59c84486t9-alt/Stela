/* SPDX-License-Identifier: MIT */
/* Compile as C11 and C++11 with the real NVKMS header for each native/host
 * ABI. These constants freeze the device byte layout and the declared CPU
 * alignment. This fixture supplies no platform services.
 */
#include "nvkms-types.h"

#ifdef __cplusplus
extern "C" {
extern const NvU64 stela_nvkms_lut_layout[];
extern const char *const stela_nvkms_lut_layout_labels[];
extern const NvU64 stela_nvkms_lut_layout_count;
#endif

#define STELA_LUT_LAYOUT(M) \
    M("sizeof(NVEvoLutEntryRec)", sizeof(NVEvoLutEntryRec)) \
    M("alignof(NVEvoLutEntryRec)", NV_ALIGNOF(NVEvoLutEntryRec)) \
    M("sizeof(NVEvoLutDataRec)", sizeof(NVEvoLutDataRec)) \
    M("alignof(NVEvoLutDataRec)", NV_ALIGNOF(NVEvoLutDataRec)) \
    M("offsetof(base)", offsetof(NVEvoLutDataRec, base)) \
    M("offsetof(output)", offsetof(NVEvoLutDataRec, output)) \
    M("sizeof(base)", sizeof(((NVEvoLutDataRec *)0)->base)) \
    M("sizeof(output)", sizeof(((NVEvoLutDataRec *)0)->output))

#define STELA_LUT_VALUE(label, value) (NvU64)(value),
const NvU64 stela_nvkms_lut_layout[] = { STELA_LUT_LAYOUT(STELA_LUT_VALUE) };
#undef STELA_LUT_VALUE
#define STELA_LUT_LABEL(label, value) label,
const char *const stela_nvkms_lut_layout_labels[] = { STELA_LUT_LAYOUT(STELA_LUT_LABEL) };
#undef STELA_LUT_LABEL
const NvU64 stela_nvkms_lut_layout_count =
    sizeof(stela_nvkms_lut_layout) / sizeof(stela_nvkms_lut_layout[0]);

ct_assert(sizeof(NVEvoLutDataRec) == 16896);
ct_assert(offsetof(NVEvoLutDataRec, base) == 0);
ct_assert(offsetof(NVEvoLutDataRec, output) == 8448);
ct_assert(sizeof(((NVEvoLutDataRec *)0)->base) == 8232);
ct_assert(sizeof(((NVEvoLutDataRec *)0)->output) == 8232);
ct_assert(NV_ALIGNOF(NVEvoLutDataRec) == 256);

void stela_nvkms_lut_first_entry_store(NVEvoLutDataRec *p, NvU16 value);
void stela_nvkms_lut_first_entry_store(NVEvoLutDataRec *p, NvU16 value)
{
    p->output[0].Red = value;
}

#ifdef __cplusplus
}
#endif
