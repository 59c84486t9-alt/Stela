/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_DISCOVERY_TMR_H
#define STELA_AMD_DISCOVERY_TMR_H
#include <stdint.h>
#include <stddef.h>
struct stela_amd_discovery_tmr {
 uint64_t offset, vram_bytes;
 uint32_t size, reserved;
};
enum stela_amd_discovery_tmr_status {
 STELA_AMD_TMR_OK = 0,
 STELA_AMD_TMR_INVALID = 1,
 STELA_AMD_TMR_BOUNDS = 2,
 STELA_AMD_TMR_VF_OWNER_UNAVAILABLE = 3,
 STELA_AMD_TMR_SYSTEM_OWNER_UNAVAILABLE = 4,
};
/* Borrow the same actual canonical UC register mapping, matched original ASIC,
 * D0/reset/removal/MM-index/IRQ exclusion and process context as vram_mm.h.
 * The original discovery caller must have selected this bootstrap path; no
 * SI/CIK/VI admission or preferred-file policy is inferred here. sleep_ms is
 * mandatory real elapsed-time service, not an immediate/success callback.
 * Actual direct register/owner/service bounds are checked before first I/O.
 * Output unchanged on every error. Negative values are original errno status.
 * A successful region is GPU VRAM, never a system physical/DMA/IOVA address.
 * It is not a reservation, BO, firmware integrity or readiness proof.
 * Real system-memory/VF owners are unavailable here and explicitly refused.
 * After original reads/index writes there is no rollback; returned void reads
 * carry no transport ACK. No pointer is retained. Output is exclusive CPU RAM,
 * distinct from the register span, and all callbacks retain the same owner.
 */
int stela_amd_discovery_tmr_query(void *registers, size_t register_bytes,
 uint32_t asic_type, void *sleep_context,
 void (*sleep_ms)(void *, unsigned), struct stela_amd_discovery_tmr *out);
#endif
