/* SPDX-License-Identifier: MIT */
#ifndef STELA_NVIDIA_FIRMWARE_H
#define STELA_NVIDIA_FIRMWARE_H

#include "stela_services.h"

/* Native same-CPU ABI, borrowing immutable canonical catalog bytes. The pinned
 * MemoryServices owner supplies the actual device's observed architecture and
 * implementation before binding. All calls/releases are serialized, nonreentrant
 * process/deferred operations with a live global heap, never ISR callbacks.
 * Every non-NULL token is returned once after CPU readers stop. The catalog,
 * provider, state and service remain alive until all tokens are put and unbind
 * succeeds. NULL put is valid. Failure preserves both caller output slots.
 * Bytes are CPU-only: not physical/IOVA addresses, pinned DMA storage or GPU VA.
 * Catalog manifest integrity does not authenticate NVIDIA firmware. Original RM
 * version/ELF/signature validation, upload and device initialization still apply.
 */
NvU32 stela_nvidia_firmware_family(NvU32 architecture, NvU32 implementation);
NvU64 stela_nvidia_firmware_alignment(void);
const char *stela_nvidia_firmware_version(void);
const void *stela_nvidia_get_firmware(void *services, void *state, NvU32 family,
                                    const char *name, const char *hardware,
                                    const char *revision, const void **buffer,
                                    NvU32 *bytes);
void stela_nvidia_put_firmware(const void *token);

#endif
