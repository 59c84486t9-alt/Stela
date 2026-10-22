/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_ACTIVATION_H
#define STELA_INTEL_ACTIVATION_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Native PF-only probe. All callbacks are mandatory real owner operations.
 * prepare holds actual PCI D0/bridge/reset/exclusive/no-IRQ/no-DMA ownership,
 * applies required original WA and PCODE/lmem readiness, and qualifies MMIO
 * ordering and the monotonic nanosecond clock/sleep context. It may refuse;
 * it is not a boolean substitute for those effects. Retain that owner and the
 * canonical UC Mapping/View until explicit acknowledged retirement. No guest
 * pointers or hardware activation occur merely by constructing this table.
 * read/write access only bounded canonical UC CPU mappings, actual width32;
 * writes order all required preceding accesses, reads honor original WA read
 * flushing. delay preserves atomic vs sleepable context, never substitutes a
 * 3-minute spin for a sleepable PCODE wait. invariant must fail-stop on false.
 * now_ns is nonnegative, monotonic, and cannot approach INT64_MAX during the
 * largest 100ms wait. All public calls require one real exclusive probe owner.
 */
struct stela_intel_activation_io {
    int (*check_context)(void *);
    int (*prepare)(void *, uint32_t platform, uint32_t pci_revision, bool discrete);
    uint32_t (*read32)(void *, uint32_t offset);
    void (*write32)(void *, uint32_t offset, uint32_t value);
    int64_t (*now_ns)(void *);
    void (*delay_us)(void *, uint32_t minimum, uint32_t maximum, bool atomic);
    void (*invariant)(void *, bool);
    void (*report)(void *, uint32_t domain_mask, bool wake, int status, uint32_t value);
};

struct stela_intel_activation_facts {
    uint32_t platform, subplatform, graphics_verx100, media_verx100;
    uint32_t graphics_revision, media_revision, pci_revision, tile_count;
    uint32_t dma_bits, va_bits, max_gt_per_tile, discrete;
    uint32_t force_probe_required, gt_control, gt_ack, initialized, awake;
    uint32_t has_llc, gt_type;
};
_Static_assert(sizeof(struct stela_intel_activation_facts) == 76, "device facts ABI");
_Static_assert(offsetof(struct stela_intel_activation_facts, has_llc) == 68, "LLC ABI");
_Static_assert(offsetof(struct stela_intel_activation_facts, gt_type) == 72, "GT role ABI");
struct stela_intel_activation;

size_t stela_intel_activation_size(void);
size_t stela_intel_activation_alignment(void);
/* Pure original PCI-table/force-probe selection, before claiming/mapping BARs.
 * A match is not device readiness, discovery of runtime facts or Metal support. */
int stela_intel_activation_match(uint32_t vendor, uint32_t device, uint32_t pci_class,
                                 bool vf, bool force_probe);
/* Caller supplies owned, aligned host object storage. Outputs unchanged on
 * error. bar_bytes is the entire actual reserved BAR0, never a guessed span.
 * pci_class is the actual 24bit class tuple. VF always refuses. force_probe
 * must be an explicit driver policy decision, never inferred from a match.
 * Errors -22 invalid, -19 no match/unreliable MMIO, -95 unsupported, -110 ACK.
 */
int stela_intel_activation_init(void *storage, size_t bytes,
    const struct stela_intel_activation_io *, void *context, uint32_t vendor,
    uint32_t device, uint32_t pci_class, uint32_t revision, uint64_t bar_bytes,
    bool vf, bool force_probe);
int stela_intel_activation_facts(const struct stela_intel_activation *,
                                struct stela_intel_activation_facts *);
int stela_intel_activation_wake(struct stela_intel_activation *);
/* Acknowledged sleep is required before releasing the power/mapping owner.
 * Original sleep failure retains awake bits with ref0; failure remains a real
 * non-retirable state until separately qualified recovery, never fake success.
 */
int stela_intel_activation_sleep(struct stela_intel_activation *);
#endif
