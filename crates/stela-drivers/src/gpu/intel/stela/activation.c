/* SPDX-License-Identifier: MIT */
/* Owned native integration; original Xe notices remain in shared headers. */
#include "activation.h"
#include "wopcm.h"
#include "pat.h"
#include "guc_reset.h"
#include "xe_gt_type.h"
#include <linux/types.h>
#include "xe_pci_types.h"
#include "xe_engine_ids.h"
#include "regs/xe_gt_regs.h"
#include "regs/xe_regs.h"
#include "xe_force_wake_domain_types.h"

/* Port only scalar/diagnostic spelling. There is no kernel service shim. */
#include <linux/array_size.h>
#define __maybe_unused __attribute__((unused))
#define __diag_push()
#define __diag_pop()
#define __diag_ignore_all(a, b)
#define for_each_if(condition) if (!(condition)) {} else
#define ffs(value) __builtin_ffs((int)(value))
#define EIO 5
#ifdef ETIMEDOUT
#undef ETIMEDOUT
#endif
#define ETIMEDOUT 110
#include "xe_force_wake_core.h"
#include "xe_force_wake_gt.h"

/* Same entire original ID/descriptor block, including class filters/order.
 * This is a native table row, not a fabricated Linux pci_dev/device object. */
struct stela_intel_pci_match {
    uint32_t vendor, device, class, class_mask;
    const struct xe_device_desc *driver_data;
};
#define XE_PCI_ID_TYPE struct stela_intel_pci_match
#define INTEL_PCI_DEVICE(id, info) {.vendor = 0x8086, .device = (id), .driver_data = (info)}
#define INTEL_VGA_DEVICE(id, info) {.vendor = 0x8086, .device = (id), .class = 0x030000, \
                                   .class_mask = 0xff0000, .driver_data = (info)}
#include <drm/intel/pciids.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winitializer-overrides"
#include "xe_pci_device_info.h"
#pragma clang diagnostic ignored "-Wsign-compare"
#include "xe_pci_runtime.h"
#pragma clang diagnostic pop

struct stela_intel_activation {
    const struct stela_intel_activation_io *io;
    void *context;
    uint64_t bar_bytes;
    struct stela_intel_activation_facts facts;
    struct xe_force_wake_domain domains[XE_FW_DOMAIN_ID_COUNT];
    int wait_error;
    bool poisoned;
    bool wopcm_uncertain;
    bool wopcm_prepared;
    bool pat_sequence_issued;
    bool guc_reset_issued, guc_reset_uncertain;
};

size_t stela_intel_activation_size(void) { return sizeof(struct stela_intel_activation); }
size_t stela_intel_activation_alignment(void) { return _Alignof(struct stela_intel_activation); }

static bool valid_io(const struct stela_intel_activation_io *io)
{
    return io && io->check_context && io->prepare && io->read32 && io->write32 && io->now_ns && io->delay_us &&
           io->invariant && io->report;
}
static int descriptor(uint32_t vendor, uint32_t device, uint32_t pci_class,
                       bool vf, bool force_probe, const struct xe_device_desc **out)
{
    if (vendor > UINT16_MAX || device > UINT16_MAX || pci_class > 0xffffff) return -22;
    if (vf) return -95;
    for (size_t i = 0; i < ARRAY_SIZE(pciidlist); ++i) {
        const struct stela_intel_pci_match *row = &pciidlist[i];
        if (!row->driver_data) break; /* Original PCI table terminator. */
        if (row->vendor == vendor && row->device == device &&
            !((row->class ^ pci_class) & row->class_mask)) {
            if (row->driver_data->require_force_probe && !force_probe) return -95;
            *out = row->driver_data;
            return 0;
        }
    }
    return -19;
}
int stela_intel_activation_match(uint32_t vendor, uint32_t device, uint32_t pci_class,
                                 bool vf, bool force_probe)
{
    const struct xe_device_desc *matched;
    return descriptor(vendor, device, pci_class, vf, force_probe, &matched);
}

static uint32_t read32(struct stela_intel_activation *state, struct xe_reg reg)
{
    state->io->invariant(state->context, !(reg.addr & 3) && (uint64_t)reg.addr + 4 <= SZ_4M);
    return state->io->read32(state->context, reg.addr);
}

static int64_t add_us(int64_t time, int64_t us) { return time + us * 1000; }
#define XE_MMIO_POLL_NAME poll32
#define XE_MMIO_POLL_CONTEXT struct stela_intel_activation
#define XE_MMIO_POLL_TIME int64_t
#define XE_MMIO_POLL_NOW(mmio) ((mmio)->io->now_ns((mmio)->context))
#define XE_MMIO_POLL_ADD_US add_us
#define XE_MMIO_POLL_READ read32
#define XE_MMIO_POLL_BEFORE(a, b) ((a) < (b))
#define XE_MMIO_POLL_AFTER(a, b) ((a) > (b))
#define XE_MMIO_POLL_DELTA_US(a, b) (((a) - (b)) / 1000)
#define XE_MMIO_POLL_DELAY(mmio, wait, atomic) \
    (mmio)->io->delay_us((mmio)->context, (uint32_t)(wait), \
                         (uint32_t)((atomic) ? (wait) : ((wait) << 1)), (atomic))
#include "xe_mmio_poll.h"

int stela_intel_activation_init(void *storage, size_t bytes,
    const struct stela_intel_activation_io *io, void *context, uint32_t vendor,
    uint32_t device, uint32_t pci_class, uint32_t revision, uint64_t bar_bytes,
    bool vf, bool force_probe)
{
    if (!storage || bytes < sizeof(struct stela_intel_activation) ||
        (uintptr_t)storage % _Alignof(struct stela_intel_activation) || !valid_io(io) ||
        vendor > UINT16_MAX || device > UINT16_MAX || pci_class > 0xffffff || revision > UINT8_MAX)
        return -22;
    const struct xe_device_desc *desc = NULL;
    int ret = descriptor(vendor, device, pci_class, vf, force_probe, &desc);
    if (ret) return ret;
    if (bar_bytes < 16 * 1024 * 1024) return -22;
    ret = io->check_context(context);
    if (ret) return ret;
    ret = io->prepare(context, (uint32_t)desc->platform, revision, desc->is_dgfx);
    if (ret) return ret;
    int64_t time = io->now_ns(context);
    if (time < 0 || time > INT64_MAX - INT64_C(100000000)) return -22;
    struct stela_intel_activation candidate = {.io = io, .context = context, .bar_bytes = bar_bytes};
    const struct xe_ip *graphics = desc->pre_gmdid_graphics_ip, *media = desc->pre_gmdid_media_ip;
    uint32_t graphics_revision = revision, media_revision = revision;
    if (!graphics) {
        uint32_t version, value = read32(&candidate, xe_pci_gmdid_register(false));
        if (value == UINT32_MAX) return -19;
        xe_pci_decode_gmdid(value, &version, &graphics_revision);
        graphics = find_graphics_ip(version);
        if (!graphics) return -95;
        value = read32(&candidate, xe_pci_gmdid_register(true));
        if (value == UINT32_MAX) return -19;
        xe_pci_decode_gmdid(value, &version, &media_revision);
        media = version ? find_media_ip(version) : NULL;
        if (version && !media) return -95;
    }
    uint8_t tiles = (uint8_t)(1 + desc->max_remote_tiles);
    if (tiles > 1) {
        uint32_t value = read32(&candidate, XEHP_MTCFG_ADDR);
        if (value == UINT32_MAX) return -19;
        tiles = xe_pci_runtime_tile_count(tiles, value);
        if (!tiles) return -19;
    }
    if ((uint64_t)tiles * 16 * 1024 * 1024 > bar_bytes) return -22;
    const struct xe_subplatform_desc *sub = find_subplatform(desc, (u16)device);
    candidate.facts = (struct stela_intel_activation_facts){
        .platform = (uint32_t)desc->platform,
        .subplatform = sub ? (uint32_t)sub->subplatform : XE_SUBPLATFORM_NONE,
        .graphics_verx100 = graphics->verx100, .media_verx100 = media ? media->verx100 : 0,
        .graphics_revision = graphics_revision, .media_revision = media_revision,
        .pci_revision = revision, .tile_count = tiles, .dma_bits = desc->dma_mask_size,
        .va_bits = desc->va_bits, .max_gt_per_tile = desc->max_gt_per_tile,
        .discrete = desc->is_dgfx, .force_probe_required = desc->require_force_probe,
        .gt_control = FORCEWAKE_GT.addr, .gt_ack = xe_force_wake_gt_ack(graphics->verx100).addr,
        .initialized = (uint32_t)XE_FW_GT,
        .has_llc = desc->has_llc,
        /* Same root-primary construction as original alloc_primary_gt; media
         * IP discovery does not construct a separate media GT in this API. */
        .gt_type = XE_GT_TYPE_MAIN,
    };
    xe_force_wake_domain_init(&candidate.domains[XE_FW_DOMAIN_ID_GT], XE_FW_DOMAIN_ID_GT,
                              FORCEWAKE_GT, xe_force_wake_gt_ack(graphics->verx100));
    *(struct stela_intel_activation *)storage = candidate;
    return 0;
}

int stela_intel_activation_facts(const struct stela_intel_activation *state,
                                struct stela_intel_activation_facts *facts)
{
    if (!state || !facts || !valid_io(state->io)) return -22;
    if (state->wopcm_uncertain || state->guc_reset_uncertain) return -5;
    int context_status = state->io->check_context(state->context);
    if (context_status) return context_status;
    *facts = state->facts;
    return 0;
}

static void control(void *context, struct xe_force_wake_domain *domain, bool wake)
{
    struct stela_intel_activation *state = context;
    state->io->write32(state->context, domain->reg_ctl.addr, xe_force_wake_control(domain, wake));
}
static int wait(void *context, struct xe_force_wake_domain *domain, bool wake)
{
    struct stela_intel_activation *state = context;
    uint32_t value;
    int status = poll32(state, domain->reg_ack, domain->val, wake ? domain->val : 0,
                        XE_FORCE_WAKE_ACK_TIMEOUT_MS * 1000, &value, true, true);
    status = xe_force_wake_wait_status(status, value);
    state->io->report(state->context, (uint32_t)XE_FW_GT, wake, status, value);
    if (status) state->wait_error = status;
    return status;
}
static void invariant(void *context, bool condition)
{
    struct stela_intel_activation *state = context;
    state->io->invariant(state->context, condition);
}
static struct xe_force_wake_core core(struct stela_intel_activation *state)
{
    static const struct xe_force_wake_core_ops ops = {control, wait, invariant};
    return (struct xe_force_wake_core){state, &ops, state->facts.initialized,
                                      &state->facts.awake, state->domains};
}
int stela_intel_activation_wake(struct stela_intel_activation *state)
{
    if (!state || !valid_io(state->io)) return -22;
    int context_status = state->io->check_context(state->context);
    if (context_status) return context_status;
    if (state->poisoned) return -5;
    if (state->domains[XE_FW_DOMAIN_ID_GT].ref == UINT32_MAX) return -22;
    struct xe_force_wake_core fw = core(state);
    unsigned failed;
    state->wait_error = 0;
    unsigned ref = xe_force_wake_get_locked(&fw, (unsigned)XE_FW_GT, &failed);
    if (failed || !ref) { state->poisoned = true; return state->wait_error ? state->wait_error : -110; }
    return 0;
}
int stela_intel_activation_sleep(struct stela_intel_activation *state)
{
    if (!state || !valid_io(state->io)) return -22;
    int context_status = state->io->check_context(state->context);
    if (context_status) return context_status;
    if (state->poisoned) return -5;
    if (!state->domains[XE_FW_DOMAIN_ID_GT].ref) return -22;
    struct xe_force_wake_core fw = core(state);
    state->wait_error = 0;
    if (xe_force_wake_put_locked(&fw, (unsigned)XE_FW_GT)) {
        state->poisoned = true; return state->wait_error ? state->wait_error : -110;
    }
    return 0;
}

void stela_intel_activation_assert_gt(struct stela_intel_activation *state)
{
    state->io->invariant(state->context,
        !state->poisoned && !state->wopcm_uncertain &&
        state->domains[XE_FW_DOMAIN_ID_GT].ref > 0 &&
        (state->facts.awake & (uint32_t)XE_FW_GT) != 0);
}
int stela_intel_activation_wopcm(struct stela_intel_activation *state,
    const uint8_t *bytes, size_t size, struct stela_intel_wopcm_result *out)
{
    if (!out) return -22;
    *out = (struct stela_intel_wopcm_result){0};
    if (!state || !valid_io(state->io)) return -22;
    if (state->poisoned || state->wopcm_uncertain) return -5;
    if (state->wopcm_prepared) return -114;
    if (!state->domains[XE_FW_DOMAIN_ID_GT].ref ||
        !(state->facts.awake & (uint32_t)XE_FW_GT)) return -22;
    int status = state->io->check_context(state->context);
    if (status) return status;
    status = stela_intel_wopcm_prepare(state->io, state->context, state,
        state->facts.platform, state->facts.graphics_verx100, state->facts.discrete != 0,
        bytes, size, out);
    if (status && out->writes) {
        /* Writes can have partially locked the hardware. There is no rollback,
         * sleep/drain/reset release or future access in this native epoch. */
        state->wopcm_uncertain = true;
        state->poisoned = true;
    }
    if (!status) state->wopcm_prepared = true;
    return status;
}

int stela_intel_activation_pat(struct stela_intel_activation *state,
                              struct stela_intel_pat_result *out)
{
    if (!state || !out || !valid_io(state->io)) return -22;
    if (state->poisoned || state->wopcm_uncertain) return -5;
    if (state->pat_sequence_issued || state->wopcm_prepared) return -114;
    if (!state->domains[XE_FW_DOMAIN_ID_GT].ref ||
        !(state->facts.awake & (uint32_t)XE_FW_GT)) return -22;
    int status = state->io->check_context(state->context);
    if (status) return status;
    status = stela_intel_pat_program(state->io, state->context, &state->facts, out);
    if (!status) state->pat_sequence_issued = true; /* Issued, never an ACK. */
    return status;
}

int stela_intel_activation_guc_reset(struct stela_intel_activation *state,
                                    struct stela_intel_guc_reset_result *out)
{
    if (!state || !out || !valid_io(state->io)) return -22;
    if (state->poisoned || state->wopcm_uncertain || state->guc_reset_uncertain) return -5;
    if (state->guc_reset_issued) return -114;
    if (!state->domains[XE_FW_DOMAIN_ID_GT].ref ||
        !(state->facts.awake & (uint32_t)XE_FW_GT)) return -22;
    int status = state->io->check_context(state->context);
    if (status) return status;
    struct stela_intel_guc_reset_result result = {0};
    status = stela_intel_guc_reset(state->io, state->context, state, &state->facts, &result);
    if (status && result.writes) {
        /* No safe sleep/drain/owner release after an uncertain reset effect. */
        state->guc_reset_uncertain = true;
        state->poisoned = true;
    }
    if (!status) state->guc_reset_issued = true;
    if (!status || result.writes) *out = result;
    return status;
}
