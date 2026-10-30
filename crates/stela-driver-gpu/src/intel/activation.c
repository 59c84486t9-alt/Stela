/* SPDX-License-Identifier: MIT */
/* The unchanged Linux xe_module.c, xe_pci.c, xe_step.c and xe_force_wake.c,
 * run on a native device. Activation runs Linux's own device-info probe and
 * GT forcewake; nothing else of the PCI driver is reachable. */
#include "activation.h"
#include "device.h"
#include "guc_reset.h"
#include "pat.h"
#include "wopcm.h"
#include <stela/module.h>
#include <unsupported.h>
#include "xe_bo.h"
#include "xe_vram_types.h"
#include "xe_module.c"
#include "xe_force_wake.c"
#include "xe_step.c"
#include "xe_pci.c"

/* The rest of the PCI driver and module: registration, probe and removal,
 * power management, SR-IOV and device setup. Activation reaches none of it. */
STELA_UNSUPPORTED(struct xe_device *, xe_device_create, struct pci_dev *)
STELA_UNSUPPORTED(int, xe_device_probe, struct xe_device *)
STELA_UNSUPPORTED(int, xe_device_probe_early, struct xe_device *)
STELA_UNSUPPORTED(void, xe_device_remove, struct xe_device *)
STELA_UNSUPPORTED(void, xe_device_shutdown, struct xe_device *)
STELA_UNSUPPORTED(int, xe_gt_sriov_vf_bootstrap, struct xe_gt *)
STELA_UNSUPPORTED(u32, xe_gt_sriov_vf_gmdid, struct xe_gt *)
STELA_UNSUPPORTED(void, xe_guc_comm_init_early, struct xe_guc *)
STELA_UNSUPPORTED(void, xe_hw_fence_module_exit, void)
STELA_UNSUPPORTED(int, xe_hw_fence_module_init, void)
STELA_UNSUPPORTED(int, xe_observation_sysctl_register, void)
STELA_UNSUPPORTED(void, xe_observation_sysctl_unregister, void)
STELA_UNSUPPORTED(void, xe_pci_rebar_resize, struct xe_device *)
STELA_UNSUPPORTED(void, xe_pm_assert_unbounded_bridge, struct xe_device *)
STELA_UNSUPPORTED(void, xe_pm_fini, struct xe_device *)
STELA_UNSUPPORTED(int, xe_pm_init, struct xe_device *)
STELA_UNSUPPORTED(int, xe_pm_module_init, void)
STELA_UNSUPPORTED(int, xe_pm_probe, struct xe_device *)
STELA_UNSUPPORTED(void, xe_sched_job_module_exit, void)
STELA_UNSUPPORTED(int, xe_sched_job_module_init, void)
STELA_UNSUPPORTED(const char *, xe_sriov_mode_to_string, enum xe_sriov_mode)
STELA_UNSUPPORTED(bool, xe_survivability_mode_is_boot_enabled, struct xe_device *)

struct stela_intel_activation {
    struct stela_xe dev;
    uint64_t bar_bytes;
    struct stela_intel_activation_facts facts;
    struct pci_dev pdev;
    struct xe_gt gts[XE_MAX_TILES_PER_DEVICE * XE_MAX_GT_PER_TILE];
    unsigned gts_used;
    struct xe_vram_region vram[XE_MAX_TILES_PER_DEVICE];
    uint32_t gmdid[2];      /* Latest graphics and media GMD_ID reads. */
    bool waited;            /* The GT domain's acknowledgment was read. */
    uint32_t ack;           /* Its last read. */
    bool poisoned;
    bool wopcm_uncertain;
    bool wopcm_prepared;
    bool pat_sequence_issued;
    bool guc_reset_issued, guc_reset_uncertain;
};

size_t stela_intel_activation_size(void) { return sizeof(struct stela_intel_activation); }
size_t stela_intel_activation_alignment(void) { return _Alignof(struct stela_intel_activation); }

static struct stela_intel_activation *state_of(struct xe_device *xe)
{
    return container_of(stela_xe(xe), struct stela_intel_activation, dev);
}
static void invariant(struct stela_intel_activation *state, bool condition)
{
    state->dev.io->invariant(state->dev.context, condition);
}

static void observe(struct stela_xe *dev, u32 addr, u32 value, bool write)
{
    struct stela_intel_activation *state = state_of(&dev->xe);
    if (write) return;
    if (addr == GMD_ID.addr) state->gmdid[0] = value;
    if (addr == GMD_ID.addr + MEDIA_GT_GSI_OFFSET) state->gmdid[1] = value;
    const struct xe_force_wake *fw = &state->gts[0].pm.fw;
    if ((fw->initialized_domains & XE_FW_GT) &&
        addr == fw->domains[XE_FW_DOMAIN_ID_GT].reg_ack.addr) {
        state->waited = true;
        state->ack = value;
    }
}
/* Activation's messages and warnings restate the failures its statuses
 * carry, so it discards them. */
static const struct stela_linux_services services = {
    .now_ns = stela_xe_now_ns, .delay_us = stela_xe_delay_us,
    .unsupported = stela_xe_unsupported,
};
static struct stela_linux_owner owner_of(struct stela_intel_activation *state)
{
    return (struct stela_linux_owner){.services = &services, .context = &state->dev};
}

/* The parts of xe_gt.c and xe_tile.c that the probe calls. Activation's GTs
 * and VRAM regions live in its own storage. A GT gets no ordered workqueue,
 * as activation queues no work; the tile's GGTT, migration and PCODE state
 * belong to the owners that start them, not to activation. */
struct xe_gt *xe_gt_alloc(struct xe_tile *tile)
{
    struct stela_intel_activation *state = state_of(tile_to_xe(tile));
    if (state->gts_used == ARRAY_SIZE(state->gts)) return ERR_PTR(-ENOMEM);
    struct xe_gt *gt = &state->gts[state->gts_used++];
    gt->tile = tile;
    return gt;
}
int xe_tile_init_early(struct xe_tile *tile, struct xe_device *xe, u8 id)
{
    tile->xe = xe;
    tile->id = id;
    return 0;
}
int xe_tile_alloc_vram(struct xe_tile *tile)
{
    struct xe_device *xe = tile_to_xe(tile);
    if (!IS_DGFX(xe)) return 0;
    struct xe_vram_region *vram = &state_of(xe)->vram[tile->id];
    vram->xe = xe;
    vram->id = tile->id;
    vram->placement = XE_PL_VRAM0 + tile->id;
    tile->mem.vram = vram;
    if (!tile->mem.kernel_vram) tile->mem.kernel_vram = vram;
    return 0;
}

static bool valid_io(const struct stela_intel_activation_io *io)
{
    return io && io->check_context && io->prepare && io->read32 && io->write32 && io->now_ns &&
           io->delay_us && io->invariant && io->report;
}
/* The PCI core's match against the driver's table, before claiming BARs. */
static int descriptor(uint32_t vendor, uint32_t device, uint32_t pci_class,
                      bool vf, bool force_probe, const struct xe_device_desc **out)
{
    if (vendor > UINT16_MAX || device > UINT16_MAX || pci_class > 0xffffff) return -22;
    if (vf) return -95;
    struct pci_dev pdev = {.vendor = (unsigned short)vendor, .device = (unsigned short)device,
                           .class = pci_class};
    stela_linux_enter(&stela_linux_bare);
    const struct pci_device_id *id = pci_match_id(pciidlist, &pdev);
    stela_linux_exit();
    if (!id) return -19;
    const struct xe_device_desc *desc = (const void *)id->driver_data;
    /* xe_pci_probe's force_probe policy, decided by the caller. */
    if (desc->require_force_probe && !force_probe) return -95;
    *out = desc;
    return 0;
}
int stela_intel_activation_match(uint32_t vendor, uint32_t device, uint32_t pci_class,
                                 bool vf, bool force_probe)
{
    const struct xe_device_desc *matched;
    return descriptor(vendor, device, pci_class, vf, force_probe, &matched);
}

static void sync_awake(struct stela_intel_activation *state)
{
    state->facts.awake = state->gts[0].pm.fw.awake_domains;
}
/* The probe xe_pci_probe runs before any device setup: Linux's device info
 * and the root GT's forcewake domains. */
static int probe(struct stela_intel_activation *state, const struct xe_device_desc *desc,
                 uint32_t device, uint32_t revision)
{
    struct xe_device *xe = &state->dev.xe;
    xe->drm.dev = &state->pdev.dev;
    xe->sriov.__mode = XE_SRIOV_MODE_NONE;
    int ret = xe_info_init_early(xe, desc, find_subplatform(desc, (u16)device));
    if (ret) return ret;
    /* xe_mmio_probe_early's root tile registers: the first 4 MiB of BAR0. */
    xe_mmio_init(&xe->tiles[0].mmio, &xe->tiles[0], NULL, SZ_4M);
    ret = xe_info_init(xe, desc);
    if (ret) return ret;
    if ((uint64_t)xe->info.tile_count * SZ_16M > state->bar_bytes) return -22;
    struct xe_gt *gt = xe->tiles[0].primary_gt;
    invariant(state, gt == &state->gts[0]);
    xe_gt_mmio_init(gt);
    xe_force_wake_init_gt(gt, gt_to_fw(gt));
    const struct xe_force_wake_domain *domain = &gt->pm.fw.domains[XE_FW_DOMAIN_ID_GT];
    bool gmdid = !desc->pre_gmdid_graphics_ip;
    state->facts = (struct stela_intel_activation_facts){
        .platform = (uint32_t)xe->info.platform, .subplatform = (uint32_t)xe->info.subplatform,
        .graphics_verx100 = xe->info.graphics_verx100, .media_verx100 = xe->info.media_verx100,
        .graphics_revision = gmdid ? REG_FIELD_GET(GMD_ID_REVID, state->gmdid[0]) : revision,
        .media_revision = gmdid ? REG_FIELD_GET(GMD_ID_REVID, state->gmdid[1]) : revision,
        .pci_revision = revision, .tile_count = xe->info.tile_count,
        .dma_bits = xe->info.dma_mask_size, .va_bits = xe->info.va_bits,
        .max_gt_per_tile = xe->info.max_gt_per_tile, .discrete = xe->info.is_dgfx,
        .force_probe_required = desc->require_force_probe,
        .gt_control = domain->reg_ctl.addr, .gt_ack = domain->reg_ack.addr,
        .initialized = gt->pm.fw.initialized_domains, .has_llc = xe->info.has_llc,
        .gt_type = gt->info.type,
    };
    return 0;
}
/* The caller's bytes, kept while a probe builds Linux's objects in place
 * (they point into each other) and restored if it fails. Only the running
 * Linux owner uses it, so there is one. */
static struct stela_intel_activation saved;

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
    if (bar_bytes < SZ_16M) return -22;
    ret = io->check_context(context);
    if (ret) return ret;
    ret = io->prepare(context, (uint32_t)desc->platform, revision, desc->is_dgfx);
    if (ret) return ret;
    int64_t time = io->now_ns(context);
    if (time < 0 || time > INT64_MAX - INT64_C(2000000000)) return -22;
    struct stela_intel_activation *state = storage;
    const struct stela_linux_owner owner = owner_of(state);
    stela_linux_enter(&owner);
    saved = *state;
    memset(state, 0, sizeof(*state));
    state->dev.io = io;
    state->dev.context = context;
    state->dev.observe = observe;
    state->bar_bytes = bar_bytes;
    state->pdev.vendor = (unsigned short)vendor;
    state->pdev.device = (unsigned short)device;
    state->pdev.revision = (u8)revision;
    state->pdev.class = pci_class;
    ret = probe(state, desc, device, revision);
    if (!ret && state->dev.unsupported) ret = -EOPNOTSUPP;
    if (ret) *state = saved;
    stela_linux_exit();
    return ret;
}

int stela_intel_activation_facts(const struct stela_intel_activation *state,
                                struct stela_intel_activation_facts *facts)
{
    if (!state || !facts || !valid_io(state->dev.io)) return -22;
    if (state->wopcm_uncertain || state->guc_reset_uncertain) return -5;
    int context_status = state->dev.io->check_context(state->dev.context);
    if (context_status) return context_status;
    *facts = state->facts;
    return 0;
}

/* One reference on the root GT's GT domain. A failed acknowledgment leaves
 * the device in an unknown power state, so it poisons the activation. As
 * xe_force_wake.c does, an all-ones acknowledgment is unreliable MMIO and any
 * other failure a timeout. */
static int forcewake(struct stela_intel_activation *state, bool wake)
{
    struct xe_force_wake *fw = gt_to_fw(&state->gts[0]);
    const struct xe_force_wake_domain *domain = &fw->domains[XE_FW_DOMAIN_ID_GT];
    state->waited = false;
    const struct stela_linux_owner owner = owner_of(state);
    stela_linux_enter(&owner);
    bool failed;
    if (wake) failed = !(xe_force_wake_get(fw, XE_FW_GT) & XE_FW_GT);
    else {
        xe_force_wake_put(fw, XE_FW_GT);
        failed = !domain->ref && (fw->awake_domains & XE_FW_GT);
    }
    stela_linux_exit();
    sync_awake(state);
    int status = state->dev.unsupported ? -EOPNOTSUPP :
                 !failed                ? 0 :
                 state->ack == ~0u      ? -EIO : -ETIMEDOUT;
    if (state->waited)
        state->dev.io->report(state->dev.context, (uint32_t)XE_FW_GT, wake, status, state->ack);
    if (status) state->poisoned = true;
    return status;
}
int stela_intel_activation_wake(struct stela_intel_activation *state)
{
    if (!state || !valid_io(state->dev.io)) return -22;
    int context_status = state->dev.io->check_context(state->dev.context);
    if (context_status) return context_status;
    if (state->poisoned) return -5;
    if (state->gts[0].pm.fw.domains[XE_FW_DOMAIN_ID_GT].ref == UINT32_MAX) return -22;
    return forcewake(state, true);
}
int stela_intel_activation_sleep(struct stela_intel_activation *state)
{
    if (!state || !valid_io(state->dev.io)) return -22;
    int context_status = state->dev.io->check_context(state->dev.context);
    if (context_status) return context_status;
    if (state->poisoned) return -5;
    if (!state->gts[0].pm.fw.domains[XE_FW_DOMAIN_ID_GT].ref) return -22;
    return forcewake(state, false);
}

static bool gt_awake(const struct stela_intel_activation *state)
{
    return state->gts[0].pm.fw.domains[XE_FW_DOMAIN_ID_GT].ref &&
           (state->facts.awake & (uint32_t)XE_FW_GT);
}
int stela_intel_activation_wopcm(struct stela_intel_activation *state,
    const uint8_t *bytes, size_t size, struct stela_intel_wopcm_result *out)
{
    if (!out) return -22;
    *out = (struct stela_intel_wopcm_result){0};
    if (!state || !valid_io(state->dev.io)) return -22;
    if (state->poisoned || state->wopcm_uncertain) return -5;
    if (state->wopcm_prepared) return -114;
    if (!gt_awake(state)) return -22;
    int status = state->dev.io->check_context(state->dev.context);
    if (status) return status;
    status = stela_intel_wopcm_prepare(state->dev.io, state->dev.context,
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
    if (!state || !out || !valid_io(state->dev.io)) return -22;
    if (state->poisoned || state->wopcm_uncertain) return -5;
    if (state->pat_sequence_issued || state->wopcm_prepared) return -114;
    if (!gt_awake(state)) return -22;
    int status = state->dev.io->check_context(state->dev.context);
    if (status) return status;
    status = stela_intel_pat_program(state->dev.io, state->dev.context, &state->facts, out);
    if (!status) state->pat_sequence_issued = true; /* Issued, never an ACK. */
    return status;
}

int stela_intel_activation_guc_reset(struct stela_intel_activation *state,
                                    struct stela_intel_guc_reset_result *out)
{
    if (!state || !out || !valid_io(state->dev.io)) return -22;
    if (state->poisoned || state->wopcm_uncertain || state->guc_reset_uncertain) return -5;
    if (state->guc_reset_issued) return -114;
    if (!gt_awake(state)) return -22;
    int status = state->dev.io->check_context(state->dev.context);
    if (status) return status;
    struct stela_intel_guc_reset_result result = {0};
    status = stela_intel_guc_reset(state->dev.io, state->dev.context, &state->facts, &result);
    if (status && result.writes) {
        /* No safe sleep/drain/owner release after an uncertain reset effect. */
        state->guc_reset_uncertain = true;
        state->poisoned = true;
    }
    if (!status) state->guc_reset_issued = true;
    if (!status || result.writes) *out = result;
    return status;
}
