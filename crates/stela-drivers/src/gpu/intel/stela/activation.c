/* SPDX-License-Identifier: MIT */
/* Stela's environment for the unchanged Linux xe_pci.c, xe_step.c and
 * xe_force_wake.c, which follow. Activation runs Linux's own device-info
 * probe and GT forcewake on a native device; nothing else of the PCI driver
 * is reachable. */
#include "activation.h"
#include "guc_reset.h"
#include "pat.h"
#include "unsupported.h"
#include "wopcm.h"
#include <stdarg.h>
#include <linux/pci.h>
#include "regs/xe_gt_regs.h"
#include "xe_device.h"
#include "xe_force_wake.h"
#include "xe_gt.h"
#include "xe_mmio.h"

struct stela_intel_activation {
    const struct stela_intel_activation_io *io;
    void *context;
    uint64_t bar_bytes;
    struct stela_intel_activation_facts facts;
    struct pci_dev pdev;
    struct xe_device xe;
    struct xe_gt gts[XE_MAX_TILES_PER_DEVICE * XE_MAX_GT_PER_TILE];
    unsigned gts_used;
    uint32_t gmdid[2];      /* Latest graphics and media GMD_ID reads. */
    bool waited;            /* A forcewake acknowledgment wait ran. */
    uint32_t ack;           /* Its last acknowledgment read. */
    int wait_error;         /* Its failure, from xe_force_wake.c's report. */
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
    return container_of(xe, struct stela_intel_activation, xe);
}
static void invariant(struct stela_intel_activation *state, bool condition)
{
    state->io->invariant(state->context, condition);
}

/* Register access through the owner's mapped BAR0 window. Every tile and GT
 * register handle names the activation that owns it. */
static struct stela_intel_activation *mmio_state(struct xe_mmio *mmio)
{
    return mmio->context;
}
static u32 xe_mmio_read32(struct xe_mmio *mmio, struct xe_reg reg)
{
    struct stela_intel_activation *state = mmio_state(mmio);
    u32 addr = reg.addr + mmio->adj_offset;
    invariant(state, !(addr & 3) && (uint64_t)addr + 4 <= SZ_4M);
    u32 value = state->io->read32(state->context, addr);
    if (addr == GMD_ID.addr) state->gmdid[0] = value;
    if (addr == GMD_ID.addr + MEDIA_GT_GSI_OFFSET) state->gmdid[1] = value;
    return value;
}
static void xe_mmio_write32(struct xe_mmio *mmio, struct xe_reg reg, u32 value)
{
    struct stela_intel_activation *state = mmio_state(mmio);
    u32 addr = reg.addr + mmio->adj_offset;
    invariant(state, !(addr & 3) && (uint64_t)addr + 4 <= SZ_4M);
    state->io->write32(state->context, addr, value);
}
int stela_intel_mmio_wait32(const struct stela_intel_activation_io *io, void *context,
    uint32_t offset, uint32_t mask, uint32_t value, uint32_t timeout_us, uint32_t *out,
    bool atomic)
{
    io->invariant(context, !(offset & 3) && (uint64_t)offset + 4 <= SZ_4M);
    int64_t end = io->now_ns(context) + (int64_t)timeout_us * 1000;
    uint32_t wait = 10, read = io->read32(context, offset);
    int ret = 0;
    while ((read & mask) != value) {
        int64_t now = io->now_ns(context);
        if (now > end) {
            read = io->read32(context, offset);
            ret = (read & mask) == value ? 0 : -ETIMEDOUT;
            break;
        }
        uint32_t left = (uint32_t)((end - now) / 1000) + 1;
        if (wait > left) wait = left;
        io->delay_us(context, wait, atomic ? wait : wait << 1, atomic);
        if (wait < 1000) wait <<= 1;
        read = io->read32(context, offset);
    }
    *out = read;
    return ret;
}
static int xe_mmio_wait32(struct xe_mmio *mmio, struct xe_reg reg, u32 mask, u32 val,
                          u32 timeout_us, u32 *out_val, bool atomic)
{
    struct stela_intel_activation *state = mmio_state(mmio);
    u32 read;
    int ret = stela_intel_mmio_wait32(state->io, state->context, reg.addr + mmio->adj_offset,
                                      mask, val, timeout_us, &read, atomic);
    for (unsigned i = 0; i < XE_FW_DOMAIN_ID_COUNT; ++i) {
        const struct xe_force_wake_domain *domain = &state->gts[0].pm.fw.domains[i];
        if (domain->reg_ctl.addr && domain->reg_ack.addr == reg.addr) {
            state->waited = true;
            state->ack = read;
        }
    }
    if (out_val) *out_val = read;
    return ret;
}

/* Linux's GT and tile objects, from the activation's own storage. */
static struct xe_gt *xe_gt_alloc(struct xe_tile *tile)
{
    struct stela_intel_activation *state = state_of(tile->xe);
    if (state->gts_used == ARRAY_SIZE(state->gts)) return ERR_PTR(-ENOMEM);
    struct xe_gt *gt = &state->gts[state->gts_used++];
    __builtin_memset(gt, 0, sizeof(*gt));
    gt->tile = tile;
    return gt;
}
/* Stela builds no tile-managed objects (GGTT, SA pools, migration, PCODE
 * lock) during activation; their owners initialize them. */
int xe_tile_init_early(struct xe_tile *tile, struct xe_device *xe, u8 id)
{
    tile->xe = xe;
    tile->id = id;
    tile->mmio = (struct xe_mmio){0};
    return 0;
}
/* VRAM regions belong to the memory manager, which activation does not
 * start; on an integrated device Linux allocates none either. */
int xe_tile_alloc_vram(struct xe_tile *tile)
{
    (void)tile;
    return 0;
}

/* Forcewake failures carry their status in xe_force_wake.c's reports. */
static void stela_drm_printk(const struct drm_device *drm, enum stela_drm_level level,
    const char *format, ...)
{
    struct stela_intel_activation *state = state_of(to_xe_device(drm));
    (void)level;
    if (!strcmp(format, "Force wake domain %d failed to ack %s (%pe) reg[%#x] = %#x\n")) {
        va_list arguments;
        va_start(arguments, format);
        (void)va_arg(arguments, int);
        (void)va_arg(arguments, const char *);
        state->wait_error = (int)PTR_ERR(va_arg(arguments, void *));
        va_end(arguments);
    } else if (!strcmp(format, "Force wake domain %d: %s. MMIO unreliable (forcewake register returns 0xFFFFFFFF)!\n")) {
        state->wait_error = -EIO;
    }
}
/* Forcewake reports its unacknowledged domains, already failed above. */
static void stela_linux_warn(const char *file, int line, const char *condition)
{
    (void)file; (void)line; (void)condition;
}

/* The rest of the PCI driver: probe, removal, power management, SR-IOV and
 * the module's registration. Activation reaches none of it. */
STELA_UNSUPPORTED(void *, kzalloc, size_t, gfp_t)
STELA_UNSUPPORTED(char *, kstrdup, const char *, gfp_t)
STELA_UNSUPPORTED(void, kfree, const void *)
STELA_UNSUPPORTED(void, dev_info, const struct device *, const char *, ...)
STELA_UNSUPPORTED(int, pcim_enable_device, struct pci_dev *)
STELA_UNSUPPORTED(void, pci_set_drvdata, struct pci_dev *, void *)
STELA_UNSUPPORTED(void, pci_set_master, struct pci_dev *)
STELA_UNSUPPORTED(int, pci_register_driver, struct pci_driver *)
STELA_UNSUPPORTED(void, pci_unregister_driver, struct pci_driver *)
STELA_UNSUPPORTED(struct drm_device *, pci_iov_get_pf_drvdata, struct pci_dev *, struct pci_driver *)
STELA_UNSUPPORTED(struct xe_device *, pdev_to_xe_device, struct pci_dev *)
STELA_UNSUPPORTED(struct xe_device *, xe_device_create, struct pci_dev *)
STELA_UNSUPPORTED(int, xe_device_probe_early, struct xe_device *)
STELA_UNSUPPORTED(int, xe_device_probe, struct xe_device *)
STELA_UNSUPPORTED(void, xe_device_remove, struct xe_device *)
STELA_UNSUPPORTED(void, xe_device_shutdown, struct xe_device *)
STELA_UNSUPPORTED(void, xe_gt_mmio_init, struct xe_gt *)
STELA_UNSUPPORTED(void, xe_guc_comm_init_early, struct xe_guc *)
STELA_UNSUPPORTED(int, xe_gt_sriov_vf_bootstrap, struct xe_gt *)
STELA_UNSUPPORTED(u32, xe_gt_sriov_vf_gmdid, struct xe_gt *)
STELA_UNSUPPORTED_EXTERN(void, xe_destroy_wq_flush, void)
STELA_UNSUPPORTED_EXTERN(void, xe_pci_rebar_resize, struct xe_device *)
STELA_UNSUPPORTED_EXTERN(bool, xe_survivability_mode_is_boot_enabled, struct xe_device *)
STELA_UNSUPPORTED_EXTERN(void, xe_pm_assert_unbounded_bridge, struct xe_device *)
STELA_UNSUPPORTED_EXTERN(int, xe_pm_probe, struct xe_device *)
STELA_UNSUPPORTED_EXTERN(int, xe_pm_init, struct xe_device *)
STELA_UNSUPPORTED_EXTERN(void, xe_pm_fini, struct xe_device *)
STELA_UNSUPPORTED_EXTERN(const char *, xe_sriov_mode_to_string, enum xe_sriov_mode)

#include "xe_force_wake.c"
#include "xe_step.c"
#include "xe_pci.c"

static bool valid_io(const struct stela_intel_activation_io *io)
{
    return io && io->check_context && io->prepare && io->read32 && io->write32 && io->now_ns && io->delay_us &&
           io->invariant && io->report;
}
/* Linux's pci_match_id over the driver's own table. */
static const struct pci_device_id *match(uint32_t vendor, uint32_t device, uint32_t pci_class)
{
    for (const struct pci_device_id *id = pciidlist; id->vendor || id->subvendor || id->class_mask; ++id)
        if ((id->vendor == (u32)PCI_ANY_ID || id->vendor == vendor) &&
            (id->device == (u32)PCI_ANY_ID || id->device == device) &&
            !((id->class ^ pci_class) & id->class_mask))
            return id;
    return NULL;
}
static int descriptor(uint32_t vendor, uint32_t device, uint32_t pci_class,
                       bool vf, bool force_probe, const struct xe_device_desc **out)
{
    if (vendor > UINT16_MAX || device > UINT16_MAX || pci_class > 0xffffff) return -22;
    if (vf) return -95;
    const struct pci_device_id *id = match(vendor, device, pci_class);
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
    struct xe_device *xe = &state->xe;
    xe->drm.dev = &state->pdev.dev;
    xe->sriov.__mode = XE_SRIOV_MODE_NONE;
    int ret = xe_info_init_early(xe, desc, find_subplatform(desc, (u16)device));
    if (ret) return ret;
    xe->tiles[0].mmio = (struct xe_mmio){.io = state->io, .context = state};
    ret = xe_info_init(xe, desc);
    if (ret) return ret;
    if ((uint64_t)xe->info.tile_count * SZ_16M > state->bar_bytes) return -22;
    /* xe_gt_mmio_init gives the root primary GT its tile's registers. */
    struct xe_gt *gt = xe->tiles[0].primary_gt;
    invariant(state, gt == &state->gts[0]);
    gt->mmio = xe->tiles[0].mmio;
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
    if (time < 0 || time > INT64_MAX - INT64_C(100000000)) return -22;
    /* Linux's objects point into each other, so they are built in place and
     * the caller's bytes restored if the probe fails. */
    struct stela_intel_activation *state = storage, saved = *state;
    *state = (struct stela_intel_activation){
        .io = io, .context = context, .bar_bytes = bar_bytes,
        .pdev = {.vendor = (unsigned short)vendor, .device = (unsigned short)device,
                 .revision = (u8)revision, .class = pci_class},
    };
    ret = probe(state, desc, device, revision);
    if (ret) *state = saved;
    return ret;
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

/* One reference on the root GT's GT domain. A failed acknowledgment leaves
 * the device in an unknown power state, so it poisons the activation. */
static int forcewake(struct stela_intel_activation *state, bool wake)
{
    struct xe_force_wake *fw = gt_to_fw(&state->gts[0]);
    state->waited = false;
    state->wait_error = 0;
    bool failed;
    if (wake) failed = !(xe_force_wake_get(fw, XE_FW_GT) & XE_FW_GT);
    else {
        xe_force_wake_put(fw, XE_FW_GT);
        failed = state->wait_error != 0;
    }
    sync_awake(state);
    if (state->waited)
        state->io->report(state->context, (uint32_t)XE_FW_GT, wake, state->wait_error, state->ack);
    if (!failed) return 0;
    state->poisoned = true;
    return state->wait_error ? state->wait_error : -110;
}
int stela_intel_activation_wake(struct stela_intel_activation *state)
{
    if (!state || !valid_io(state->io)) return -22;
    int context_status = state->io->check_context(state->context);
    if (context_status) return context_status;
    if (state->poisoned) return -5;
    if (state->gts[0].pm.fw.domains[XE_FW_DOMAIN_ID_GT].ref == UINT32_MAX) return -22;
    return forcewake(state, true);
}
int stela_intel_activation_sleep(struct stela_intel_activation *state)
{
    if (!state || !valid_io(state->io)) return -22;
    int context_status = state->io->check_context(state->context);
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
    if (!state || !valid_io(state->io)) return -22;
    if (state->poisoned || state->wopcm_uncertain) return -5;
    if (state->wopcm_prepared) return -114;
    if (!gt_awake(state)) return -22;
    int status = state->io->check_context(state->context);
    if (status) return status;
    status = stela_intel_wopcm_prepare(state->io, state->context,
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
    if (!gt_awake(state)) return -22;
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
    if (!gt_awake(state)) return -22;
    int status = state->io->check_context(state->context);
    if (status) return status;
    struct stela_intel_guc_reset_result result = {0};
    status = stela_intel_guc_reset(state->io, state->context, &state->facts, &result);
    if (status && result.writes) {
        /* No safe sleep/drain/owner release after an uncertain reset effect. */
        state->guc_reset_uncertain = true;
        state->poisoned = true;
    }
    if (!status) state->guc_reset_issued = true;
    if (!status || result.writes) *out = result;
    return status;
}
