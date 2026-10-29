//! iBoot's memory-controller lock registers: `/chosen/lock-regs`, where SPTM
//! finds the AMCC's register map, and the CTRR-A region iBoot programs into
//! it before SPTM starts.
//!
//! The map is iBoot's own. 26A434 `iBoot.j473.RELEASE` builds a `harr`
//! table (`0x377bc`) that `0x126f34` turns into the `amcc` node: the
//! aperture count, size and physical addresses, the plane count and stride,
//! the cache-status register, and five registers per lock group, each an
//! offset into a plane, a mask and, for the bit registers, the value that
//! means set. Of the template's four groups iBoot fills only `amcc-ctrr-a`;
//! the others stay empty, as it leaves them.
//!
//! Every SoC's map comes from its own iBoot's `harr` builder, run over the
//! decoded image ([`FAMILIES`]; builders, emulation and checks in
//! docs/research/iboot-handoff.md, "Memory-controller lock registers"). The
//! M4 and later fill all four AMCC groups, CTRR-B to D with zero limits. The
//! publisher writes only into the nodes the template carries, so a group or
//! controller it describes without one (IOA-B and later everywhere, the whole
//! IOA on the M4 and later) stays unpublished. The M1 and M2 iBoots describe
//! no IOA.
//!
//! T6000 is independently recovered from 26A434 `iBoot.j314s` (decoded
//! SHA256 `20dfa3a5e6d4e4b2844c7558e6d4f8ab74397d11eae63312f00a559cf9612b03`).
//! Its builder at file `0x3848c` and publisher `0x1376d4` describe four AMCC
//! apertures, four planes each, and four single-plane IOA apertures. The MCC
//! count selector `0x514ac` indexes `0x1dfff0` by chip ID minus `0x6000`;
//! IOA selector `0x38220` indexes `0x1d8f24`, with addresses at `0x1d3110`.
//! The AMCC broadcast offset is `0x10000c`, outside the first plane
//! stride, and cache-status is `(0x1c00, 0x1f, 0)`. It has no master-lock.
//! IOA publishes master-lock `(0, 1, 1)` and no broadcast. CTRR-A has no
//! write-disable register on either controller, and IOA has no lock register.
//! The builder also contains IOA-B, but the original J314s DeviceTree has no
//! such node: publisher `0x137aa4` uses existing-child lookup `0xe0840`, then
//! skips a missing child at `0x137b28`. Only IOA-A is published here.
//!
//! Original T6000 SPTM (decoded SHA256
//! `dda6be8f5aa266b2a9505269d7152e870e2b610114185a2f60a587782d2af082`)
//! `0xfffffff0270d64f8` selects AMCC and IOA separately. Register reader
//! `0xfffffff0270d6d20` allows absent enable/write-disable/IOA lock fields;
//! `0xfffffff0270d75a0` requires matching limits across apertures/planes.
//! Its CTRR selector requests cache-status only for AMCC and does not consume
//! master-lock or broadcast. Their publication alone checks no MMIO effects.
//!
//! SPTM's register reader requires lower/upper limits and AMCC's lock, while
//! enable/write-disable and IOA's lock may be absent. Limits must agree across
//! every aperture and plane; the upper page is inclusive. AMCC limits count
//! pages from the DRAM base. IOA limits count absolute physical pages, which
//! T6000 SPTM `0xfffffff0270d7748..0xfffffff0270d777c` normalizes by subtracting
//! `dram_base >> page-size-shift`. `ctrr_lock_boot` checks the described cache
//! status and present write-disable/lock fields, then writes the present enable,
//! write-disable and lock fields in order, with the cores' matching CTRR range.
//!
//! iBoot's choice of region: the CTRR-A region covers the read-only and
//! executable images, which SPTM requires in one physical run ahead of every
//! writable one (m1n1 `load_macos_sptm`: "Required by SPTM in this order").
//! Public XNU 11215 `arm_init_sptm.c` keeps the AuxKC read-only region
//! "right below the device tree/trustcache so that it can be covered by
//! CTRR". The bundle programs the run from its first region through
//! `SPTM-rx`.
//!
//! On the M4 and later iBoot also locks the cores' per-cluster CTRR-C/D and
//! CTXR-A..D copies, and CTRR-A/B's controls, before SPTM starts
//! ([`core_handoff`]; the shared record contract is in `stela_formats::boot_bundle::schema`).
//! M5 iBoot (`iBoot.j813`) writes each region's per-core and per-cluster
//! copies together (`0x31588`, `0x316e0`) and locks them (`0x31658`,
//! `0x317b0`); SPTM 26A434 derives the same six regions from
//! `/chosen/memory-map` and panics unless the per-cluster copies hold them.
//! Without a CL4 image iBoot allocates a 16 KiB page, fills it with `wfi`
//! and publishes it as `CL4-dummypage` (`iBoot.j813` `0x29600..0x29668`),
//! which SPTM then requires as CTXR-B's region.
use crate::Result;
use crate::apple_device_tree::DeviceTree;
use alloc::{format, string::String, vec::Vec};
use core::ops::Range;
use stela_contracts::{refuse, require};
use stela_formats::boot_bundle::schema::CoreLocks;
use stela_formats::boot_bundle::schema::LockRegion;
use stela_formats::boot_bundle::schema::Locked;
pub use stela_formats::boot_bundle::schema::Programmed;

pub const AMCC: &str = "/chosen/lock-regs/amcc";
pub const IOA: &str = "/chosen/lock-regs/ioa";

/// One register of a plane: its offset, the bits that hold it and, for a
/// bit register, the masked value that means set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Register {
    pub offset: u32,
    pub mask: u32,
    pub value: Option<u32>,
}

/// A lock group: a region the memory controller protects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockGroup {
    pub name: &'static str,
    /// The limits count pages of `1 << page_size_shift` bytes.
    pub page_size_shift: u32,
    pub lower_limit: Register,
    pub upper_limit: Register,
    pub enable: Option<Register>,
    pub write_disable: Option<Register>,
    pub lock: Option<Register>,
}

/// A memory controller as its `/chosen/lock-regs` node describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryController {
    pub apertures: &'static [u64],
    pub aperture_size: u32,
    pub plane_count: u32,
    pub plane_stride: u32,
    /// Reads `value` under `mask` on every plane while the cache is
    /// disabled.
    pub cache_status: Option<Register>,
    /// Optional original control descriptors; their masked values are literal,
    /// including master-lock's zero, not an assumed active-high bit convention.
    pub master_lock: Option<Register>,
    pub broadcast: Option<Register>,
    pub groups: &'static [LockGroup],
}

const fn bit(offset: u32) -> Register {
    Register {
        offset,
        mask: 1,
        value: Some(1),
    }
}

/// Limit registers: pages under `mask`, with the value iBoot describes, if
/// any.
const fn limits(mask: u32, value: Option<u32>) -> Register {
    Register {
        offset: 0,
        mask,
        value,
    }
}

/// The limits of a group iBoot programs (CTRR-A): no described value.
const PROGRAMMED: Register = limits(u32::MAX, None);
/// The limits of a group iBoot describes as zero and leaves unprogrammed.
const ZERO: Register = limits(u32::MAX, Some(0));

impl LockGroup {
    /// A group of 16 KiB pages, its limits at `lower` and `upper` as `limit`
    /// describes them, enabled at `enable`.
    const fn new(name: &'static str, limit: Register, lower: u32, upper: u32, enable: u32) -> Self {
        Self {
            name,
            page_size_shift: 14,
            lower_limit: Register {
                offset: lower,
                ..limit
            },
            upper_limit: Register {
                offset: upper,
                ..limit
            },
            enable: Some(bit(enable)),
            write_disable: None,
            lock: None,
        }
    }

    const fn with_lock(mut self, offset: u32) -> Self {
        self.lock = Some(bit(offset));
        self
    }

    const fn with_write_disable(mut self, offset: u32) -> Self {
        self.write_disable = Some(bit(offset));
        self
    }

    /// Lower, upper, enable, lock and write-disable in consecutive words.
    const fn consecutive(name: &'static str, limit: Register, lower: u32) -> Self {
        Self::new(name, limit, lower, lower + 4, lower + 8)
            .with_lock(lower + 0xc)
            .with_write_disable(lower + 0x10)
    }

    /// The M4 Pro's and later AMCC layout: four words of each register,
    /// one per group, `index` naming the group.
    const fn interleaved(name: &'static str, limit: Register, index: u32) -> Self {
        let at = 4 * index;
        Self::new(name, limit, 0xaa0 + at, 0xab0 + at, 0xac0 + at)
            .with_lock(0xad0 + at)
            .with_write_disable(0xae0 + at)
    }

    /// An IOA group: limits under `limit`, enable after them.
    const fn ioa(
        name: &'static str,
        limit: Register,
        lower: u32,
        write_disable: u32,
        lock: u32,
    ) -> Self {
        Self::new(name, limit, lower, lower + 4, lower + 8)
            .with_lock(lock)
            .with_write_disable(write_disable)
    }
}

const M1_AMCC: [LockGroup; 1] =
    [LockGroup::new("amcc-ctrr-a", PROGRAMMED, 0x680, 0x684, 0x688).with_lock(0x68c)];
const T8112_AMCC: [LockGroup; 1] = [
    LockGroup::new("amcc-ctrr-a", PROGRAMMED, 0x680, 0x684, 0x688)
        .with_lock(0x68c)
        .with_write_disable(0x7f0),
];
const T6020_AMCC: [LockGroup; 1] = [LockGroup::consecutive("amcc-ctrr-a", PROGRAMMED, 0x680)];
const T8122_AMCC: [LockGroup; 1] = [LockGroup::consecutive("amcc-ctrr-a", PROGRAMMED, 0x690)];
const T6030_AMCC: [LockGroup; 1] = [LockGroup::consecutive("amcc-ctrr-a", PROGRAMMED, 0x6a0)];
const T6031_AMCC: [LockGroup; 1] = [LockGroup::consecutive("amcc-ctrr-a", PROGRAMMED, 0x69c)];
const T8132_AMCC: [LockGroup; 4] = [
    LockGroup::consecutive("amcc-ctrr-a", PROGRAMMED, 0x6a0),
    LockGroup::consecutive("amcc-ctrr-b", ZERO, 0x6b4),
    LockGroup::consecutive("amcc-ctrr-c", ZERO, 0x6c8),
    LockGroup::consecutive("amcc-ctrr-d", ZERO, 0x450),
];
const T6040_AMCC: [LockGroup; 4] = [
    LockGroup::interleaved("amcc-ctrr-a", PROGRAMMED, 0),
    LockGroup::interleaved("amcc-ctrr-b", ZERO, 1),
    LockGroup::interleaved("amcc-ctrr-c", ZERO, 2),
    LockGroup::interleaved("amcc-ctrr-d", ZERO, 3),
];

const M1_IOA: [LockGroup; 2] = [
    LockGroup::new("ioa-ctrr-a", PROGRAMMED, 0x220, 0x224, 0x228),
    LockGroup::new("ioa-ctrr-b", ZERO, 0x22c, 0x230, 0x234),
];
const M2_IOA: [LockGroup; 3] = [
    LockGroup::ioa("ioa-ctrr-a", limits(0x3fff_ffff, None), 0x220, 0x14, 0x4),
    LockGroup::ioa("ioa-ctrr-b", limits(0x3fff_ffff, Some(0)), 0x22c, 0x18, 0x8),
    LockGroup::ioa("ioa-ctrr-c", limits(0x3fff_ffff, Some(0)), 0x238, 0x1c, 0xc),
];
const M4_IOA: [LockGroup; 4] = [
    LockGroup::ioa("ioa-ctrr-a", limits(0x0fff_ffff, None), 0xa0, 0x18, 0x4),
    LockGroup::ioa("ioa-ctrr-b", limits(0x0fff_ffff, Some(0)), 0xac, 0x1c, 0x8),
    LockGroup::ioa("ioa-ctrr-c", limits(0x0fff_ffff, Some(0)), 0xb8, 0x20, 0xc),
    LockGroup::ioa("ioa-ctrr-d", limits(0x0fff_ffff, Some(0)), 0xc4, 0x24, 0x10),
];

/// The M2 Pro's to the M4's cache status: bit 0 clear.
const CACHE_CLEAR: Register = Register {
    offset: 0x1c00,
    mask: 1,
    value: Some(0),
};

/// An AMCC of planes `0x40000` apart.
const fn amcc(
    apertures: &'static [u64],
    aperture_size: u32,
    plane_count: u32,
    cache_status: Register,
    groups: &'static [LockGroup],
) -> MemoryController {
    MemoryController {
        apertures,
        aperture_size,
        plane_count,
        plane_stride: 0x4_0000,
        cache_status: Some(cache_status),
        master_lock: None,
        broadcast: None,
        groups,
    }
}

/// The M1 family's AMCC, as iBoot labels its controller registers.
const fn m1_amcc(apertures: &'static [u64], aperture_size: u32) -> MemoryController {
    let cache_status = Register {
        offset: 0x1c00,
        mask: 0x1f,
        value: Some(0),
    };
    MemoryController {
        broadcast: Some(bit(0x10_000c)),
        ..amcc(apertures, aperture_size, 4, cache_status, &M1_AMCC)
    }
}

/// Single-plane IOA apertures.
const fn ioa(
    apertures: &'static [u64],
    aperture_size: u32,
    groups: &'static [LockGroup],
) -> MemoryController {
    MemoryController {
        apertures,
        aperture_size,
        plane_count: 1,
        plane_stride: 0,
        cache_status: None,
        master_lock: None,
        broadcast: None,
        groups,
    }
}

const fn m1_ioa(apertures: &'static [u64]) -> MemoryController {
    MemoryController {
        master_lock: Some(bit(0)),
        ..ioa(apertures, 0x4000, &M1_IOA)
    }
}

const T8112: MemoryController = amcc(&[0x2_0000_0000], 0xf4_0000, 4, bit(0x424), &T8112_AMCC);

// J314s builder 0x385e4..0x38a6c: one die, four MCCs (not T6001/2's
// eight), each a 2 MiB lock aperture in its 16 MiB MCC register window.
// Kind 0xc0 is broadcast at 0x10000c (0x3862c), kind 0xc1 cache-status
// at 0x1c00 with mask 0x1f/value 0 (0x38660), as on the other M1 parts.
const T6000: MemoryController = m1_amcc(
    &[0x2_0000_0000, 0x2_0100_0000, 0x2_0200_0000, 0x2_0300_0000],
    0x20_0000,
);

// J314s builder 0x38aa4..0x38d10. A single plane needs no stride. The
// original template exposes only IOA-A. iBoot names the (0, 1, 1) register
// master-lock (kind 0xc2, builder 0x38ae4), not broadcast.
const T6000_IOA: MemoryController = MemoryController {
    apertures: &[0x2_8200_0000, 0x3_0400_0000, 0x3_8300_0000, 0x4_0200_0000],
    aperture_size: 0x4000,
    plane_count: 1,
    plane_stride: 0,
    cache_status: None,
    master_lock: Some(bit(0)),
    broadcast: None,
    groups: &[LockGroup::new(
        "ioa-ctrr-a",
        PROGRAMMED,
        0x220,
        0x224,
        0x228,
    )],
};

/// The M5 and M6 AMCC: one aperture.
const M5_AMCC: MemoryController = amcc(&[0x2_2000_0000], 0x14_0000, 4, bit(0x82c), &T6040_AMCC);

/// A T6050 AMCC: one aperture per enabled MCC.
const fn t6050_amcc(apertures: &'static [u64]) -> MemoryController {
    amcc(apertures, 0x14_0000, 4, bit(0x82c), &T6040_AMCC)
}

/// The unbinned Max's AMCC, and one die's IOA.
const T6050_MAX: MemoryController = t6050_amcc(&[
    0x22_2000_0000,
    0x22_2200_0000,
    0x22_2400_0000,
    0x22_2600_0000,
    0x22_2800_0000,
    0x22_2a00_0000,
    0x22_2c00_0000,
    0x22_2e00_0000,
]);
const T6050_IOA: MemoryController = ioa(
    &[
        0x2_a002_0000,
        0x2_a802_0000,
        0x3_8002_0000,
        0x3_8802_0000,
        0x4_1602_0000,
        0x4_8602_0000,
    ],
    0x1_0000,
    &M4_IOA,
);

/// The T6050's maps by the `/:sotra` variant its fuses select
/// ([`crate::soc_variant`]). Builder `iBoot.j714s` `0x3cdc8` places an AMCC
/// aperture at `0x22_2000_0000 + 0x200_0000 * n` for each MCC `n` the MCC
/// bring-up (`0x7b81c`) enabled, and six IOA apertures per die; the second
/// die's are `0x40_0000_0000` above the first's (die index shifted to bit
/// 38). Emulating the builder with each variant's fuses gives these lists.
#[rustfmt::skip]
pub const T6050_VARIANTS: [(&str, MemoryController, MemoryController); 5] = [
    ("h17s", t6050_amcc(&[0x22_2000_0000, 0x22_2200_0000, 0x22_2400_0000, 0x22_2600_0000]), T6050_IOA),
    ("h17c", T6050_MAX, T6050_IOA),
    ("h17cr1", t6050_amcc(&[0x22_2000_0000, 0x22_2200_0000, 0x22_2400_0000, 0x22_2600_0000, 0x22_2800_0000, 0x22_2a00_0000]), T6050_IOA),
    ("h17cr2", t6050_amcc(&[0x22_2000_0000, 0x22_2200_0000, 0x22_2800_0000, 0x22_2a00_0000, 0x22_2c00_0000, 0x22_2e00_0000]), T6050_IOA),
    (
        "h17d",
        t6050_amcc(&[
            0x22_2000_0000, 0x22_2200_0000, 0x22_2400_0000, 0x22_2600_0000, 0x22_2800_0000, 0x22_2a00_0000, 0x22_2c00_0000, 0x22_2e00_0000,
            0x62_2000_0000, 0x62_2200_0000, 0x62_2400_0000, 0x62_2600_0000, 0x62_2800_0000, 0x62_2a00_0000, 0x62_2c00_0000, 0x62_2e00_0000,
        ]),
        ioa(&[
            0x2_a002_0000, 0x2_a802_0000, 0x3_8002_0000, 0x3_8802_0000, 0x4_1602_0000, 0x4_8602_0000,
            0x42_a002_0000, 0x42_a802_0000, 0x43_8002_0000, 0x43_8802_0000, 0x44_1602_0000, 0x44_8602_0000,
        ], 0x1_0000, &M4_IOA),
    ),
];

/// The SoCs one iBoot lock-register description covers.
pub struct Family {
    pub chips: &'static [u32],
    pub amcc: MemoryController,
    pub ioa: Option<MemoryController>,
}

/// Every SoC's description, as its iBoot's `harr` builder makes it
/// (docs/research/iboot-handoff.md, "Memory-controller lock registers").
#[rustfmt::skip]
pub const FAMILIES: [Family; 20] = [
    Family { chips: &[0x8103], amcc: m1_amcc(&[0x2_0000_0000], 0x10_4000), ioa: None },
    Family { chips: &[0x6000], amcc: T6000, ioa: Some(T6000_IOA) },
    Family {
        chips: &[0x6001],
        amcc: m1_amcc(&[0x2_0000_0000, 0x2_0100_0000, 0x2_0200_0000, 0x2_0300_0000, 0x2_0400_0000, 0x2_0500_0000, 0x2_0600_0000, 0x2_0700_0000], 0x20_0000),
        ioa: Some(m1_ioa(&[0x2_8200_0000, 0x3_0400_0000, 0x3_8300_0000, 0x4_0200_0000, 0x4_8200_0000, 0x5_0200_0000])),
    },
    Family {
        chips: &[0x6002],
        amcc: m1_amcc(&[
            0x2_0000_0000, 0x2_0100_0000, 0x2_0200_0000, 0x2_0300_0000, 0x2_0400_0000, 0x2_0500_0000, 0x2_0600_0000, 0x2_0700_0000,
            0x22_0700_0000, 0x22_0600_0000, 0x22_0500_0000, 0x22_0400_0000, 0x22_0300_0000, 0x22_0200_0000, 0x22_0100_0000, 0x22_0000_0000,
        ], 0x20_0000),
        ioa: Some(m1_ioa(&[
            0x2_8200_0000, 0x3_0400_0000, 0x3_8300_0000, 0x4_0200_0000, 0x4_8200_0000, 0x5_0200_0000,
            0x22_8200_0000, 0x23_0400_0000, 0x23_8300_0000, 0x24_0200_0000, 0x24_8200_0000, 0x25_0200_0000,
        ])),
    },
    Family { chips: &[0x8112], amcc: T8112, ioa: None },
    Family {
        chips: &[0x6020],
        amcc: amcc(&[0x2_0000_0000, 0x2_0100_0000, 0x2_0200_0000, 0x2_0300_0000], 0x20_0000, 4, CACHE_CLEAR, &T6020_AMCC),
        ioa: Some(ioa(&[0x2_8000_0000, 0x3_0000_0000, 0x3_4000_0000, 0x3_8000_0000, 0x4_0000_0000], 0x4000, &M2_IOA)),
    },
    Family {
        chips: &[0x6021],
        amcc: amcc(&[0x2_0000_0000, 0x2_0100_0000, 0x2_0200_0000, 0x2_0300_0000, 0x2_0400_0000, 0x2_0500_0000, 0x2_0600_0000, 0x2_0700_0000], 0x20_0000, 4, CACHE_CLEAR, &T6020_AMCC),
        ioa: Some(ioa(&[0x2_8000_0000, 0x3_0000_0000, 0x3_4000_0000, 0x3_8000_0000, 0x4_0000_0000, 0x4_8000_0000, 0x5_0000_0000], 0x4000, &M2_IOA)),
    },
    Family {
        chips: &[0x6022],
        amcc: amcc(&[
            0x2_0000_0000, 0x2_0100_0000, 0x2_0200_0000, 0x2_0300_0000, 0x2_0400_0000, 0x2_0500_0000, 0x2_0600_0000, 0x2_0700_0000,
            0x22_0700_0000, 0x22_0600_0000, 0x22_0500_0000, 0x22_0400_0000, 0x22_0300_0000, 0x22_0200_0000, 0x22_0100_0000, 0x22_0000_0000,
        ], 0x20_0000, 4, CACHE_CLEAR, &T6020_AMCC),
        ioa: Some(ioa(&[
            0x2_8000_0000, 0x3_0000_0000, 0x3_4000_0000, 0x3_8000_0000, 0x4_0000_0000, 0x4_8000_0000, 0x5_0000_0000,
            0x22_8000_0000, 0x23_0000_0000, 0x23_4000_0000, 0x23_8000_0000, 0x24_0000_0000, 0x24_8000_0000, 0x25_0000_0000,
        ], 0x4000, &M2_IOA)),
    },
    Family {
        chips: &[0x8122],
        amcc: amcc(&[0x2_2000_0000, 0x2_2200_0000], 0x20_0000, 2, CACHE_CLEAR, &T8122_AMCC),
        ioa: Some(ioa(&[0x2_8000_0000, 0x3_0000_0000], 0x4000, &M2_IOA)),
    },
    Family {
        chips: &[0x6030],
        amcc: amcc(&[0x2_2000_0000, 0x2_2200_0000], 0x20_0000, 3, CACHE_CLEAR, &T6030_AMCC),
        ioa: Some(ioa(&[0x2_8000_0000, 0x2_c000_0000, 0x3_0000_0000, 0x3_8000_0000], 0x4000, &M2_IOA)),
    },
    Family {
        chips: &[0x6031],
        amcc: amcc(&[0x2_2000_0000, 0x2_2200_0000, 0x2_2400_0000, 0x2_2600_0000, 0x2_2800_0000, 0x2_2a00_0000, 0x2_2c00_0000, 0x2_2e00_0000], 0x20_0000, 4, CACHE_CLEAR, &T6031_AMCC),
        ioa: Some(ioa(&[0x2_8000_0000, 0x2_c000_0000, 0x3_0000_0000, 0x3_4000_0000, 0x3_8000_0000, 0x3_c000_0000, 0x4_0000_0000, 0x4_4000_0000], 0x4000, &M2_IOA)),
    },
    Family {
        chips: &[0x6034],
        amcc: amcc(&[0x2_2000_0000, 0x2_2200_0000, 0x2_2400_0000, 0x2_2600_0000, 0x2_2800_0000, 0x2_2a00_0000], 0x20_0000, 4, CACHE_CLEAR, &T6031_AMCC),
        ioa: Some(ioa(&[0x2_8000_0000, 0x2_c000_0000, 0x3_0000_0000, 0x3_4000_0000, 0x3_8000_0000, 0x3_c000_0000, 0x4_0000_0000, 0x4_4000_0000], 0x4000, &M2_IOA)),
    },
    Family {
        chips: &[0x6032],
        amcc: amcc(&[
            0x2_2000_0000, 0x2_2200_0000, 0x2_2400_0000, 0x2_2600_0000, 0x2_2800_0000, 0x2_2a00_0000, 0x2_2c00_0000, 0x2_2e00_0000,
            0x22_2000_0000, 0x22_2200_0000, 0x22_2400_0000, 0x22_2600_0000, 0x22_2800_0000, 0x22_2a00_0000, 0x22_2c00_0000, 0x22_2e00_0000,
        ], 0x20_0000, 4, CACHE_CLEAR, &T6031_AMCC),
        ioa: Some(ioa(&[
            0x2_8000_0000, 0x2_c000_0000, 0x3_0000_0000, 0x3_4000_0000, 0x3_8000_0000, 0x3_c000_0000, 0x4_0000_0000, 0x4_4000_0000,
            0x22_8000_0000, 0x22_c000_0000, 0x23_0000_0000, 0x23_4000_0000, 0x23_8000_0000, 0x23_c000_0000, 0x24_0000_0000, 0x24_4000_0000,
        ], 0x4000, &M2_IOA)),
    },
    Family {
        chips: &[0x8132],
        amcc: amcc(&[0x2_2000_0000, 0x2_2200_0000], 0x20_0000, 2, CACHE_CLEAR, &T8132_AMCC),
        ioa: Some(ioa(&[0x4_0002_0000, 0x4_0802_0000, 0x4_1002_0000, 0x4_1802_0000, 0x4_9602_0000], 0x4000, &M4_IOA)),
    },
    Family {
        chips: &[0x6040],
        amcc: amcc(&[0x2_2000_0000, 0x2_2200_0000, 0x2_2400_0000, 0x2_2600_0000], 0x20_0000, 4, bit(0x82c), &T6040_AMCC),
        ioa: Some(ioa(&[0x3_8002_0000, 0x3_8802_0000, 0x3_9002_0000, 0x3_9802_0000, 0x4_1602_0000], 0x4000, &M4_IOA)),
    },
    Family {
        chips: &[0x6041],
        amcc: amcc(&[0x2_2000_0000, 0x2_2200_0000, 0x2_2400_0000, 0x2_2600_0000, 0x2_2800_0000, 0x2_2a00_0000, 0x2_2c00_0000, 0x2_2e00_0000], 0x20_0000, 4, bit(0x82c), &T6040_AMCC),
        ioa: Some(ioa(&[0x3_8002_0000, 0x3_8802_0000, 0x3_9002_0000, 0x3_9802_0000, 0x4_1602_0000], 0x4000, &M4_IOA)),
    },
    Family { chips: &[0x8140], amcc: M5_AMCC, ioa: Some(ioa(&[0x3_9602_0000], 0x4000, &M4_IOA)) },
    Family {
        chips: &[0x8142],
        amcc: M5_AMCC,
        ioa: Some(ioa(&[0x4_0002_0000, 0x4_0802_0000, 0x4_1002_0000, 0x4_1802_0000, 0x4_8e02_0000], 0x4000, &M4_IOA)),
    },
    Family { chips: &[0x6050], amcc: T6050_MAX, ioa: Some(T6050_IOA) },
    Family {
        chips: &[0x8152],
        amcc: M5_AMCC,
        ioa: Some(ioa(&[0x4_0002_0000, 0x4_0802_0000, 0x3_8002_0000, 0x4_1002_0000, 0x3_8e02_0000], 0x4000, &M4_IOA)),
    },
];

fn family(chip_id: u32) -> Option<&'static Family> {
    FAMILIES
        .iter()
        .find(|family| family.chips.contains(&chip_id))
}

/// The maps of a SoC whose iBoot sizes them by the fused `variant`
/// ([`crate::soc_variant`]).
fn variant(
    chip_id: u32,
    variant: Option<&str>,
) -> Option<&'static (&'static str, MemoryController, MemoryController)> {
    (chip_id == crate::soc_variant::CHIP_ID)
        .then(|| T6050_VARIANTS.iter().find(|row| Some(row.0) == variant))
        .flatten()
}

/// iBoot's AMCC map for the SoC with `chip_id` and, where its fuses size
/// it, `fused` variant; `None` for a SoC whose iBoot has not been read.
pub fn table(chip_id: u32, fused: Option<&str>) -> Option<&'static MemoryController> {
    match variant(chip_id, fused) {
        Some((_, amcc, _)) => Some(amcc),
        None => family(chip_id).map(|family| &family.amcc),
    }
}

/// iBoot's IOA map for the SoC with `chip_id` and `fused` variant, which
/// never reuses the AMCC's.
pub fn ioa_table(chip_id: u32, fused: Option<&str>) -> Option<&'static MemoryController> {
    match variant(chip_id, fused) {
        Some((_, _, ioa)) => Some(ioa),
        None => family(chip_id)?.ioa.as_ref(),
    }
}

fn u32_value(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn set_register(tree: &mut DeviceTree, path: &str, name: &str, register: Register) -> Result<()> {
    tree.set_property(
        path,
        &format!("{name}-reg-offset"),
        u32_value(register.offset),
    )?;
    tree.set_property(path, &format!("{name}-reg-mask"), u32_value(register.mask))?;
    if let Some(value) = register.value {
        tree.set_property(path, &format!("{name}-reg-value"), u32_value(value))?;
    } else {
        tree.node_mut(path)
            .ok_or(refuse!("lock-register node disappeared"))?
            .remove_property(&format!("{name}-reg-value"));
    }
    Ok(())
}

fn set_optional_register(
    tree: &mut DeviceTree,
    path: &str,
    name: &str,
    register: Option<Register>,
) -> Result<()> {
    if let Some(register) = register {
        return set_register(tree, path, name, register);
    }
    let node = tree
        .node_mut(path)
        .ok_or(refuse!("lock-register node disappeared"))?;
    for suffix in ["offset", "mask", "value"] {
        node.remove_property(&format!("{name}-reg-{suffix}"));
    }
    Ok(())
}

/// Writes the map into the template's `/chosen/lock-regs/amcc` and its group
/// nodes, as iBoot does; `false` when the template has no such node.
pub fn publish(tree: &mut DeviceTree, controller: &MemoryController) -> Result<bool> {
    publish_controller(tree, AMCC, controller)
}

/// The same for `/chosen/lock-regs/ioa`, which only the M1 Pro to M3 Max
/// templates carry.
pub fn publish_ioa(tree: &mut DeviceTree, controller: &MemoryController) -> Result<bool> {
    publish_controller(tree, IOA, controller)
}

/// iBoot's publisher fills only the nodes the template carries (J473
/// `0x126f34`; J314s `0x137aa4` looks each group up with existing-child
/// lookup `0xe0840` and skips a missing one at `0x137b28`): a group it
/// describes without a node stays unpublished, and a node it does not fill
/// stays empty.
fn publish_controller(
    tree: &mut DeviceTree,
    path: &str,
    controller: &MemoryController,
) -> Result<bool> {
    if tree.node(path).is_none() {
        return Ok(false);
    }
    let count = controller.apertures.len() as u32;
    tree.set_property(path, "aperture-count", u32_value(count))?;
    tree.set_property(path, "aperture-size", u32_value(controller.aperture_size))?;
    let addresses = controller
        .apertures
        .iter()
        .flat_map(|address| address.to_le_bytes())
        .collect();
    tree.set_property(path, "aperture-phys-addr", addresses)?;
    tree.set_property(path, "plane-count", u32_value(controller.plane_count))?;
    tree.set_property(path, "plane-stride", u32_value(controller.plane_stride))?;
    for (name, register) in [
        ("cache-status", controller.cache_status),
        ("master-lock", controller.master_lock),
        ("broadcast", controller.broadcast),
    ] {
        set_optional_register(tree, path, name, register)?;
    }
    for group in controller.groups {
        let path = format!("{path}/{}", group.name);
        if tree.node(&path).is_none() {
            continue;
        }
        tree.set_property(&path, "page-size-shift", u32_value(group.page_size_shift))?;
        for (name, register) in [
            ("lower-limit", Some(group.lower_limit)),
            ("upper-limit", Some(group.upper_limit)),
            ("enable", group.enable),
            ("write-disable", group.write_disable),
            ("lock", group.lock),
        ] {
            set_optional_register(tree, &path, name, register)?;
        }
    }
    Ok(true)
}

/// The CTRR-A region iBoot programs: `[start, end)`, which must be whole
/// pages of the group above `dram_base`.
pub fn ctrr_a(
    controller: &MemoryController,
    dram_base: u64,
    start: u64,
    end: u64,
) -> Result<Programmed> {
    let group = controller
        .groups
        .iter()
        .find(|group| group.name == "amcc-ctrr-a")
        .ok_or(refuse!("the AMCC map has no amcc-ctrr-a"))?;
    let page = 1u64 << group.page_size_shift;
    require!(
        dram_base <= start
            && start < end
            && start.is_multiple_of(page)
            && end.is_multiple_of(page)
            && (end - dram_base) >> group.page_size_shift <= u64::from(group.upper_limit.mask),
        "CTRR-A region {start:#x}..{end:#x} is not whole {page:#x}-byte pages above {dram_base:#x}",
        start,
        end,
        page,
        dram_base
    );
    Ok(Programmed {
        group: group.name.into(),
        base: start,
        bytes: end - start,
    })
}

/// The page iBoot publishes in place of an absent CL4 image.
pub const CL4_DUMMY_PAGE: &str = "CL4-dummypage";
pub const CL4_DUMMY_PAGE_BYTES: usize = 0x4000;
/// `wfi`, the word iBoot fills it with.
const WFI: u32 = 0xd503_207f;

/// The dummy page's contents.
pub fn cl4_dummy_page() -> Vec<u8> {
    WFI.to_le_bytes()
        .repeat(CL4_DUMMY_PAGE_BYTES / size_of::<u32>())
}

/// What iBoot leaves in the core lock registers on the M4 and later, from
/// the placed regions (`region` gives one's `[start, end)`): each region
/// SPTM 26A434 derives (`0x...bebec..0x...bed5c` in the T8132 build), locked
/// into the per-cluster copies, CTRR-D only when `kernel_ctrr`
/// (`/chosen kernel-ctrr-to-be-enabled` is not a present 0), and CTRR-A/B's
/// controls locked, with `tag_offset` (`stela_engine::machine::tag_storage`).
pub fn core_handoff(
    region: impl Fn(&str) -> Option<Range<u64>>,
    kernel_ctrr: bool,
    tag_offset: u64,
) -> Result<CoreLocks> {
    let either = |name: &'static str, fallback: &'static str| {
        if region(name).is_some() {
            name
        } else {
            fallback
        }
    };
    let span = |first: &str, last: &str| -> Result<(u64, u64)> {
        let start = region(first)
            .ok_or_else(|| refuse!("no region {first}", first))?
            .start;
        let end = region(last)
            .ok_or_else(|| refuse!("no region {last}", last))?
            .end;
        require!(start < end, "{first}..{last} is empty", first, last);
        Ok((start, end - 1))
    };
    let secure_kernel = either("CL4-rx", CL4_DUMMY_PAGE);
    let kernel_text = either("AuxKC-rx", "BootKC-rx");
    let mut spans = alloc::vec![
        (
            LockRegion::CtrrC,
            span(either("CL4-rx", "DeviceTree"), "SPTM-rx")?
        ),
        (LockRegion::CtxrA, span("SPTM-rx", "SPTM-rx")?),
        (LockRegion::CtxrB, span(secure_kernel, secure_kernel)?),
        (LockRegion::CtxrC, span("TXM-rx", "TXM-bx")?),
        (LockRegion::CtxrD, span(kernel_text, "BootKC-bx")?),
    ];
    if kernel_ctrr {
        spans.push((LockRegion::CtrrD, span("TXM-ro", "BootKC-rs")?));
    }
    Ok(CoreLocks {
        locked: spans
            .into_iter()
            .map(|(region, (first, last))| Locked {
                region,
                first,
                last,
            })
            .collect(),
        legacy_locked: true,
        tag_offset,
    })
}

/// What the bundle leaves out of iBoot's lock-register setup.
pub fn gaps(chip_id: Option<u32>) -> Vec<String> {
    match chip_id.and_then(|chip| table(chip, None)) {
        Some(_) => Vec::new(),
        None => alloc::vec![format!(
            "{AMCC}: no iBoot AMCC map for this SoC; SPTM's CTRR lockdown cannot find it"
        )],
    }
}

#[cfg(test)]
pub(crate) mod tests;
