//! Apple SoCs: a board's chip and PEs from its DeviceTree.
//!
//! The board's DeviceTree gives the SoC: `/chosen` `chip-id` (the identity's
//! ApChipID, which the boot bundle writes there as iBoot does), `/product`
//! `product-soc-name`, and one `/cpus` node per PE with `reg` and
//! `cluster-type`. Each SoC row pairs an ApChipID with the
//! `product-soc-name` its boards' DeviceTrees give in UniversalMac 26A434 and
//! the MIDR_EL1 part number of each cluster type (m1n1 `src/midr.h`
//! `MIDR_PART_<soc>_<core>`; for the Ultras, the parts of the Max dies they
//! join, and for the second M3 Max and the M3 Ultra an inference stated at
//! their rows). A SoC, cluster type or affinity without that evidence
//! refuses: the A18 Pro, which no `machine::Chip` profile describes, the
//! T6050 (no `product-soc-name`) and its M cores.
use super::{
    Chip,
    adt::Node,
    caches::{Cache, Caches},
    registers::Identity,
};
use crate::platform::apple::{
    agx,
    aic::{AIC3_IRQ_CFG, AicLayout},
    aic1::AIC1_EVENT,
    amcc, ans, asc, atc_phy, bridge, cluster, core_counters, coresight, cpm, cpustart, dart, dcp,
    dpe, energy, fuse, gpio, i2c, nor, pmu, power, ptd, sart, smc, spi, spmi, wake,
};
use alloc::{format, string::String, vec::Vec};

mod dart_topology;
#[cfg(test)]
use dart_topology::iommu;
use dart_topology::iommus;

mod handoff;
mod memory_resources;
pub use memory_resources::DirectMemoryCache;
mod power_resources;
mod topology;
pub use handoff::{
    BOOT_CLOCK_HZ, CHIP_REVISION, Carveout, DRAM_VENDOR, DramVendor, Evidence, HANDOFF_REGION,
    Handoff, IBOOT_PAGE_BYTES, PANIC_REGION_BYTES, PANIC_REGION_ID, PANIC_WINDOW_BYTES,
    PANIC_WINDOW_MEMBERS, SOCD_TRACE_KEYS, USB_PHY_HZ, handoff,
};
#[cfg(test)]
use power_resources::PMGR_VIRTUAL;
use power_resources::{PMGR_DEVICE, power_states};
pub use power_resources::{PowerOwner, PowerResource, PowerStates, ProcessorAssociation};
pub use topology::assigned;

/// One SoC row: ApChipID, `product-soc-name`, chip, the MIDR_EL1 part
/// number of each `cluster-type`, and the `aic` node's `compatible` with the
/// offset of its event register from its `reg`: for the M1's `aic,1` the
/// event register in its core block (Linux `AIC_EVENT`, 0x2004), and for an
/// `aic,2` or `aic,3` the separate block Linux `arch/arm64/boot/dts/apple`
/// places (0x8000 in `t8112.dtsi`, 0xc000 in `t600x-die0.dtsi` and
/// `t602x-die0.dtsi`, 0x40000 in `t8122.dtsi`). The SoCs whose AIC no public
/// DeviceTree places have none. `dram_base` is where the
/// SoC places DRAM (the `memory@` node of Linux `t8103-jxxx.dtsi`,
/// `t8112-jxxx.dtsi`, `t600x-j314-j316.dtsi` and `t600x-j375.dtsi`, which the
/// t602x boards include); the SoCs without a public memory node have none,
/// and their boards state it in their DeviceTree ([`board_dram_base`]).
/// `pmgr` is the `compatible` of the SoC's `/arm-io/pmgr` in its boards'
/// DeviceTrees (`isa/apple-soc-facts.json` `boards[].pmgr`), modeled once
/// the row has its clusters and bridge layouts ([`Soc::pmgr_modeled`]).
/// `lockdown` is
/// the CONTROL offset of the lockdown registers in each PE's `cpu-impl-reg`
/// and each cluster's `cpm-impl-reg` (`platform::apple::lockdown`), on the
/// SoCs whose SPTM writes them ([`LOCKDOWN`]); the M4 and later SPTMs write
/// none, so their boards map no lockdown block.
/// `operating_points` is each cluster type's core clocks in MHz, lowest
/// first, in each [`CoreType`]: the opp tables of Linux
/// `arch/arm64/boot/dts/apple/t8112.dtsi` (`ecluster_opp`, `pcluster_opp`)
/// and the other files [`M1_POINTS`] names, including the P states they
/// leave disabled until CPU deep sleep. The highest paces the
/// cycle counter of Apple's performance monitor (`machine::pmu`), and the
/// bundle publishes them as iBoot's `voltage-states` tables, which the IPSW
/// DeviceTree leaves to it; the SoCs without that evidence have none. `memory_cache` is the memory
/// cache's bytes and ways: the defaults the T8112's 26A434
/// `AppleT8112MemCacheController` driver starts from (`start` assumes 8 MiB
/// before `readCacheSize`; `mccEnableCacheMode` powers at most 16 ways).
/// `clusters` is each cluster type's PMGR registers
/// (`platform::apple::cluster`), in E/P order on the T8112, where known, and
/// `aon_fuses` the `/arm-io/pmgr` `reg` index of the always-on eFuses
/// (`platform::apple::fuse`): the T8112's 26A434 `ApplePMGR::
/// readPMGRAONFuseReg` reads `reg[36]`. `cpu_start` is the offset of the
/// CPU start registers (`platform::apple::cpustart`) from `/arm-io/pmgr`
/// `reg[0]` ([`CPU_START_T8112`] and its siblings). Each [`CoreType`] also
/// holds its cache geometry ([`CoreCaches`]), where known.
struct Soc {
    chip_id: u32,
    name: &'static str,
    pmgr: &'static str,
    chip: Chip,
    cores: &'static [CoreType],
    aic: Option<(&'static str, u64)>,
    dram_base: Option<u64>,
    lockdown: Option<[u64; 2]>,
    memory_cache: Option<(u64, u32)>,
    clusters: Option<[CpuCluster; 2]>,
    aon_fuses: Option<usize>,
    cpu_start: Option<u64>,
    wake_masks: Option<WakeLayout>,
    power_banks: &'static [(usize, power::Kind)],
    dpe_reg: Option<usize>,
    bridge_fields: Option<&'static [&'static [(u64, u32)]]>,
}

/// One observed core type's CPU-identity requirements, independent of its
/// physical cluster. Missing values are unknown requirements, never an
/// invitation to inherit another core type's capabilities.
#[derive(Debug, Clone, Copy)]
pub struct CoreType {
    pub cluster_type: u8,
    pub midr_part: Option<u16>,
    pub mpidr_aff2: Option<u8>,
    pub operating_points: Option<&'static [u32]>,
    caches: Option<CoreCaches>,
}

impl CoreType {
    /// Compose the established MPIDR identity independently of the MIDR,
    /// caches and clocks that a complete PE profile also requires. `reg`
    /// retains the physical cluster/core coordinates; core type never
    /// creates another physical cluster. Returns `None` for an unknown
    /// mapping, out-of-field core type or undeclared `reg` bits.
    pub fn mpidr(&self, reg: u32) -> Option<u64> {
        // XNU xnu-12377.121.6 apple_arm64_regs.h:102–107 defines
        // MPIDR_CORETYPE at bits 18:16, E=0, P=1, M=4.
        const CORETYPE_MASK: u8 = 7;
        const CORETYPE_SHIFT: u32 = 16;
        let aff2 = self.mpidr_aff2?;
        if aff2 & !CORETYPE_MASK != 0 || reg & !MPIDR_CLUSTER_CORE != 0 {
            return None;
        }
        Some(0x8000_0000 | u64::from(aff2) << CORETYPE_SHIFT | u64::from(reg))
    }
}

#[derive(Debug, Clone, Copy)]
struct WakeLayout {
    reg: usize,
    valid: [u32; wake::WORDS],
}

/// A cluster type's level 1 caches and its level 2's associativity; the
/// level 2's capacity is each `/cpus` node's `l2-cache-size`. The T8112's
/// capacities are the `i-cache-size` and `d-cache-size` of the cpu nodes of
/// Linux `arch/arm64/boot/dts/apple/t8112.dtsi`, whose `l2-cache` nodes
/// agree with the J473AP DeviceTree's `l2-cache-size`; its lines are 128
/// bytes, the `hw.cachelinesize` macOS reports on Apple silicon, which XNU
/// takes from the level 1 data cache's CCSIDR_EL1. The associativities
/// are inferred: no public capture gives them, and XNU reads only the line
/// length and the capacities they multiply to (`machine::caches`).
#[derive(Debug, Clone, Copy)]
struct CoreCaches {
    instruction: Cache,
    data: Cache,
    unified_ways: u32,
}

/// Apple's 128-byte cache lines.
const LINE: u32 = 128;

const fn cache(bytes: u32, ways: u32) -> Cache {
    Cache {
        bytes,
        ways,
        line: LINE,
    }
}

/// The level 1 caches of every SoC row's E and P cores: 128 KiB instruction
/// and 64 KiB data caches on E cores, 192 KiB and 128 KiB on P cores.
///
/// - Known (Linux `arch/arm64/boot/dts/apple`): the M1, M1 Pro and Max
///   (Icestorm and Firestorm: `t8103.dtsi`, `t600x-common.dtsi`), the M2 and
///   M2 Pro and Max (Blizzard and Avalanche: `t8112.dtsi`,
///   `t602x-common.dtsi`) and the M3 (Sawtooth and Everest: `t8122.dtsi`).
/// - Known (published `sysctl hw.perflevel*` of real machines, gist
///   chockenberry/1d08129bdf41bfb70e98c3a75ce74578): the M4 Max and the M5
///   report these `l1icachesize` and `l1dcachesize` values per core type,
///   with the `l2cachesize` values their boards' 26A434 DeviceTrees state.
/// - Inferred: the M3 Pro and Max, the M4 and M4 Pro and the M6, whose
///   26A434 DeviceTrees give their cores the same `apple,sawtooth` and
///   `apple,everest` compatibles as the M3, M4 Max and M5 cores above.
///   This inference applies only to the declared E/P descriptors; the M6
///   M type has no inferred cache geometry.
const L1_CACHES: [CoreCaches; 2] = [
    CoreCaches {
        instruction: cache(128 << 10, 8),
        data: cache(64 << 10, 8),
        unified_ways: 16,
    },
    CoreCaches {
        instruction: cache(192 << 10, 6),
        data: cache(128 << 10, 8),
        unified_ways: 16,
    },
];

/// Established E/P identities and cache geometries used by the existing
/// profiles. Other core types must supply their own explicit descriptor.
const fn ep_cores(e_part: u16, p_part: u16, points: Option<[&'static [u32]; 2]>) -> [CoreType; 2] {
    [
        CoreType {
            cluster_type: b'E',
            midr_part: Some(e_part),
            mpidr_aff2: Some(0),
            operating_points: match points {
                Some(points) => Some(points[0]),
                None => None,
            },
            caches: Some(L1_CACHES[0]),
        },
        CoreType {
            cluster_type: b'P',
            midr_part: Some(p_part),
            mpidr_aff2: Some(1),
            operating_points: match points {
                Some(points) => Some(points[1]),
                None => None,
            },
            caches: Some(L1_CACHES[1]),
        },
    ]
}

/// Original J873GAP has six E cores and one mixed P2/M4 physical cluster.
/// The historical per-cluster census copied the first PE's P type. The
/// fresh per-PE ledger `isa/apple-board-interfaces.json` retains all types.
/// XNU's M_CORE identity establishes Aff2=4; its MIDR part, L1 geometry
/// and clock requirements remain unestablished.
const M6_CORES: [CoreType; 3] = [
    ep_cores(0x072, 0x073, None)[0],
    ep_cores(0x072, 0x073, None)[1],
    CoreType {
        cluster_type: b'M',
        midr_part: None,
        mpidr_aff2: Some(4),
        operating_points: None,
        caches: None,
    },
];

/// One CPU cluster's PMGR registers (`platform::apple::cluster`): their
/// base, the performance-state slots the boot firmware fills and the DVMR
/// weight tables it programs, as `(offset, value)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuCluster {
    pub base: u64,
    pub pstates: usize,
    /// Driver capacity at kernel file 0x2b67d80; DT carries no count.
    pub counter_capacity: usize,
    pub counter_map: bool,
    pub dvmr: &'static [(u64, u64)],
}

/// The T8112 clusters. The 26A434 J473AP iBoot's native register lists
/// program the DVMR tables: the E cluster's common list `0x17dd70`
/// (descriptors `0x17ce28`, `0x17ce48`, `0x17ce58` and `0x17ce68`), the P
/// cluster's common list `0x181f18` (`0x17f7f0`, `0x17f800`) and its
/// revision 0 list `0x1825d8` (`0x17f810` to `0x17f850`), revision 0 being
/// the `/arm-io` `chip-revision` the DeviceTree hands off. `0x206b8` keeps
/// only the bits its descriptor masks, `0x4000003700000fff` (E) and
/// `0x4000003780000fff` (P), with DVMR (bit 63) left for `enableDVMR` to
/// set. iBoot's state captures span 16 E and 18 P performance-state slots.
const T8112_CLUSTERS: [CpuCluster; 2] = [
    CpuCluster {
        base: 0x2_10e0_0000,
        pstates: 16,
        counter_capacity: 16,
        counter_map: false,
        dvmr: &[
            (0x206a8, 0x4444_4433_3322_2110),
            (0x206b8, 0x4000_0037_0000_0321),
            (0x206e0, 0x6666_6655_5544_4333),
            (0x206f0, 0x6666_6655_5544_4333),
        ],
    },
    CpuCluster {
        base: 0x2_11e0_0000,
        pstates: 18,
        counter_capacity: 16,
        counter_map: true,
        dvmr: &[
            (0x206a8, 0x5555_5544_4433_3110),
            (0x206b0, 0xcccc_ccaa_aa88_8776),
            (0x206b8, 0x4000_0037_8000_0531),
            (0x206e0, 0xaaaa_aa88_8877_7666),
            (0x206e8, 0xeeee_eecc_ccaa_a886),
            (0x206f0, 0xaaaa_aa88_8877_7666),
            (0x206f8, 0xeeee_eecc_ccaa_a886),
        ],
    },
];

/// The CONTROL offsets of the lockdown pairs in `cpu-impl-reg` and
/// `cpm-impl-reg` that every SPTM from the M1 to the M3 families writes
/// (`isa/apple-soc-facts.json` `socs[].lockdown`; the T8112's at
/// `__text+0x1b0e4..0x1b14c`). The M4 and later SPTMs write none.
const LOCKDOWN: [u64; 2] = [0x5000, 0x9000];

/// The CPU start registers' offsets from `/arm-io/pmgr` `reg[0]`, m1n1
/// `src/smp.c` `CPU_START_OFF_*` and the chips its `smp_init` gives each.
const CPU_START_T8103: u64 = 0x54000;
const CPU_START_T8112: u64 = 0x34000;
const CPU_START_T6020: u64 = 0x28000;
const CPU_START_T6031: u64 = 0x88000;

/// Operating points in MHz from Linux `arch/arm64/boot/dts/apple`, each
/// cluster type lowest first with the P states the files leave disabled
/// until CPU deep sleep: `t8103.dtsi` (`ecluster_opp`, `pcluster_opp`),
/// `t600x-common.dtsi` (`icestorm_opp`, `firestorm_opp`) and
/// `t602x-common.dtsi` (`blizzard_opp`, whose "pstate #1 is a dummy clone of
/// #2", and `avalanche_opp`).
const M1_POINTS: [&[u32]; 2] = [
    &[600, 972, 1332, 1704, 2064],
    &[
        600, 828, 1056, 1284, 1500, 1728, 1956, 2184, 2388, 2592, 2772, 2988, 3096, 3144, 3204,
    ],
];
const M1_PRO_POINTS: [&[u32]; 2] = [
    &[600, 972, 1332, 1704, 2064],
    &[
        600, 828, 1056, 1296, 1524, 1752, 1980, 2208, 2448, 2676, 2904, 3036, 3132, 3168, 3228,
    ],
];
const M2_PRO_POINTS: [&[u32]; 2] = [
    &[912, 1284, 1752, 2004, 2256, 2424],
    &[
        702, 948, 1188, 1452, 1704, 1968, 2208, 2400, 2568, 2724, 2868, 3000, 3132, 3264, 3360,
        3408, 3504,
    ],
];

const M1_MAX: Soc = Soc {
    chip_id: 0x6001,
    name: "Apple M1 Max",
    pmgr: "pmgr1,t6001",
    chip: Chip::AppleM1,
    cores: &ep_cores(0x028, 0x029, Some(M1_PRO_POINTS)),
    aic: Some(("aic,2", 0xc000)),
    dram_base: Some(0x100_0000_0000),
    lockdown: Some(LOCKDOWN),
    memory_cache: None,
    clusters: None,
    aon_fuses: None,
    cpu_start: Some(CPU_START_T8103),
    wake_masks: None,
    power_banks: &[],
    dpe_reg: None,
    bridge_fields: None,
};

const M2_MAX: Soc = Soc {
    chip_id: 0x6021,
    name: "Apple M2 Max",
    pmgr: "pmgr1,t6021",
    chip: Chip::AppleM2,
    cores: &ep_cores(0x038, 0x039, Some(M2_PRO_POINTS)),
    aic: Some(("aic,2", 0xc000)),
    dram_base: Some(0x100_0000_0000),
    lockdown: Some(LOCKDOWN),
    memory_cache: None,
    clusters: None,
    aon_fuses: None,
    cpu_start: Some(CPU_START_T6020),
    wake_masks: None,
    power_banks: &[],
    dpe_reg: None,
    bridge_fields: None,
};

const M3_MAX: Soc = Soc {
    chip_id: 0x6031,
    name: "Apple M3 Max",
    pmgr: "pmgr1,t6031",
    chip: Chip::AppleM3,
    cores: &ep_cores(0x048, 0x049, None),
    aic: None,
    dram_base: None,
    lockdown: Some(LOCKDOWN),
    memory_cache: None,
    clusters: None,
    aon_fuses: None,
    cpu_start: Some(CPU_START_T6031),
    wake_masks: None,
    power_banks: &[],
    dpe_reg: None,
    bridge_fields: None,
};

const SOCS: [Soc; 18] = [
    Soc {
        chip_id: 0x8103,
        name: "Apple M1",
        pmgr: "pmgr1,t8103",
        chip: Chip::AppleM1,
        cores: &ep_cores(0x022, 0x023, Some(M1_POINTS)),
        aic: Some(("aic,1", AIC1_EVENT)),
        dram_base: Some(0x8_0000_0000),
        lockdown: Some(LOCKDOWN),
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: Some(CPU_START_T8103),
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    Soc {
        chip_id: 0x6000,
        name: "Apple M1 Pro",
        pmgr: "pmgr1,t6000",
        chip: Chip::AppleM1,
        cores: &ep_cores(0x024, 0x025, Some(M1_PRO_POINTS)),
        aic: Some(("aic,2", 0xc000)),
        dram_base: Some(0x100_0000_0000),
        lockdown: Some(LOCKDOWN),
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: Some(CPU_START_T8103),
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    M1_MAX,
    // Two M1 Max dies (Linux `t6002.dtsi`: the same core compatibles).
    Soc {
        chip_id: 0x6002,
        name: "Apple M1 Ultra",
        ..M1_MAX
    },
    Soc {
        chip_id: 0x8112,
        name: "Apple M2",
        pmgr: "pmgr1,t8112",
        chip: Chip::AppleM2,
        cores: &ep_cores(
            0x032,
            0x033,
            Some([
                &[600, 912, 1284, 1752, 2004, 2256, 2424],
                &[
                    660, 924, 1188, 1452, 1704, 1968, 2208, 2400, 2568, 2724, 2868, 2988, 3096,
                    3204, 3324, 3408, 3504,
                ],
            ]),
        ),
        aic: Some(("aic,2", 0x8000)),
        dram_base: Some(0x8_0000_0000),
        lockdown: Some(LOCKDOWN),
        memory_cache: Some((8 << 20, 16)),
        clusters: Some(T8112_CLUSTERS),
        aon_fuses: Some(36),
        cpu_start: Some(CPU_START_T8112),
        // setAPWakeupSources: RegMap 0x42 -> reg[4], kernel file
        // 0x2fa31bc..0x2fa3620. Compiled valid masks at 0x7957ec;
        // the DeviceTree does not carry this capability bitmap.
        wake_masks: Some(WakeLayout {
            reg: 4,
            valid: [
                u32::MAX,
                u32::MAX,
                u32::MAX,
                u32::MAX,
                u32::MAX,
                u32::MAX,
                u32::MAX,
                0x7fff_ffff,
            ],
        }),
        // initRegMaps, kernel file 0x2fa31bc..0x2fa3620: RegMap
        // 0x68/0x64/0x62/0x65. DT gives the addresses, not enum bindings.
        power_banks: &[
            (31, power::Kind::Volman),
            (30, power::Kind::Marker),
            (34, power::Kind::Gpce),
            (32, power::Kind::Gating),
            (35, power::Kind::Tvm),
        ],
        dpe_reg: Some(29),
        bridge_fields: Some(&bridge::tunables::T8112),
    },
    Soc {
        chip_id: 0x6020,
        name: "Apple M2 Pro",
        pmgr: "pmgr1,t6020",
        chip: Chip::AppleM2,
        cores: &ep_cores(0x034, 0x035, Some(M2_PRO_POINTS)),
        aic: Some(("aic,2", 0xc000)),
        dram_base: Some(0x100_0000_0000),
        lockdown: Some(LOCKDOWN),
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: Some(CPU_START_T6020),
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    M2_MAX,
    // Two M2 Max dies (Linux `t6022.dtsi`: the same core compatibles).
    Soc {
        chip_id: 0x6022,
        name: "Apple M2 Ultra",
        ..M2_MAX
    },
    Soc {
        chip_id: 0x8122,
        name: "Apple M3",
        pmgr: "pmgr1,t8122",
        chip: Chip::AppleM3,
        cores: &ep_cores(0x042, 0x043, None),
        aic: Some(("aic,3", 0x40000)),
        dram_base: None,
        lockdown: Some(LOCKDOWN),
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: Some(CPU_START_T8112),
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    Soc {
        chip_id: 0x6030,
        name: "Apple M3 Pro",
        pmgr: "pmgr1,t6030",
        chip: Chip::AppleM3,
        cores: &ep_cores(0x044, 0x045, None),
        aic: None,
        dram_base: None,
        lockdown: Some(LOCKDOWN),
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: Some(CPU_START_T8112),
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    M3_MAX,
    // The binned M3 Max (Mac15,10 and Mac15,11) and the M3 Ultra's two dies.
    // Their parts are inferred: their boards' T6031 SPTM handles only the H15
    // parts 0x42-0x45, 0x48, 0x49, 0x50 and 0x51 (sptm.t6031
    // 0xfffffff0270af46c), and of those only XNU's Palma pair is a Max die
    // (CPUSUBFAMILY_ARM_HC_HD), the layout their DeviceTrees give.
    Soc {
        chip_id: 0x6034,
        name: "Apple M3 Max",
        ..M3_MAX
    },
    Soc {
        chip_id: 0x6032,
        name: "Apple M3 Ultra",
        ..M3_MAX
    },
    Soc {
        chip_id: 0x8132,
        name: "Apple M4",
        pmgr: "pmgr1,t8132",
        chip: Chip::AppleM4,
        cores: &ep_cores(0x052, 0x053, None),
        aic: None,
        dram_base: None,
        lockdown: None,
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: Some(CPU_START_T8112),
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    Soc {
        chip_id: 0x6040,
        name: "Apple M4 Pro",
        pmgr: "pmgr1,t6041",
        chip: Chip::AppleM4,
        cores: &ep_cores(0x054, 0x055, None),
        aic: None,
        dram_base: None,
        lockdown: None,
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: Some(CPU_START_T6031),
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    Soc {
        chip_id: 0x6041,
        name: "Apple M4 Max",
        pmgr: "pmgr1,t6041",
        chip: Chip::AppleM4,
        cores: &ep_cores(0x058, 0x059, None),
        aic: None,
        dram_base: None,
        lockdown: None,
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: Some(CPU_START_T6031),
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    Soc {
        chip_id: 0x8142,
        name: "Apple M5",
        pmgr: "pmgr1,t8142",
        chip: Chip::AppleM5,
        cores: &ep_cores(0x062, 0x063, None),
        aic: None,
        dram_base: None,
        lockdown: None,
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: Some(CPU_START_T8112),
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    Soc {
        chip_id: 0x8152,
        name: "Apple M6",
        pmgr: "pmgr2,arch",
        chip: Chip::AppleM6,
        cores: &M6_CORES,
        aic: None,
        dram_base: None,
        lockdown: None,
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        // The original PMGR2 architecture node has no reg aperture. Its
        // child register layout does not establish PMGR1 CPU-start offsets.
        cpu_start: None,
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
];

/// The chip and PEs a board's SoC row and `/cpus` select.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cpus {
    pub chip: Chip,
    /// The PEs in `/cpus` order.
    pub processors: Vec<Identity>,
    /// The `aic` node's `compatible` and its event register's offset from its
    /// `reg`, on a SoC whose AIC a public DeviceTree places.
    pub aic: Option<(&'static str, u64)>,
    /// The SoC's lockdown CONTROL offsets in `cpu-impl-reg` and
    /// `cpm-impl-reg`, where known.
    pub lockdown: Option<[u64; 2]>,
}

/// The `aic` node's `compatible` and its event register's offset from its
/// `reg` on the SoC with `chip_id`, when a public DeviceTree places it.
pub fn aic(chip_id: u32) -> Option<(&'static str, u64)> {
    SOCS.iter().find(|soc| soc.chip_id == chip_id)?.aic
}

/// Each cluster type's operating points in MHz, lowest first, as
/// `(cluster-type, points)` on the SoC with `chip_id`, where known.
pub fn operating_points(chip_id: u32) -> Option<Vec<(u8, &'static [u32])>> {
    let cores = core_types(chip_id)?;
    let points: Vec<_> = cores
        .iter()
        .filter_map(|core| Some((core.cluster_type, core.operating_points?)))
        .collect();
    (!points.is_empty()).then_some(points)
}

/// The observed core types and their configured or unknown CPU requirements.
/// The number of types does not define the number of physical clusters.
pub fn core_types(chip_id: u32) -> Option<&'static [CoreType]> {
    Some(SOCS.iter().find(|soc| soc.chip_id == chip_id)?.cores)
}

/// The CPU of the SoC with `chip_id`, for the SoCs with a row.
pub fn chip(chip_id: u32) -> Option<Chip> {
    Some(SOCS.iter().find(|soc| soc.chip_id == chip_id)?.chip)
}

/// The `product-soc-name` of the SoC with `chip_id`, for the SoCs with a row.
pub fn name(chip_id: u32) -> Option<&'static str> {
    Some(SOCS.iter().find(|soc| soc.chip_id == chip_id)?.name)
}

/// The MIDR_EL1 part number of `cluster_type`'s cores on the SoC with
/// `chip_id`, the one [`cpus`] gives them.
pub fn midr_part(chip_id: u32, cluster_type: u8) -> Option<u16> {
    core_types(chip_id)?
        .iter()
        .find(|core| core.cluster_type == cluster_type)?
        .midr_part
}

/// The level 1 instruction and data caches of `cluster_type`'s cores on the
/// SoC with `chip_id`, the ones [`cpus`] gives them, where known.
pub fn level1_caches(chip_id: u32, cluster_type: u8) -> Option<(Cache, Cache)> {
    let caches = core_types(chip_id)?
        .iter()
        .find(|core| core.cluster_type == cluster_type)?
        .caches?;
    Some((caches.instruction, caches.data))
}

/// The guest DRAM base of the SoC with `chip_id`.
pub fn dram_base(chip_id: u32) -> Result<u64, String> {
    SOCS.iter()
        .find(|soc| soc.chip_id == chip_id)
        .and_then(|soc| soc.dram_base)
        .ok_or_else(|| format!("ApChipID {chip_id:#x} has no public DRAM base"))
}

/// The guest DRAM base of a board whose SoC is `chip_id`: its DeviceTree's
/// `/arm-io/mcc` `dram-base`, which the M3 and later boards state, or else
/// the SoC's public base ([`dram_base`]). Where both exist they must agree.
pub fn board_dram_base(tree: &[u8], chip_id: u32) -> Result<u64, String> {
    let root = Node::root(tree).ok_or("DeviceTree has no root")?;
    let stated = root
        .child("arm-io")
        .and_then(|io| io.child("mcc"))
        .and_then(|mcc| mcc.property("dram-base"))
        .map(|bytes| {
            <[u8; 8]>::try_from(bytes)
                .map(u64::from_le_bytes)
                .map_err(|_| "/arm-io/mcc dram-base is not 8 bytes")
        })
        .transpose()?;
    match (stated, dram_base(chip_id)) {
        (Some(stated), Ok(public)) if stated != public => Err(format!(
            "/arm-io/mcc dram-base {stated:#x} is not ApChipID {chip_id:#x}'s {public:#x}"
        )),
        (Some(stated), _) => Ok(stated),
        (None, public) => public,
    }
}

/// One `/cpus` node: its `cluster-type` letter, `reg` and `l2-cache-size`.
#[derive(Debug, Clone, Copy)]
pub struct Processor {
    pub cluster_type: u8,
    pub reg: u32,
    pub l2_bytes: Option<u32>,
}

/// The chip and PEs, in `/cpus` order, of a board whose DeviceTree names
/// `chip_id` and `soc_name`.
///
/// MIDR_EL1 is implementer 0x61 (Apple), variant 1, architecture 0xF, the
/// cluster type's part and revision 0, the values the J473AP profile has
/// always used; variant and revision are inferred until a reference capture
/// supplies them. MPIDR_EL1 is `reg` with bit 31 RES1 and the core type's
/// Aff2 (E=0, P=1, M=4 from XNU's `MPIDR_CORETYPE_ACC_*` definitions):
/// `reg` is Aff1 (cluster) and Aff0 (core) on every single-die board (the
/// J473AP's cpu0-3 are 0-3 and cpu4-7 0x100-0x103), the cores of P clusters
/// have Aff2 1 (the `cpu@` `reg` of Linux `t8103.dtsi`, `t8112.dtsi`,
/// `t600x-common.dtsi` and `t602x-common.dtsi` and `t8122.dtsi`, which XNU
/// masks off in `ml_get_cpu_number`; inferred for the later SoCs), and U and
/// MT are 0 for a multiprocessor without multithreading (inferred). On the
/// two-die boards the second die's clusters are Aff1 8 and up (its `reg`
/// 0x800 to 0xaff), with the same Aff2 for its P cores (Linux `t6002.dtsi` and
/// `t6022.dtsi`: `cpu@800`, `cpu@10900`). A `reg` beyond Aff1's sixteen
/// clusters has no public MPIDR mapping and refuses.
/// The `reg` bits a `/cpus` node may set: Aff1's sixteen clusters, two dies
/// of eight, and Aff0's cores.
const MPIDR_CLUSTER_CORE: u32 = 0xfff;

pub fn cpus(chip_id: u32, soc_name: &str, processors: &[Processor]) -> Result<Cpus, String> {
    let soc = SOCS
        .iter()
        .find(|soc| soc.chip_id == chip_id)
        .ok_or_else(|| format!("ApChipID {chip_id:#x} ({soc_name}) has no public MIDR part"))?;
    if soc.name != soc_name {
        return Err(format!(
            "ApChipID {chip_id:#x} is {}, but the DeviceTree names {soc_name}",
            soc.name
        ));
    }
    if processors.is_empty() {
        return Err("the DeviceTree has no /cpus nodes".into());
    }
    topology::validate(processors)?;
    let processors = processors
        .iter()
        .map(|processor| {
            let core = soc
                .cores
                .iter()
                .find(|core| core.cluster_type == processor.cluster_type);
            let part = core
                .and_then(|core| core.midr_part)
                .map(u64::from)
                .ok_or_else(|| {
                    format!(
                        "{} cluster type {} has no public MIDR part",
                        soc.name,
                        char::from(processor.cluster_type)
                    )
                })?;
            let core = core.expect("a part requires a core descriptor");
            if processor.reg & !MPIDR_CLUSTER_CORE != 0 {
                return Err(format!(
                    "{} cpu reg {:#x} has no public MPIDR mapping",
                    soc.name, processor.reg
                ));
            }
            let mpidr = core.mpidr(processor.reg).ok_or_else(|| {
                format!(
                    "{} cluster type {} has no public MPIDR mapping",
                    soc.name,
                    char::from(processor.cluster_type)
                )
            })?;
            let caches = core.caches.ok_or_else(|| {
                format!(
                    "{} cluster type {} has no cache geometry",
                    soc.name,
                    char::from(processor.cluster_type)
                )
            })?;
            Ok(Identity {
                midr: 0x61 << 24 | 1 << 20 | 0xf << 16 | part << 4,
                mpidr,
                clock: core
                    .operating_points
                    .and_then(|points| points.last())
                    .map(|&mhz| u64::from(mhz) * 1_000_000),
                caches: Some(core_caches(caches, processor)?),
            })
        })
        .collect::<Result<_, String>>()?;
    Ok(Cpus {
        lockdown: soc.lockdown,
        chip: soc.chip,
        processors,
        aic: soc.aic,
    })
}

/// A PE's caches: its cluster type's level 1 caches and the level 2 its
/// `/cpus` node sizes.
fn core_caches(caches: CoreCaches, processor: &Processor) -> Result<Caches, String> {
    let bytes = processor
        .l2_bytes
        .ok_or_else(|| format!("cpu reg {:#x} has no l2-cache-size", processor.reg))?;
    let unified = Cache {
        bytes,
        ways: caches.unified_ways,
        line: LINE,
    };
    Caches::split_unified(caches.instruction, caches.data, unified)
        .map_err(|reason| format!("cpu reg {:#x}: {reason}", processor.reg))
}

/// A device's first `reg` range in guest PA and its AIC input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Device {
    pub physical: u64,
    pub bytes: u64,
    pub irq: u32,
}

/// The lockdown registers of one CPU implementation block: the ADT `/cpus`
/// property naming the block, its guest PA and size, the offset of its
/// lockdown CONTROL, and for a `cpu-impl-reg` the PE (in `/cpus` order)
/// whose RVBAR it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockdownBlock {
    pub name: &'static str,
    pub physical: u64,
    pub bytes: u64,
    pub control: u64,
    pub cpu: Option<usize>,
}

/// One PE's CLPC sampler counters: the PE (in `/cpus` order), its
/// `cpu-impl-reg`'s guest PA and the SoC's counters
/// (`platform::apple::core_counters`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterBlock {
    pub cpu: usize,
    pub physical: u64,
    pub layout: core_counters::Layout,
}

/// The AIC: its core block's guest PA, its input count and its layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptController {
    pub physical: u64,
    pub inputs: u16,
    pub layout: AicLayout,
}

/// The register offsets an `aic,3` node states, as m1n1 `aic.c` reads them,
/// and the AICv2 layout they must match (Linux `aic3_info` hard-codes them
/// for the M3 through the M5).
const AIC3_OFFSETS: [(&str, u32); 5] = [
    ("rev-offset", 0),
    ("cap0-offset", 0x4),
    ("maxnumirq-offset", 0xc),
    ("aicglbcfg-offset", 0x14),
    ("extint-baseaddress", AIC3_IRQ_CFG as u32),
];

/// The layout of an `/arm-io/aic` node compatible with `version` whose event
/// register is `event` bytes from its `reg`: the AICv1's, the AICv2's, or the
/// AICv3's once its stated offsets match the modeled layout.
fn aic_layout(aic: &Node<'_>, version: &str, event: u64) -> Result<AicLayout, String> {
    match version {
        "aic,1" => return Ok(AicLayout::V1),
        "aic,2" => {
            let timestamps = aic.first_u32("#shared-timestamps").unwrap_or(0);
            let timestamps = u8::try_from(timestamps)
                .map_err(|_| format!("/arm-io/aic has {timestamps} shared timestamps"))?;
            return Ok(AicLayout::aic2(event, timestamps));
        }
        _ => {}
    }
    for (name, expected) in AIC3_OFFSETS {
        let found = aic
            .first_u32(name)
            .ok_or_else(|| format!("/arm-io/aic has no {name}"))?;
        if found != expected {
            return Err(format!(
                "/arm-io/aic {name} is {found:#x}, not the modeled {expected:#x}"
            ));
        }
    }
    Ok(AicLayout::aic3(event))
}

/// The `compatible` of the S5L UART the engine models (`platform::apple::uart`).
pub const UART: &str = "uart-1,samsung";
/// The `compatible` of the watchdog the engine models (`platform::apple::wdt`).
pub const WATCHDOG: &str = "wdt,s5l8960x";
/// The AIC versions the engine models (`platform::apple::aic1` and `aic`).
const AICS: [&str; 3] = ["aic,1", "aic,2", "aic,3"];
/// The modern DART compatible; native legacy families are selected through
/// [`dart::Profile::from_compatible`], with separate optional-feature gates.
pub const DART: &str = "dart,t8110";
/// The `compatible` of a DART child naming one client's stream (its `reg`),
/// which XNU's IODARTMapper binds and clients name as `iommu-parent`.
pub const IOMMU_MAPPER: &str = "iommu-mapper";
/// The `compatible` of the SoC's PMGR (each row's `pmgr`) when the machine
/// models it ([`Soc::pmgr_modeled`]): `platform::apple::pmgr` and the PMGR
/// family models place its power states and CPU start registers (m1n1
/// `src/pmgr.c` and `src/smp.c` read them alike on every SoC), clusters,
/// eFuses, energy, performance counters, wake masks, voltage, DPE and
/// fabric bridges.
pub fn pmgr(chip_id: u32) -> Option<&'static str> {
    SOCS.iter()
        .find(|soc| soc.chip_id == chip_id)
        .filter(|soc| soc.pmgr_modeled())
        .map(|soc| soc.pmgr)
}

impl Soc {
    /// Whether the row has the facts the PMGR models need beyond the power
    /// states and CPU start: its CPU clusters' registers and its fabric
    /// bridges' register layouts. Without them the PMGR's cluster and bridge
    /// windows would have no model, so the PMGR stays hidden (`models`), as
    /// every unmodeled device does, rather than present a partial one.
    const fn pmgr_modeled(&self) -> bool {
        self.clusters.is_some() && self.bridge_fields.is_some()
    }
}
/// The `compatible` of the AES engine the engine models
/// (`platform::apple::aes`).
pub const AES: &str = "aes,s8000";
/// The `compatible` of the memory cache controller whose registers
/// `platform::apple::amcc`, `dcs` and `ptd` model.
pub const MCC: &str = "mcc,t8112";
/// ASC wrapper and nub shared by multiple coprocessor roles.
pub const ASC: &str = "iop,ascwrap-v4";
pub const RTBUDDY: &str = "iop-nub,rtbuddy-v2";
/// The SMC nub's PMU child: `AppleSMCPMU` binds it through the
/// `AppleSMCInterface` nub that `AppleSMCInterface::startInterfaces`
/// (26A434 J473AP KC file 0x2d99550) creates for every child of the SMC's
/// RTBuddy nub except `smc-socd`. Its contract (boot and shutdown records,
/// `MBSE` system events, HID button notifications and the `pKW4`, `keyW`
/// and `btnR` platform functions other nodes route through it) is the SMC
/// key endpoint's (`platform::apple::smc`).
pub const SMC_PMU: &str = "smc-pmu";
/// The board's buttons (`/buttons`), which `AppleM68Buttons` binds. Its
/// `function-button_*` platform functions name their provider; the loader
/// keeps the node only while each provider stays visible
/// (`stela_loader::devices`).
pub const BUTTONS: &str = "buttons";

/// `/arm-io/ans` properties under which SPTM's `nvme_bootstrap`
/// (0x270c8a74..8bc0, 0x270c8dac) drives banks or flows the ANS2 model
/// lacks: the secure BAR and its alternate register layout (SPTM programs
/// the queues at `reg[9]` or +0x4000), the transfer-length workaround
/// (`reg[10..12]` doorbells written on unmap) and the SHA engine
/// (`reg[14]`). docs/research/ans2.md has the matrix.
const UNMODELED_ANS_SPTM: [&str; 4] = [
    "nvme-secure-bar",
    "nvme-secure-reg-layout",
    "nvme-tl-wa",
    "nvme-ans-sha-present",
];
pub const SART: &str = "sart,coastguard";

/// RTBuddy nub flags under which the AP does not wait for the coprocessor's
/// power-on announcement and wakes it by AP power instead (`rtkit` module
/// comment). No placed coprocessor model follows that contract.
const UNAWAITED_NUB: [&str; 2] = ["remote-only", "automatic-rail-gating-enabled"];

/// Select the protocol endpoint by its declared compatible under an already
/// qualified ASC role. Node names are labels (J314s uses iop-gfx-nub0),
/// not a second protocol discriminator. Ambiguous endpoints refuse.
fn rtbuddy_nub<'a>(asc: &Node<'a>, role: &str) -> Result<Node<'a>, String> {
    let children = asc
        .children()
        .ok_or_else(|| format!("{role} children are malformed"))?;
    let mut nubs = children.into_iter().filter(|node| node.compatible(RTBUDDY));
    let nub = nubs
        .next()
        .ok_or_else(|| format!("{role} has no RTBuddy v2 nub"))?;
    if nubs.next().is_some() {
        return Err(format!("{role} has ambiguous RTBuddy v2 nubs"));
    }
    awaited_nub(&nub, role)?;
    Ok(nub)
}

/// Refuse an RTBuddy nub whose start-up the RTKit model does not carry.
fn awaited_nub(nub: &Node<'_>, role: &str) -> Result<(), String> {
    match UNAWAITED_NUB
        .into_iter()
        .find(|flag| nub.property(flag).is_some())
    {
        Some(flag) => Err(format!(
            "{role} nub is {flag}, a start-up the RTKit model does not carry"
        )),
        None => Ok(()),
    }
}

/// SPI controller compatible, byte-PIO version 1.
pub const SPI: &str = "spi-1,spimc";
/// Single-wire SPI NOR compatible.
pub const NOR: &str = "nor-flash,spi";
/// Apple CHRP NVRAM service compatible.
pub const NVRAM: &str = "nvram,chrp";
/// GPIO output provider compatible.
pub const GPIO: &str = "gpio,t8101";
const GPIO_T6000: &str = "gpio,t6000";
const GPIO_S5L: &str = "gpio,s5l8960x";

/// Compatible identifies register semantics, while role bounds the qualified
/// board owner. Only the AP S5L bank is admitted: auxiliary restoration,
/// wake groups and nets remain explicit unqualified board dependencies.
fn gpio_profile<'a>(property: impl Fn(&str) -> Option<&'a [u8]>) -> Option<gpio::Profile> {
    let compatibles = property("compatible")?;
    let has = |name: &str| {
        compatibles
            .split(|byte| *byte == 0)
            .any(|c| c == name.as_bytes())
    };
    match (has(GPIO), has(GPIO_T6000), has(GPIO_S5L)) {
        (true, false, false) => Some(gpio::Profile::T8101),
        (false, true, true) if property("role") == Some(b"AP\0".as_slice()) => {
            Some(gpio::Profile::S5l8960x)
        }
        _ => None,
    }
}

/// The Type-C I2C bus: controller, HPM bus manager and CD321x dies.
pub const I2C: &str = "i2c,t8101";
pub const HPM_MANAGER: &str = "usbc,manager";
pub const HPM: &str = "usbc,cd3217";
pub const RETIMER: &str = "atcrt";
pub const ATC_PHY: &str = "atc-phy,t8112";
/// The ATC PHY register layouts, by the first compatible a node lists that
/// names one: `AppleT8103TypeCPhy` binds all of them. The T8103 (J274AP) and
/// T6020 (J414sAP, `atc-phy,t6020` then `atc-phy,t8112`) views are the
/// T8112 (J473AP) views without its last, core+0x4c000, which is beyond the
/// canonical core window. The views the model places (USB2, event block,
/// core+0x20000, core) are views 0 to 3 in each.
const ATC_PHY_LAYOUTS: [(&str, usize); 3] = [
    (ATC_PHY, ATC_PHY_BASE_VIEWS + 1),
    ("atc-phy,t6020", ATC_PHY_BASE_VIEWS),
    ("atc-phy,t8103", ATC_PHY_BASE_VIEWS),
];
/// The ADT views every [`ATC_PHY_LAYOUTS`] layout starts with.
const ATC_PHY_BASE_VIEWS: usize = 28;
/// A Type-C connector description (`/port-usb-c-N`): no IOKit personality
/// binds it and it has no registers. The ATC PHY, `usb-drd` and ACIO name
/// it as `function-dock_parent`, which `AppleARMFunction::withProvider`
/// (0xfffffe0008c53aac) resolves through the node's registered platform
/// nub. With the node hidden, each of those starts stalled about 30 s and
/// the xHCI then failed to find its PHY (restore study ru-s17).
pub const DOCK_PORT: &str = "dock,usb-c";
/// The SPMI Gen2 controller and the Dialog PMU on it (`spmi`, `pmu`).
pub const SPMI: &str = "aapl,spmi";
pub const PMU: &str = "pmu,spmi";
/// A NOR partition read by AppleDiagnosticDataAccessReadOnly (kernel file
/// 0x235ecb8 start, 0x235f1e8 lazy whole-region read, 0x235f788 forwarding).
pub const SYSCFG: &str = "diagnostic-data,format1";

/// A compatible may require a distinguishing property and may own children
/// sharing a compatible with unrelated devices. Match properties exactly;
/// a missing or malformed role never broadens the claim.
struct ModelClaim {
    compatible: &'static str,
    property: (&'static str, &'static [u8]),
    children: &'static [ChildModel],
    /// Boot-chain facts the claimed node itself carries, as
    /// [`ChildModel::boot_properties`] do for a child.
    boot_properties: &'static [(&'static str, &'static [u8])],
    /// Whether the claim admits its node; see [`GPU_ADMITTED`].
    admitted: bool,
}

/// Whether the GPU (`sgx`, its `gfx-asc` coprocessor and firmware mapper) is
/// visible. Its kernel window resolves through SPTM's shared L2
/// (docs/research/agx.md section 3) and the firmware consumes the kext's
/// device-control ring (section 2), so `AGXAcceleratorG14G::start` completes
/// on the 26A434 J473AP kext (restore boot agx-obs-9). GPU work commands still
/// refuse by name until their fields are confirmed (section 5.1a).
pub const GPU_ADMITTED: bool = true;
/// A child owned by a native coprocessor model and its boot-chain facts.
/// Properties describe model state, never a guest image or a driver patch.
/// `children` are the child's own children the same model owns.
pub struct ChildModel {
    pub compatible: &'static str,
    pub boot_properties: &'static [(&'static str, &'static [u8])],
    pub children: &'static [ChildModel],
}
/// Native RTKit is already running before SPTM and uses no ARM firmware
/// memory. RTBuddy::_initConfigEDT (0x4661408..14b4) reads
/// pre-loaded/running/no-firmware-service; getSegmentMap (0x4661d68/1df8)
/// accepts empty segment-ranges/segment-names. _handlePreloadFirmware
/// (0x465a488) consumes that segment map.
const NATIVE_RTKIT_PROPERTIES: &[(&str, &[u8])] = &[
    ("pre-loaded", b""),
    ("running", b""),
    ("no-firmware-service", b""),
    ("segment-ranges", b""),
    ("segment-names", b""),
];
const NATIVE_RTKIT: ChildModel = ChildModel {
    compatible: RTBUDDY,
    boot_properties: NATIVE_RTKIT_PROPERTIES,
    children: &[],
};
/// The SMC's native nub, which also owns its `smc-pmu` child ([`SMC_PMU`]).
const SMC_RTKIT: ChildModel = ChildModel {
    compatible: RTBUDDY,
    boot_properties: NATIVE_RTKIT_PROPERTIES,
    children: &[ChildModel {
        compatible: SMC_PMU,
        boot_properties: &[],
        children: &[],
    }],
};
/// The SEP's native nub (`iop-nub,sep`, kept so `AppleSEPManager`'s
/// `A7IOPNub` personality binds). Unlike RTBuddy coprocessors, the SEP is not
/// an RTKit preload: it boots through its SEPROM mailbox handshake, so no
/// pre-loaded/running firmware-segment markers are injected.
const SEP_NUB_MODEL: ChildModel = ChildModel {
    compatible: SEP_NUB,
    boot_properties: &[],
    children: &[],
};
/// The register tunings the ANS2 driver requires before it re-powers the
/// coprocessor. `AppleANS2NVMeController::ApplyTunables` (0x3dbfc48), from
/// `PowerStateAction` (0x3dbf740), fails with 0xe00002c9 when any of these
/// `/arm-io/ans` properties is missing (0x3dbfeec..0x3dbff40). The IPSW
/// DeviceTree has none of them, so the boot chain supplies them. Each is a
/// list of 24-byte entries: register offset, width (4), mask and value.
/// The command accelerator's offsets are relative to reg[3] + 0x20000. The
/// others are relative to reg[4], reg[5] and reg[6]
/// (`mapDeviceMemoryWithIndex` 4..6 at 0x3dbf36c..0x3dbf448).
/// `ApplyTunablesFromData` (0x3dbf914) accepts an empty list without any
/// access. Emulated die: Stela's choice. The die has no analog or fabric
/// trim to set, so each list is empty. The ECC and parity shadow lists are
/// read only when reg[7], reg[8] or `gib-pcie-up` exist, and J473AP has none
/// of them. The `tunable-table-bundle` is unrelated: it names the restore
/// updater's NAND tables, which reach the MSP through tunnel commands
/// (`AppleNVMeUpdateUC::TunableTableDownload`, selector 14).
const ANS2_TUNABLES: &[(&str, &[u8])] = &[
    ("afc-aiu-ans-dual-tunables", b""),
    ("command-accelerator-tunables", b""),
    ("storage-lane-common-tunables", b""),
    ("ccu-security-interrupt-tunables", b""),
];
const ROLE_MODELS: &[ModelClaim] = &[
    ModelClaim {
        compatible: ASC,
        property: ("role", b"ANS2\0"),
        children: &[NATIVE_RTKIT],
        boot_properties: ANS2_TUNABLES,
        admitted: true,
    },
    ModelClaim {
        compatible: ASC,
        property: ("role", b"SMC\0"),
        children: &[SMC_RTKIT],
        boot_properties: &[],
        admitted: true,
    },
    // The AGX GPU's coprocessor: AGXFirmwareKextRTBuddy::bootFirmware
    // (0x1ae9c88) panics unless its nub reads as iBoot-loaded.
    ModelClaim {
        compatible: ASC,
        property: ("role", b"GFX\0"),
        children: &[NATIVE_RTKIT],
        boot_properties: &[],
        admitted: GPU_ADMITTED,
    },
    // The SEP: a native model whose ASC wrapper uses `iop-sep,ascwrap-v4` and
    // whose nub is `iop-nub,sep`. Distinguished by its `role = SEP`, so it
    // never collides with the ANS2/SMC `iop,ascwrap-v4` coprocessors.
    ModelClaim {
        compatible: SEP,
        property: ("role", b"SEP\0"),
        children: &[SEP_NUB_MODEL],
        boot_properties: &[],
        admitted: true,
    },
    ModelClaim {
        compatible: ASC,
        property: ("role", b"PMP\0"),
        children: &[NATIVE_RTKIT],
        boot_properties: &[],
        admitted: true,
    },
    // The display coprocessor (`platform::apple::dcp`): its `iop-dcpext-nub`
    // reads as the native RTKit the other ASC claims present.
    ModelClaim {
        compatible: ASC,
        property: ("role", DCPEXT_ROLE),
        children: &[NATIVE_RTKIT],
        boot_properties: &[],
        admitted: true,
    },
    ModelClaim {
        compatible: ASC,
        property: ("role", b"DCPEXT0\0"),
        children: &[NATIVE_RTKIT],
        boot_properties: &[],
        admitted: T6000_EXTERNAL_OUTPUT_ADMITTED,
    },
    ModelClaim {
        compatible: DCP_EXPERT,
        property: ("role", b"DCPEXT0\0"),
        children: &[],
        boot_properties: &[],
        admitted: T6000_EXTERNAL_OUTPUT_ADMITTED,
    },
    // Its power expert ([`DCP_EXPERT`]), a register-less node that
    // `AppleDCPExpert` binds to. IOMFB waits for it before it makes a call.
    ModelClaim {
        compatible: DCP_EXPERT,
        property: ("role", DCPEXT_ROLE),
        children: &[],
        boot_properties: &[],
        admitted: true,
    },
];

/// Child compatibles claimed by a matching parent model. The loader uses
/// this relationship before changing the tree, without relying on paths.
pub fn model_children<'a>(
    name: &str,
    property: impl Fn(&str) -> Option<&'a [u8]>,
) -> &'static [ChildModel] {
    ROLE_MODELS
        .iter()
        .find(|claim| {
            claim.admitted
                && claim.compatible == name
                && property(claim.property.0) == Some(claim.property.1)
        })
        .map_or(&[], |claim| claim.children)
}

/// Boot-chain properties a matching claimed node carries itself.
pub fn model_boot_properties<'a>(
    name: &str,
    property: impl Fn(&str) -> Option<&'a [u8]>,
) -> &'static [(&'static str, &'static [u8])] {
    ROLE_MODELS
        .iter()
        .find(|claim| {
            claim.admitted
                && claim.compatible == name
                && property(claim.property.0) == Some(claim.property.1)
        })
        .map_or(&[], |claim| claim.boot_properties)
}

/// Whether a compatible and its distinguishing properties name a modeled
/// device. The loader also checks provider and parent/child relationships.
pub fn models<'a>(name: &str, property: impl Fn(&str) -> Option<&'a [u8]>) -> bool {
    [
        UART,
        WATCHDOG,
        IOMMU_MAPPER,
        AES,
        MCC,
        SPI,
        NOR,
        NVRAM,
        SYSCFG,
        GPIO,
        I2C,
        HPM_MANAGER,
        HPM,
        DOCK_PORT,
        USB_DRD,
        SPMI,
        PMU,
        BUTTONS,
        DISPEXT,
    ]
    .contains(&name)
        || T6000_EXTERNAL_OUTPUT_ADMITTED && name == DISPEXT_T6000
        || [GPIO_T6000, GPIO_S5L].contains(&name)
            && gpio_profile(&property) == Some(gpio::Profile::S5l8960x)
        || dart::Profile::from_compatible(name.as_bytes()).is_some_and(|profile| {
            property("compatible")
                .is_none_or(|bytes| dart::Profile::from_compatible(bytes) == Some(profile))
                && (profile == dart::Profile::T8110
                    || dart_topology::legacy_requirements(profile, &property).is_ok())
        })
        || GPU_ADMITTED && (name == GFX_MAPPER || admitted_gpu(name))
        || AICS.contains(&name)
        || ATC_PHY_LAYOUTS.iter().any(|&(layout, _)| layout == name)
        || SOCS
            .iter()
            .any(|soc| soc.pmgr == name && soc.pmgr_modeled())
        || ROLE_MODELS.iter().any(|claim| {
            claim.admitted
                && claim.compatible == name
                && property(claim.property.0) == Some(claim.property.1)
        })
}

/// SEP's wrapper and native nub, from the J473AP IPSW DeviceTree. Admitted
/// through [`ROLE_MODELS`] (matched by `role = SEP`), so the loader keeps the
/// sep node and its nub and `AppleSEPManager` binds and boots the native SEP.
pub const SEP: &str = "iop-sep,ascwrap-v4";
pub const SEP_NUB: &str = "iop-nub,sep";

/// The J473AP HDMI display pipeline the engine models at its AP-facing
/// protocols (`platform::apple::dcp`, `display`,
/// `docs/research/display-gpu.md` section 8): the `dcpext` coprocessor (the
/// shared ASC [`ASC`] with `role` `DCPEXT`, admitted through [`ROLE_MODELS`])
/// and the display pipe `dispext0` ([`DISPEXT`], kept so `AppleCLCD2`, an
/// `IOMobileFramebufferAP`, matches), whose DART `dart-dispext0` the
/// coprocessor reads swap surfaces through ([`DcpController::surface`]).
///
/// `dptx-phy` ([`DPTX_PHY`]) and `display-crossbar0` ([`DISPLAY_CROSSBAR`])
/// stay hidden. Their AP drivers (`AppleT8112DPTXPort` and
/// `AppleT8112DisplayCrossbar`, both in `com.apple.driver.AppleDisplayCrossbar`;
/// the 26A434 DeviceTree-to-kext match) configure the physical link: the
/// crossbar node has no `reg` and only routes the four `dispext` pipes and
/// `scodec0` to the ATC, `lpdptx` and `dptx` endpoints, and the PHY answers
/// the DCP's DPTX-port requests (AFK endpoint 0x2a, Linux `dptxep.c`). The
/// model drives no link and announces no DPTX-port service, so no request
/// reaches either driver; the model's monitor is connected by the
/// coprocessor itself. A guest that waits for their services instead is an
/// Open row of section 8.6.
pub const DCPEXT_ROLE: &[u8] = b"DCPEXT\0";
pub const DISPEXT: &str = "dispext0,t8112";
pub const DISPEXT_T6000: &str = "dispext0,t600x";
/// One native GOP-backed external graph with qualified TRAD/UMMS ownership.
/// This admits its resource contract; visible Recovery output still requires
/// original firmware/kernel execution through that graph.
pub const T6000_EXTERNAL_OUTPUT_ADMITTED: bool = true;

/// A source-qualified external pipeline family, preserving native identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalOutput {
    pub controller: &'static str,
    pub role: &'static str,
    pub role_property: &'static [u8],
    pub expert: &'static str,
    pub pipe: &'static str,
    pub compatible: &'static str,
    pub external_index: Option<u32>,
    pub identity: dcp::ExternalIdentity,
    pub admitted: bool,
}

pub const EXTERNAL_OUTPUTS: &[ExternalOutput] = &[
    ExternalOutput {
        controller: "dcpext",
        role: "DCPEXT",
        role_property: DCPEXT_ROLE,
        expert: "dcpext-expert",
        pipe: "dispext0",
        compatible: DISPEXT,
        external_index: None,
        identity: dcp::ExternalIdentity::Unnumbered,
        admitted: true,
    },
    ExternalOutput {
        controller: "dcpext0",
        role: "DCPEXT0",
        role_property: b"DCPEXT0\0",
        expert: "dcpext0-expert",
        pipe: "dispext0",
        compatible: DISPEXT_T6000,
        external_index: Some(1),
        identity: dcp::ExternalIdentity::Numbered(0),
        admitted: T6000_EXTERNAL_OUTPUT_ADMITTED,
    },
];

pub fn external_output(role: &[u8]) -> Option<&'static ExternalOutput> {
    EXTERNAL_OUTPUTS
        .iter()
        .find(|p| p.admitted && p.role_property == role)
}

/// These features require native expert operations beyond RTKit power.
pub const DCP_EXPERT_HARDWARE_FEATURES: &[&str] = &[
    "require-pmgr-scratch",
    "require-conditional-retention",
    "require-force-wakeup",
    "require-axi2af-reset",
    "support-dynamic-sysfe-pg",
    "support-psd-self-vote",
];
/// The coprocessor's power expert, `/arm-io/dcpext-expert` (`role` `DCPEXT`,
/// `join-power-plane`, no `reg`). In the 26A434 J473AP kernelcache:
/// - `UnifiedPipeline2::start` waits in `DCPPowerManager::wait_for_dcp_expert`,
///   and `DCPEndpointV2::start` in `AppleDCPExpert::copyDCPExpert`, until an
///   `AppleDCPExpert` with the coprocessor's role is published. Without it,
///   `AppleCLCD2` never makes an IOMFB call and restore reports no display.
/// - `AppleDCPExpert::start` (KC file 0x22f4278) reads its hardware features
///   from that node: `require-pmgr-scratch`, `require-conditional-retention`,
///   `require-force-wakeup`, `require-axi2af-reset`, `support-dynamic-sysfe-pg`
///   and `support-psd-self-vote`. J473AP sets none of them, so it maps no
///   register. It waits for the role's `RTBuddyService` and joins the power
///   plane.
/// - It changes the coprocessor's power only through that RTBuddy
///   (`_changeDCPPowerStateInternal`, 0x22f8928), whose RTKit power messages
///   the coprocessor model answers.
///
/// The primary display pipe's `dcp0-expert` (`role` `DCP`) stays hidden with its
/// unmodeled coprocessor.
pub const DCP_EXPERT: &str = "dcp-expert-v1";
pub const DPTX_PHY: &str = "dptx-phy,t8112";
pub const DISPLAY_CROSSBAR: &str = "display-crossbar,t8112";

/// SEP's DT-placed register banks, four mailbox IRQs, DART stream and optional
/// iBoot SEPFW source extent. The extent is not proof of firmware acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SepDevice {
    pub ranges: [(u64, u64); 2],
    pub irqs: [u32; 4],
    pub iommu: usize,
    /// Explicit selection of the sole original TRAD, independent of SID count.
    pub instance: usize,
    /// Actual iommu-parent owner and OS context, before native incoming remap.
    pub mapper: u32,
    pub mapper_context: u32,
    pub stream: u32,
    pub firmware: Option<(u64, u64)>,
    /// The AP's effective production status and security mode in `/chosen`,
    /// which the SEP, sharing its fuses, reports as its own.
    pub security: Option<crate::platform::apple::sep::SecurityMode>,
    /// The machine's `/chosen` `unique-chip-id` (Stela's per-machine ECID,
    /// set at setup and written by bundle preparation), bound into the SEP
    /// key hierarchy. `None` when `/chosen` does not carry it.
    pub ecid: Option<u64>,
}

/// The `dcpext` display coprocessor and the register apertures around it,
/// from the J473AP DeviceTree: the ASC wrapper `reg[0]` and four mailbox IRQs,
/// whether the nub is `quiesced`, each visible display aperture's primary
/// Complete register views with a stable model name, and the DART streams it masters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DcpController {
    pub phandle: Option<u32>,
    pub mapper: u32,
    pub surface_phandle: Option<u32>,
    /// Full original surface mapper list, primary first; additional PIODMA
    /// ownership is retained without inventing execution for that producer.
    pub surface_routes: Vec<DcpMapperRoute>,
    pub role: &'static str,
    pub identity: dcp::ExternalIdentity,
    /// Explicit sole-TRAD selection, checked before this ordinal is retained.
    pub instance: usize,
    /// OS mapper context, distinct from the incoming `stream` before remap.
    pub mapper_context: u32,
    pub surface_instance: Option<usize>,
    pub wrapper: (u64, u64),
    pub interrupts: [u32; 4],
    pub quiesced: bool,
    pub regions: Vec<(&'static str, (u64, u64))>,
    /// The [`Board::darts`] index and stream of its `iommu-parent`
    /// (`mapper-dcpext`, dart-dcpext stream 5 on J473AP).
    pub iommu: usize,
    pub stream: u32,
    /// That DART's `vm-base` when the node is `truncate-dvas`: the AP then
    /// hands the coprocessor only a DVA's low 32 bits
    /// (`AppleA7IOP::_restrictDVA`, kernel file 0x1bb1424).
    pub window: Option<u64>,
    /// The [`Board::darts`] index and stream the swap surfaces are read
    /// through: the visible display pipe's ([`DISPEXT`]) first
    /// `iommu-parent` (J473AP `mapper-dispext0`, dart-dispext0 stream 0, the
    /// framebuffer mapping Linux `plane.c` gives the display DART; the second,
    /// `mapper-dispext0-piodma`, is the pipe's programmed-I/O DMA).
    pub surface: Option<(usize, u32)>,
}

/// One original display-pipe mapper owner; metadata does not select traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DcpMapperRoute {
    pub mapper: u32,
    pub iommu: usize,
    pub instance: usize,
    pub mapper_context: u32,
    pub stream: u32,
}

/// T8112 device controller compatible; admission stays closed until the
/// unchanged Apple platform/PHY initialization has been observed.
pub const USB_DRD: &str = "usb-drd,t8112";

/// Nine ADT windows, five interrupt inputs and the mapper-selected DMA
/// stream. Apple reg[2]/reg[8] overlap reg[0]; preserve their physical alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbController {
    pub ranges: [(u64, u64); 9],
    pub irqs: [u32; 5],
    pub iommu: usize,
    /// Actual owner identities; context survives native incoming assignment.
    pub phandle: Option<u32>,
    pub mapper: u32,
    pub mapper_context: u32,
    pub stream: u32,
    /// The Type-C connector's `port-number`, shared with its HPM die.
    pub port: u32,
    /// Ordinary controller state survives supply gating only when declared.
    pub retention: bool,
    /// Actual digital PHY provider (`atc-phy-parent`), never inferred from
    /// the connector's display name or ordinal.
    pub phy: u32,
}

/// Everything the engine models of a board, from its DeviceTree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Board {
    /// The AP GPIO bank, when visible.
    pub gpio: Option<GpioBank>,
    /// The other visible GPIO banks, in DeviceTree order.
    pub aux_gpios: Vec<AuxGpioBank>,
    /// SPI1, its NOR image and the GPIO chip-select wire, when visible.
    pub spi_nor: Option<SpiNor>,
    /// Explicitly visible I2C controllers and their addressed targets.
    pub i2cs: Vec<I2cController>,
    /// Explicitly visible T8112 PHYs. Prepared bundles still hide them.
    pub typec_phys: Vec<TypecPhy>,
    pub cpus: Cpus,
    /// `/arm-io/uart0`, a `uart-1,samsung`.
    pub uart: Device,
    /// `/arm-io/wdt`, a `wdt,s5l8960x`.
    pub watchdog: Device,
    /// Optional side registers and per-CPU trigger words of the watchdog.
    pub watchdog_side: Option<WatchdogSide>,
    /// `/arm-io/aic`, an `aic,1`, `aic,2` or `aic,3`.
    pub aic: InterruptController,
    /// Every PE's `cpu-impl-reg` and every cluster's `cpm-impl-reg`, once
    /// each, on a SoC whose lockdown offsets are known; none otherwise.
    pub lockdown: Vec<LockdownBlock>,
    /// Every PE's CLPC sampler counters in its `cpu-impl-reg`, on a SoC
    /// whose counters are known.
    pub counters: Vec<CounterBlock>,
    /// CPU CoreSight regions, retaining the PE identity and aperture length.
    pub coresight: Vec<CoreSight>,
    /// The AMCC lock registers of `/chosen/lock-regs/amcc`, when iBoot
    /// described them.
    pub memory_controller: Option<MemoryController>,
    /// The separately described I/O access CTRR controller.
    pub io_access_controller: Option<MemoryController>,
    /// Every supported native DART group, preserving DT traversal order.
    pub darts: Vec<Iommu>,
    /// `/arm-io/aes`, an `aes,s8000`, when the DeviceTree keeps it.
    pub aes: Option<AesEngine>,
    /// ANS2 and its SART, if an input tree explicitly presents the device.
    /// Prepared bundles still hide its compatibles until its vendor ABI is complete.
    pub ans: Option<AnsController>,
    /// The SMC coprocessor, when the DeviceTree shows its `iop,ascwrap-v4`.
    pub smc: Option<SmcController>,
    /// The PMP coprocessor, under the same condition.
    pub pmp: Option<PmpController>,
    /// The AGX GPU, when the DeviceTree shows both `gfx-asc` and `sgx`.
    pub gfx: Option<GfxController>,
    /// SEP placement if the input tree explicitly keeps it. Production
    /// `models()` admission remains closed while sepOS boot services refuse.
    pub sep: Option<SepDevice>,
    /// DWC3 placements of the visible `usb-drd,t8112` nodes, in DeviceTree order.
    pub usbs: Vec<UsbController>,
    /// `/arm-io/pmgr`'s power-state registers, when the DeviceTree shows the
    /// SoC's PMGR ([`pmgr`]).
    pub power_states: Option<PowerStates>,
    /// `/arm-io/mcc`, when the DeviceTree shows an `mcc,t8112`.
    pub memory_cache: Option<MemoryCache>,
    /// Direct T6000 resources; parsing does not grant native RAM/DSB authority.
    pub direct_memory_cache: Option<DirectMemoryCache>,
    /// The CPU clusters' PMGR registers, when the DeviceTree shows the SoC's
    /// PMGR and the SoC row describes them.
    pub clusters: Vec<CpuCluster>,
    /// The always-on eFuse block, under the same conditions.
    pub aon_fuses: Option<(u64, u64)>,
    /// CPU/CPM energy banks selected by `hw-dpe-reg`, in absolute guest PA.
    pub energy: Vec<EnergyBank>,
    /// SOC configuration banks, bound to translated PMGR `reg` entries.
    pub power_banks: Vec<PowerBank>,
    /// SOC DPE controls and absolute DT energy samples.
    pub soc_dpe: Option<SocDpe>,
    /// DT bridge maps, selected counter configurations and device dependencies.
    pub bridges: Vec<BridgeBank>,
    pub cluster_events: Vec<Vec<u8>>,
    /// AON/SOC/cluster performance banks and DT-selected counters.
    pub performance: Vec<PerfBank>,
    /// AOP wake masks and reporting source IDs.
    pub wake_masks: Option<WakeBank>,
    /// The CPU start registers' guest PA and the clusters they start, under
    /// the same conditions.
    pub cpu_start: Option<(u64, u8)>,
    /// Visible SPMI controllers and the PMUs on them.
    pub spmis: Vec<SpmiController>,
    /// The `dcpext` display coprocessor and its register apertures, when the
    /// DeviceTree shows them (admission is closed; see [`DcpController`]).
    pub dcp: Option<DcpController>,
}

/// A Dialog PMU's slave ID and the register windows its `info-*`
/// properties name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpmiPmu {
    pub sid: u8,
    /// Original is-primary controls global RTC service ownership, not register presence.
    pub primary: bool,
    /// PMU output's local edge vector, independently of the response vector.
    pub interrupt: Option<u16>,
    pub alarm_monitor: u8,
    pub rtc_helper: Option<smc::RtcKeyProfile>,
    pub identity: Option<pmu::Window>,
    /// Outside-scratch log, requiring explicit cold/retained history at placement.
    pub fault_log: Option<pmu::Window>,
    pub windows: Vec<pmu::Window>,
    pub rtc: Option<pmu::Rtc>,
}

pub type SpmiConfiguration = spmi::Configuration;

/// A source-qualified SPMI controller with independent FIFO/vector geometry
/// and an optional Gen1 fault-counter view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpmiController {
    pub configuration: SpmiConfiguration,
    pub fault_counters: Option<(u64, u64)>,
    pub banks: [(u64, u64); 2],
    pub irq: u32,
    pub pmus: Vec<SpmiPmu>,
}

/// An I2C child address is the first 32-bit `reg` cell followed by bus
/// timing, not a 64-bit MMIO address. HPM nubs instead use `hpm-iic-addr`.
/// `interrupt` is the AP GPIO pin of a target's own GPIO-parented
/// `interrupts`; an HPM has none of its own and shares its `iicProvider` bus
/// manager's line, which the dies' open-drain interrupt outputs drive.
/// `firmware` is the `usbc-fw-personality` of an HPM's image. J473AP names it
/// only on the flash-updated die (hpm0, `usbc-flash-update`); Stela
/// provisions every die on one manager with that image, so hpm1 shares it.
/// `port` is an HPM's connector `port-number`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct I2cAddress {
    pub address: u8,
    pub compatible: String,
    pub interrupt: Option<u32>,
    pub firmware: Option<String>,
    pub port: Option<u32>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct I2cController {
    pub device: Device,
    pub targets: Vec<I2cAddress>,
}

/// The guest file name of the image an HPM die with `personality` runs: the
/// name macOS keeps it under in `/usr/standalone/firmware`.
pub fn hpm_firmware_file(personality: &str) -> String {
    format!("USB-C_{personality}.bin")
}

impl Board {
    /// The board firmware images its devices run, by guest file name, each
    /// once: what a boot bundle must carry for the board's devices.
    pub fn firmware_files(&self) -> Vec<String> {
        let mut files: Vec<String> = Vec::new();
        for target in self.i2cs.iter().flat_map(|i2c| &i2c.targets) {
            if target.compatible != HPM {
                continue;
            }
            if let Some(personality) = &target.firmware {
                let file = hpm_firmware_file(personality);
                if !files.contains(&file) {
                    files.push(file);
                }
            }
        }
        files
    }
}

/// Digital PHY placement preserves all ADT views for evidence, but maps the
/// canonical USB2/core regions once. The pipehandler belongs to the same PHY
/// via `usb-drd*/atc-phy-parent`, whose `reg[3]` supplies its aperture; its
/// `reg[4]` is the PHY's own view 1, the core event block
/// (`AppleT8103TypeCPhy::initRegisterSpaces` keeps view n at +0x158 + 16n).
/// A PHY no `usb-drd` names (J414sAP `atc-phy3`, whose port has no USB
/// controller) has no pipehandler.
/// Unqualified shared fuse, AXI and analog-only views are not claimed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypecPhy {
    pub phandle: u32,
    pub retention: bool,
    pub views: Vec<(u64, u64)>,
    pub usb2: (u64, u64),
    pub core: (u64, u64),
    pub pipe: Option<(u64, u64)>,
    pub events: (u64, u64),
    pub port: u32,
}

fn typec_devices(
    io: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
    aic: u32,
    gpio: Option<&GpioBank>,
) -> Result<(Vec<I2cController>, Vec<TypecPhy>), String> {
    let mut i2cs = Vec::new();
    let mut phys = Vec::new();
    let mut failure = None;
    let place = |(offset, bytes): (u64, u64)| -> Result<_, String> {
        let first = translate(offset).ok_or("Type-C range starts outside arm-io ranges")?;
        if bytes == 0
            || offset.checked_add(bytes - 1).and_then(translate) != first.checked_add(bytes - 1)
        {
            return Err("Type-C range exceeds one arm-io translation".into());
        }
        Ok((first, bytes))
    };
    io.visit(&mut |node| {
        if failure.is_some() {
            return;
        }
        let result = (|| -> Result<(), String> {
            if node.compatible(I2C) {
                let regs = node.pairs("reg").ok_or("I2C controller has no reg pairs")?;
                let &[range] = regs.as_slice() else {
                    return Err("I2C controller requires one reg range".into());
                };
                let (physical, bytes) = place(range)?;
                if bytes != i2c::BYTES
                    || !physical.is_multiple_of(i2c::BYTES)
                    || node.first_u32("interrupt-parent") != Some(aic)
                {
                    return Err("unsupported I2C aperture or interrupt parent".into());
                }
                let irq = node
                    .first_u32("interrupts")
                    .filter(|&i| u16::try_from(i).is_ok())
                    .ok_or("I2C interrupt is absent or too large")?;
                let mut targets = Vec::new();
                // Each target's phandle and, for an HPM, its provider.
                let mut links: Vec<(Option<u32>, Option<u32>)> = Vec::new();
                let mut bad = None;
                let mut first = true;
                node.visit(&mut |target| {
                    if first {
                        first = false;
                        return;
                    }
                    let Some(compatible) = target
                        .property("compatible")
                        .and_then(|b| b.split(|b| *b == 0).next())
                        .and_then(|b| core::str::from_utf8(b).ok())
                    else {
                        return;
                    };
                    let address = if target.compatible(HPM) {
                        target.first_u32("hpm-iic-addr")
                    } else {
                        target.first_u32("reg")
                    };
                    let interrupt = match target.cells32("interrupts").as_deref() {
                        None => None,
                        Some(&[pin, _]) => match gpio {
                            Some(gpio)
                                if target.first_u32("interrupt-parent") == Some(gpio.phandle)
                                    && pin < gpio.pins =>
                            {
                                Some(pin)
                            }
                            _ => {
                                bad = Some("I2C target interrupt is not a visible AP GPIO pin");
                                return;
                            }
                        },
                        Some(_) => {
                            bad = Some("unsupported I2C target interrupt encoding");
                            return;
                        }
                    };
                    let firmware = target
                        .property("usbc-fw-personality")
                        .and_then(|b| b.split(|b| *b == 0).next())
                        .and_then(|b| core::str::from_utf8(b).ok())
                        .filter(|name| !name.is_empty())
                        .map(String::from);
                    match address
                        .and_then(|v| u8::try_from(v).ok())
                        .filter(|&v| v > 0 && v < 0x78)
                    {
                        Some(address)
                            if !targets.iter().any(|t: &I2cAddress| t.address == address) =>
                        {
                            links.push((
                                target.first_u32("AAPL,phandle"),
                                target
                                    .compatible(HPM)
                                    .then(|| target.first_u32("iicProvider"))
                                    .flatten(),
                            ));
                            targets.push(I2cAddress {
                                address,
                                compatible: compatible.into(),
                                interrupt,
                                firmware,
                                port: target
                                    .compatible(HPM)
                                    .then(|| target.first_u32("port-number"))
                                    .flatten(),
                            })
                        }
                        _ => {
                            bad = Some(
                                "I2C target has an invalid, missing or duplicate seven-bit address",
                            )
                        }
                    }
                })
                .ok_or("I2C target walk failed")?;
                if let Some(error) = bad {
                    return Err(error.into());
                }
                for index in 0..targets.len() {
                    if targets[index].compatible != HPM {
                        continue;
                    }
                    let provider = links[index]
                        .1
                        .and_then(|p| links.iter().position(|&(phandle, _)| phandle == Some(p)))
                        .filter(|&p| targets[p].compatible == HPM_MANAGER)
                        .ok_or("HPM has no visible usbc,manager iicProvider")?;
                    if targets[index].interrupt.is_some() || targets[index].port.is_none() {
                        return Err("HPM lacks a port number or names its own interrupt".into());
                    }
                    targets[index].interrupt = targets[provider].interrupt;
                    let mut images = (0..targets.len())
                        .filter(|&t| links[t].1 == links[index].1)
                        .filter_map(|t| targets[t].firmware.clone());
                    let image = images.next();
                    if images.any(|other| Some(other) != image) {
                        return Err("HPMs on one bus manager name different firmware".into());
                    }
                    targets[index].firmware = image;
                }
                i2cs.push(I2cController {
                    device: Device {
                        physical,
                        bytes,
                        irq,
                    },
                    targets,
                });
            }
            if let Some(&(layout, count)) = node
                .property("compatible")
                .into_iter()
                .flat_map(|list| list.split(|byte| *byte == 0))
                .find_map(|entry| {
                    ATC_PHY_LAYOUTS
                        .iter()
                        .find(|(layout, _)| layout.as_bytes() == entry)
                })
            {
                let reg = node.pairs("reg").ok_or("ATC PHY has no reg pairs")?;
                if reg.len() != count {
                    return Err(format!(
                        "{layout} ATC PHY requires its {count} register views"
                    ));
                }
                let views = reg.into_iter().map(place).collect::<Result<Vec<_>, _>>()?;
                let usb2 = views[0];
                let core = (views[3].0, atc_phy::CORE_BYTES);
                if usb2.1 != atc_phy::WINDOW_BYTES
                    || views[2].0
                        != core
                            .0
                            .checked_add(0x20000)
                            .ok_or("ATC core address overflows")?
                {
                    return Err(format!(
                        "ATC USB2/core views disagree with the {layout} layout"
                    ));
                }
                let phandle = node
                    .first_u32("AAPL,phandle")
                    .ok_or("ATC PHY has no phandle")?;
                let port = node
                    .first_u32("port-number")
                    .filter(|&p| p != 0)
                    .ok_or("ATC PHY has no port number")?;
                let mut controller_views = None;
                let mut duplicate = false;
                io.visit(&mut |controller| {
                    if controller.property("device_type") == Some(b"usb-drd\0".as_slice())
                        && controller.first_u32("atc-phy-parent") == Some(phandle)
                    {
                        duplicate |= controller_views.is_some();
                        controller_views = controller
                            .pairs("reg")
                            .and_then(|r| Some((*r.get(3)?, *r.get(4)?)));
                    }
                })
                .ok_or("ATC controller walk failed")?;
                let events = views[1];
                let pipe = match controller_views {
                    Some((pipe, controller_events)) => {
                        let pipe = place(pipe)?;
                        if pipe.1 != atc_phy::WINDOW_BYTES || place(controller_events)? != events {
                            return Err(
                                "ATC controller's pipehandler or event view disagrees".into()
                            );
                        }
                        Some(pipe)
                    }
                    None => None,
                };
                if duplicate || events.1 != atc_phy::WINDOW_BYTES {
                    return Err("ambiguous ATC controller or incomplete event view".into());
                }
                phys.push(TypecPhy {
                    phandle,
                    retention: node.property("retention").is_some(),
                    views,
                    usb2,
                    core,
                    pipe,
                    events,
                    port,
                });
            }
            Ok(())
        })();
        if let Err(error) = result {
            failure = Some(error);
        }
    })
    .ok_or("Type-C DeviceTree walk failed")?;
    if let Some(error) = failure {
        return Err(error);
    }
    Ok((i2cs, phys))
}

/// Placement from SPI `reg`/`interrupts`, `function-spi_cs0`, the GPIO
/// phandle and GPIO `reg`/`#gpio-pins`/`#gpio-int-groups`. No PA or pin is fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiNor {
    pub device: Device,
    pub image: nor::Image,
    /// The AP GPIO pin of an external chip select.
    pub select: Option<u32>,
}

/// The visible AP GPIO bank, from `reg`, `#gpio-pins`, its AIC-parented
/// `interrupts` (one per `#gpio-int-groups`) and phandle, with the board's
/// pulled-up I2C lines in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpioBank {
    pub profile: gpio::Profile,
    /// Original software restoration exclusions. The device model does not
    /// restore pads or implement global 0xc48/wake from this metadata.
    pub no_restore_pins: Vec<u32>,
    pub physical: u64,
    pub bytes: u64,
    pub pins: u32,
    /// `#gpio-int-groups`; the first `lines.len()` have an AIC line.
    pub groups: u32,
    pub phandle: u32,
    pub lines: Vec<u16>,
    /// The ADT's `gpio-iic_scl`/`gpio-iic_sda` pins in this bank.
    pub i2c_lines: Vec<u32>,
}

/// A node's one `reg` range, translated through contiguous `arm-io` ranges.
fn single_range(
    node: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
) -> Result<(u64, u64), &'static str> {
    let pairs = node.pairs("reg").ok_or("device reg missing")?;
    let [(offset, bytes)] = pairs[..] else {
        return Err("device requires one reg range");
    };
    let physical = translate(offset).ok_or("device outside arm-io ranges")?;
    let last = offset
        .checked_add(bytes.wrapping_sub(1))
        .filter(|_| bytes != 0)
        .ok_or("device span is empty or overflows")?;
    if translate(last) != physical.checked_add(bytes - 1) {
        return Err("device range exceeds arm-io ranges");
    }
    Ok((physical, bytes))
}

fn gpio_bank(
    io: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
    aic: u32,
) -> Result<Option<GpioBank>, String> {
    let Some(node) = AP_GPIO_NAMES
        .iter()
        .find_map(|name| io.child(name))
        .filter(|n| gpio_profile(|key| n.property(key)).is_some())
    else {
        return Ok(None);
    };
    let mut bank = gpio_geometry(&node, translate, aic)?;
    bank.i2c_lines = i2c_lines(io, bank.pins)?;
    Ok(Some(bank))
}

/// Another visible GPIO bank (`gpio,t8101` under `/arm-io` other than the
/// AP's `gpio`: J473AP's `aop-gpio` and `smc-gpio`), and the pins its
/// clients name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuxGpioBank {
    pub name: String,
    pub bank: GpioBank,
    /// Pins the tree's other nodes use: each `interrupts` pin of a node
    /// whose `interrupt-parent` is the bank (`[pin, flags]` pairs) and each
    /// `function-*` GPIO pin on it (`[bank, 'GPIO', pin, flags]`), such as
    /// `dp2hdmi-gpio`'s HDMI hot-plug input, `aop-gpio` pin 0x31.
    pub client_pins: Vec<u32>,
}

fn aux_gpio_banks(
    root: &Node<'_>,
    io: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
    aic: u32,
) -> Result<Vec<AuxGpioBank>, String> {
    let mut banks = Vec::new();
    for node in io.children().ok_or("/arm-io children are malformed")? {
        let name = node
            .property("name")
            .and_then(|name| core::str::from_utf8(name).ok())
            .map(|name| name.trim_end_matches('\0'))
            .unwrap_or_default();
        if AP_GPIO_NAMES.contains(&name) || !node.compatible(GPIO) {
            continue;
        }
        let bank =
            gpio_geometry(&node, translate, aic).map_err(|error| format!("{name}: {error}"))?;
        let mut client_pins = Vec::new();
        root.visit(&mut |client| {
            if client.first_u32("interrupt-parent") == Some(bank.phandle)
                && let Some(cells) = client.cells32("interrupts")
            {
                client_pins.extend(cells.as_chunks::<2>().0.iter().map(|[pin, _]| *pin));
            }
            for (property, value) in client.properties().unwrap_or_default() {
                if property.starts_with(b"function-")
                    && let Some([provider, GPIO_FUNCTION, pin, _]) = cells_of(value)
                    && provider == bank.phandle
                {
                    client_pins.push(pin);
                }
            }
        })
        .ok_or("DeviceTree walk failed")?;
        client_pins.sort_unstable();
        client_pins.dedup();
        if let Some(&pin) = client_pins.iter().find(|&&pin| pin >= bank.pins) {
            return Err(format!("{name}: a client names pin {pin} past the bank"));
        }
        banks.push(AuxGpioBank {
            name: name.into(),
            bank,
            client_pins,
        });
    }
    Ok(banks)
}

/// The AP GPIO bank's node: `gpio` in the M1 and M2 DeviceTrees, `gpio0`
/// (die 0) in the M2 Pro and Max and every later one (J414sAP, J504AP).
const AP_GPIO_NAMES: [&str; 2] = ["gpio", "gpio0"];
/// The pin words a bank's `#gpio-pins` may name (`platform::apple::gpio`).
const GPIO_PINS: u32 = 512;
/// The first interrupt group's status bank and the stride between groups
/// (`platform::apple::gpio`).
const GPIO_IRQ_BASE: u64 = 0x800;
const GPIO_IRQ_STRIDE: u64 = 0x40;

/// A `gpio,t8101` node's registers, pins, groups and AIC lines: up to
/// [`gpio::GROUPS`] interrupt groups, the first of which have the node's
/// `interrupts` as their lines.
fn gpio_geometry(
    node: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
    aic: u32,
) -> Result<GpioBank, String> {
    let (physical, bytes) = single_range(node, translate)?;
    let pins = node
        .first_u32("#gpio-pins")
        .ok_or("GPIO pin count missing")?;
    let groups = node
        .first_u32("#gpio-int-groups")
        .ok_or("GPIO group count missing")?;
    let lines = node
        .cells32("interrupts")
        .ok_or("GPIO interrupts missing")?
        .into_iter()
        .map(|irq| u16::try_from(irq).map_err(|_| "GPIO interrupt too large"))
        .collect::<Result<Vec<_>, _>>()?;
    if pins == 0
        || pins > GPIO_PINS
        || !(1..=gpio::GROUPS as u32).contains(&groups)
        || lines.is_empty()
        || lines.len() > groups as usize
        || node.first_u32("interrupt-parent") != Some(aic)
        || bytes < GPIO_IRQ_BASE + u64::from(groups) * GPIO_IRQ_STRIDE
    {
        return Err("unsupported GPIO geometry or interrupt parent".into());
    }
    let profile = gpio_profile(|key| node.property(key))
        .ok_or("GPIO register profile or board role is unqualified")?;
    let no_restore_pins = match node.property("no-restore-gpio-pins") {
        None => Vec::new(),
        Some(raw) if raw.len().is_multiple_of(4) => {
            let values = node.cells32("no-restore-gpio-pins").unwrap_or_default();
            if values
                .iter()
                .enumerate()
                .any(|(index, pin)| *pin >= pins || values[..index].contains(pin))
            {
                return Err(
                    "GPIO restoration exclusions contain an invalid or duplicate pin".into(),
                );
            }
            values
        }
        Some(_) => return Err("GPIO restoration exclusions have incomplete cells".into()),
    };
    if profile == gpio::Profile::S5l8960x
        && [
            "no-resume-restore",
            "supported-int-groups",
            "wake-events",
            "wake-no-interrupt-group",
        ]
        .iter()
        .any(|key| node.property(key).is_some())
    {
        return Err("S5L AP GPIO restoration/wake overrides are unqualified".into());
    }
    Ok(GpioBank {
        profile,
        no_restore_pins,
        physical,
        bytes,
        pins,
        groups,
        phandle: node
            .first_u32("AAPL,phandle")
            .ok_or("GPIO phandle missing")?,
        lines,
        i2c_lines: Vec::new(),
    })
}

/// The ADT cell naming the AP GPIO bank in a `gpio-iic_*` pin property
/// (`[pin, flags, bank]`); the AOP bank's pins (`AOP`) are not in it.
const AP_GPIO_BANK: u32 = 0x5041;

/// Every AP-bank pin an `arm-io` I2C node names as its SCL or SDA line.
fn i2c_lines(io: &Node<'_>, pins: u32) -> Result<Vec<u32>, String> {
    let mut lines = Vec::new();
    let mut failure = None;
    io.visit(&mut |node| {
        for name in ["gpio-iic_scl", "gpio-iic_sda"] {
            let Some(cells) = node.cells32(name) else {
                continue;
            };
            match cells[..] {
                [pin, _, AP_GPIO_BANK] if pin < pins => lines.push(pin),
                [_, _, bank] if bank != AP_GPIO_BANK => {}
                _ => failure = Some(format!("unsupported {name} pin encoding")),
            }
        }
    })
    .ok_or("I2C line walk failed")?;
    match failure {
        Some(error) => Err(error),
        None => Ok(lines),
    }
}

/// The opcode of a `function-*` property naming a GPIO pin: the FourCC
/// `GPIO`, first character in the high byte, as the ADT cells store it (the
/// J473AP `/arm-io/spi1` `function-spi_cs0` bytes `4f 49 50 47`).
pub const GPIO_FUNCTION: u32 = u32::from_be_bytes(*b"GPIO");

/// The byte-PIO SPI NOR topology. The 26A434 SPIMC driver accepts
/// `internal-cs`; otherwise `function-spi_cs0` names an Apple GPIO function
/// (four cells: provider phandle, 'GPIO', pin, function flags). J473AP uses
/// pin 49 with flags 0x10001; other function encodings refuse.
fn spi_nor(
    root: &Node<'_>,
    io: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
    aic: u32,
    gpio: Option<&GpioBank>,
) -> Result<Option<SpiNor>, String> {
    let Some(node) = io.child("spi1").filter(|n| n.compatible(SPI)) else {
        return Ok(None);
    };
    if node.first_u32("spi-version") != Some(1) {
        return Err("unsupported SPI version".into());
    }
    let (physical, bytes) = single_range(&node, translate)?;
    if bytes < spi::BYTES || node.first_u32("interrupt-parent") != Some(aic) {
        return Err("SPI aperture or interrupt parent is unsupported".into());
    }
    let irq = node
        .first_u32("interrupts")
        .filter(|&irq| irq <= u32::from(u16::MAX))
        .ok_or("SPI interrupt missing or too large")?;
    let flash = node
        .child("spinor")
        .filter(|n| n.compatible(NOR))
        .ok_or("SPI1 has no modeled NOR child")?;
    // AppleARMSPIDevice's 32-byte AppleARMSPIConfig: CS index,
    // clock period, CPOL/CPHA/bit order/word size, then delays.
    // The byte PIO model has only one MSB-first NOR slave, at CS0.
    let config = flash
        .property("reg")
        .ok_or("NOR SPI configuration missing")?;
    if config.len() != 32
        || config[..4] != [0; 4]
        || config[8] > 1
        || config[9] > 1
        || config[10..12] != [1, 8]
    {
        return Err("unsupported NOR SPI configuration or chip select".into());
    }
    if flash.cells32("ranges").as_deref() != Some(&[0, 0, nor::CAPACITY as u32]) {
        return Err("unsupported NOR ranges".into());
    }
    for (name, (offset, size)) in [
        ("firmware", nor::FIRMWARE),
        ("anvram", nor::ANVRAM),
        ("syscfg", nor::SYSCFG),
    ] {
        if flash.child(name).and_then(|n| n.cells32("reg")).as_deref() != Some(&[offset, size]) {
            return Err(format!(
                "NOR {name} lacks its supported boot-firmware partition"
            ));
        }
    }
    let chosen = root.child("chosen").ok_or("NVRAM chosen missing")?;
    if chosen.first_u32("nvram-bank-size") != Some(nor::nvram::BANK_SIZE as u32)
        || chosen.first_u32("nvram-bank-count") != Some(nor::nvram::BANK_COUNT)
    {
        return Err("unsupported NVRAM bank geometry".into());
    }
    let current = chosen
        .first_u32("nvram-current-bank")
        .ok_or("NVRAM current bank missing")?;
    let proxy = chosen
        .property("nvram-proxy-data")
        .ok_or("NVRAM proxy missing")?;
    let image = nor::Image::fresh()
        .with_proxy(current, proxy)
        .map_err(String::from)?;
    let select = if node.property("internal-cs").is_some() {
        None
    } else {
        let cells = node
            .cells32("function-spi_cs0")
            .ok_or("SPI external chip select missing")?;
        let [phandle, opcode, pin, flags] = cells[..] else {
            return Err("invalid SPI chip-select function".into());
        };
        if opcode != GPIO_FUNCTION || flags != 0x10001 {
            return Err("unsupported SPI chip-select function encoding".into());
        }
        let gpio = gpio
            .filter(|gpio| gpio.phandle == phandle)
            .ok_or("SPI CS GPIO provider is absent or unmodeled")?;
        if pin >= gpio.pins {
            return Err("SPI chip select beyond the GPIO bank".into());
        }
        if gpio.i2c_lines.contains(&pin) {
            return Err("SPI chip select shares an I2C line".into());
        }
        Some(pin)
    };
    Ok(Some(SpiNor {
        device: Device {
            physical,
            bytes,
            irq,
        },
        image,
        select,
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeBank {
    pub physical: u64,
    pub fields: Vec<(u64, u32)>,
    pub header: [u8; 4],
    pub configs: Vec<[u8; 36]>,
    pub axi: Option<[u8; 4]>,
    /// IDs whose `device-bridges` dependency list names this bridge.
    pub devices: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocDpe {
    pub physical: u64,
    pub samples: Vec<(u64, bool)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerBank {
    pub physical: u64,
    pub kind: power::Kind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeBank {
    pub physical: u64,
    pub valid: [u32; wake::WORDS],
    pub sources: Vec<u8>,
    /// `ap-wake-sources`' `SMC.CPUWakeupAP`: the SMC waking the AP.
    pub smc_wake: Option<u8>,
}

/// A version-1 `perf-regs` group: translated global word and the union of
/// selectors named by the DeviceTree's counter-bearing records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerfBank {
    pub physical: u64,
    pub selectors: Vec<u16>,
}

/// A direct CPU energy bank, with its optional CPM enable configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnergyBank {
    pub physical: u64,
    pub cpm: bool,
}

/// An `mcc,t8112`: its cache in the AMCC aperture, its DRAM channels and
/// the PMP PTD bank it writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryCache {
    pub cache: amcc::Cache,
    /// The DCS channels (`reg[2]`) in guest PA: base, bytes and the
    /// `dcs_num_channels` that share them evenly.
    pub channels: (u64, u64, usize),
    /// The PMP's PTD bank, `reg[pmp_ptd_reg_idx]`.
    pub ptd: PtdBank,
}

/// The PMP's PTD bank (`platform::apple::ptd`): its guest PA and the
/// `ptd-range` records of `/arm-io/pmp/iop-pmp-nub`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtdBank {
    pub physical: u64,
    pub ranges: Vec<ptd::Range>,
    /// Original fourth word, in exactly the same order as ranges. Not AIC IDs.
    pub interrupts: Vec<u32>,
}

/// A `ptd-range` record's bytes: id, first entry, entries, interrupt and a
/// 16-byte name.
const PTD_RANGE: usize = 32;

/// One translation instance, retaining its native logical number and the
/// physical `reg` ordinal. Legacy 12-byte descriptors contain kind+owner;
/// their logical number counts translation occurrences. Modern 16-byte
/// descriptors additionally encode the logical number. Owner bytes never
/// select application behavior or DMA routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DartInstance {
    pub physical: u64,
    pub bytes: u64,
    pub number: u32,
    pub reg_index: usize,
    pub owner: [u8; 8],
}

/// A DT DART group, its independently programmed TRAD windows, mapper stream
/// IDs and optional APF. Modern `sid` is a list of u32 SIDs; legacy `sids`
/// is a bitmap. Neither selects a translation instance. Modern `remap`
/// contains byte source/destination pairs, with 0/0 padding ignored
/// (0x2f11864..0x2f11938). They describe routing, not permission to bypass
/// the DART. Per-instance DMA selection remains the bus master's contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iommu {
    pub profile: dart::Profile,
    pub instances: Vec<DartInstance>,
    pub streams: u16,
    pub irq: u32,
    pub mappers: Vec<(u32, u32)>,
    pub apf: Option<(u64, usize)>,
    /// Separate original PMGR clock and power requirements.
    pub clock_gates: Vec<u16>,
    pub power_gates: Vec<u16>,
    /// A retained DART preserves ordinary state while its supply is gated.
    pub retention: bool,
    pub sids: Vec<u32>,
    pub remap: Vec<(u8, u8)>,
    /// The base of the I/O window its mappers allocate in (`vm-base`).
    pub vm_base: u64,
    /// Its SMMU instance's register block, an `instance` descriptor of kind
    /// `UMMS` after its TRAD instances (J473AP `dart-dispext0`).
    /// `AppleT8110DART::_smmuSetupInstance` (26A434 KC file 0x2f12b64) maps
    /// that numbered `reg` entry and records it, and `_smmuSetup` (0x2f12af0)
    /// marks the DART as having one. The kernel reads it for fault capture
    /// (`_smmuCaptureHardwareState` 0x2f1a3ec, `_smmuCaptureRegs` 0x2f1d2b4),
    /// and SPTM validates its capture count during startup (file 0xcabb8).
    /// The paired native cacheless view reports zero capture words and shares
    /// its DART's lifecycle; absent selector/data accesses refuse by name.
    pub smmu: Option<(u64, u64)>,
}

/// The AES engine: its block and key-disable register ranges, its
/// `aes-version`, its AIC input, and the [`Board::darts`] index and stream
/// of its `iommu-parent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AesEngine {
    pub phandle: Option<u32>,
    pub mapper: u32,
    pub mapper_context: u32,
    pub instance: usize,
    pub ranges: [(u64, u64); 2],
    pub version: u32,
    pub irq: u32,
    pub iommu: usize,
    pub stream: u32,
}

pub type AnsQueueGeometry = ans::QueueGeometry;

/// ANS2's DT placement. `reg[0]` is the ASC wrapper; `reg[3]` is the
/// NVMe aperture. `iommu-parent` names SART itself, not a DART stream.
/// J473AP: `IOCoastGuardSARTMapper::start` (kernel file 0x2ccada8),
/// `AppleANS2NVMeController::start` (0x3dbb040); neither map is guessed.
/// `vdma` is `reg[13]`, which SPTM reads only under `nvme-vdma-wa`
/// (`ans::VDMA_CACHE_OFFSET`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnsController {
    pub geometry: AnsQueueGeometry,
    pub wrapper: (u64, u64),
    pub nvme: (u64, u64),
    pub vdma: Option<(u64, u64)>,
    pub sart: (u64, u64),
    pub sart_idle: u64,
    /// The SART node's `exclusive-bounds`: entry SIZEs count pages rather
    /// than naming the last one ([`sart::Bounds`]).
    pub sart_exclusive_bounds: bool,
    pub interrupts: [u16; 4],
    pub completion_irq: u16,
    pub namespaces: Vec<ans::Description>,
    pub clock_gates: Vec<u32>,
    pub power_gates: Vec<u32>,
}

/// The SMC's DT placement: `reg[0]` is the ASC wrapper, its four
/// interrupts the mailbox lines, `reg[timers-reg-index]` the hardware
/// watchdog AppleSMC maps, and its RTBuddy nub's `region-base`/`region-size`
/// the window AppleSMCKeysEndpoint accepts the shared page in
/// (`_keyEndpointHandler`, 0xfffffe0009da5a20). `gpio_keys` are the keys
/// the tree's `pKW4` platform functions write through the nub's `smc-pmu`.
/// `quiesced` is the nub's hand-off state (`rtkit::RtKit::quiesced`).
/// `wake_bits` are the `MBSW` bits `smc-pmu`'s `event_name-bitN`
/// properties name for the wake sources the board models.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmcController {
    pub wrapper: (u64, u64),
    pub interrupts: [u16; 4],
    pub watchdog: Option<(u64, u64)>,
    pub region: (u64, u64),
    pub gpio_keys: Vec<u32>,
    pub quiesced: bool,
    pub wake_bits: smc::WakeBits,
}

/// The PMP's DT placement: `reg[0]` is the ASC wrapper and its four
/// interrupts the mailbox lines. Its nub is `user-power-managed`; the
/// PTD bank that `ptd-update-reg-index` names is [`MemoryCache`]'s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PmpController {
    pub wrapper: (u64, u64),
    pub interrupts: [u16; 4],
    pub quiesced: bool,
}

fn pmp_controller(
    io: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
) -> Result<Option<PmpController>, String> {
    let Some(node) = io
        .child("pmp")
        .filter(|n| n.compatible(ASC) && n.property("role") == Some(b"PMP\0".as_slice()))
    else {
        return Ok(None);
    };
    let nub = rtbuddy_nub(&node, "PMP")?;
    if nub.first_u32("user-power-managed") != Some(1) {
        return Err("PMP nub is not user-power-managed".into());
    }
    let &(offset, bytes) = node
        .pairs("reg")
        .ok_or("PMP has no reg pairs")?
        .first()
        .filter(|(_, bytes)| *bytes >= asc::WRAPPER_BYTES)
        .ok_or("PMP wrapper bank is absent or too short")?;
    let physical = translate(offset).ok_or("PMP wrapper outside arm-io ranges")?;
    let irqs = node.cells32("interrupts").ok_or("PMP has no interrupts")?;
    let irq = |index: usize| -> Result<u16, String> {
        irqs.get(index)
            .and_then(|&n| u16::try_from(n).ok())
            .ok_or_else(|| "PMP needs four valid mailbox interrupts".into())
    };
    Ok(Some(PmpController {
        wrapper: (physical, bytes),
        interrupts: [irq(0)?, irq(1)?, irq(2)?, irq(3)?],
        quiesced: nub.property("quiesced").is_some(),
    }))
}

/// The GPU's firmware mapper's compatible.
pub const GFX_MAPPER: &str = "iommu-mapper,gfx";

/// Whether `compatible` names an `sgx` GPU whose whole interface is modeled
/// on every SoC that carries it (`agx::generation`, every SoC 26A434
/// supports; only admitted ones stay visible).
pub fn admitted_gpu(compatible: &str) -> bool {
    agx::generation::compatible_admitted(compatible)
}

/// The AGX GPU's DT placement: the `gfx-asc` wrapper (`reg[0]`) and its four
/// mailbox interrupts, and the `sgx` register banks. The firmware reaches
/// memory through the UAT the `sgx` MMU configuration roots, which
/// `gfx-asc`'s `iommu-parent` (`mapper-gfx-asc`, `AGXArmFirmwareMapper`)
/// names; no DART stream is involved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GfxController {
    /// The census entry the `sgx` node's `compatible` names.
    pub gpu: &'static agx::generation::Gpu,
    pub wrapper: (u64, u64),
    pub interrupts: [u16; 4],
    /// The `sgx` banks as `(physical base, bytes, register offset)`. Register
    /// offsets are relative to `reg[0]`'s base, as `readGFXReg32` takes them:
    /// `reg[0]` is the first bank, and `reg[1]` another unless it lies inside
    /// `reg[0]` (T8112). On the Pro/Max SoCs `reg[0]` is 1 MiB and the
    /// registers lie in `reg[1]` (docs/research/agx.md §6).
    pub sgx: Vec<(u64, u64, u64)>,
    /// The GPU's TTBAT as the boot stage publishes it (`gptbat-ready`,
    /// `ttbat-phys-addr-base` in 16 KiB pages; the loader sets it to
    /// `gpu-region-base`): the MMU is handed off rooted there
    /// ([`agx::sgx::Sgx::handed_off`]).
    pub ttbat: u64,
    /// The shared TTBR1 window's page-directory page (`gfx-shared-l2-region`,
    /// one page, as SPTM's `uat_bootstrap_parse_dt` requires).
    pub shared_l2: u64,
}

/// The `sgx` banks of [`GfxController::sgx`] from `reg[0]` and `reg[1]`
/// (physical base, bytes).
fn sgx_banks(block: (u64, u64), info: (u64, u64)) -> Result<Vec<(u64, u64, u64)>, &'static str> {
    if info.0 < block.0 {
        return Err("sgx reg[1] lies below reg[0]");
    }
    let mut banks = vec![(block.0, block.1, 0)];
    if info.0 + info.1 > block.0 + block.1 {
        if info.0 < block.0 + block.1 {
            return Err("sgx reg[1] straddles the end of reg[0]");
        }
        banks.push((info.0, info.1, info.0 - block.0));
    }
    Ok(banks)
}

fn gfx_controller(
    io: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
    chip_id: u32,
) -> Result<Option<GfxController>, String> {
    let asc = io
        .child("gfx-asc")
        .filter(|n| n.compatible(ASC) && n.property("role") == Some(b"GFX\0".as_slice()));
    // Several SoCs share one `sgx` compatible; the chip names the GPU.
    let sgx = io.child("sgx").filter(|n| {
        agx::generation::GPUS
            .iter()
            .any(|gpu| n.compatible(gpu.compatible))
    });
    let (asc, sgx) = match (asc, sgx) {
        (None, None) => return Ok(None),
        (Some(asc), Some(sgx)) => (asc, sgx),
        _ => return Err("the GFX coprocessor and the sgx GPU must be visible together".into()),
    };
    let gpu = agx::generation::by_chip(chip_id)
        .filter(|gpu| sgx.compatible(gpu.compatible))
        .ok_or_else(|| format!("sgx is not the GPU of ApChipID {chip_id:#x}"))?;
    gpu.admitted()
        .map_err(|reason| format!("{} is not modeled: {reason}", gpu.compatible))?;
    rtbuddy_nub(&asc, "GFX")?;
    let place = |node: &Node<'_>, index: usize, minimum: u64, what: &str| {
        let (offset, bytes) = node
            .pairs("reg")
            .and_then(|regs| regs.get(index).copied())
            .filter(|&(_, bytes)| bytes >= minimum)
            .ok_or_else(|| format!("{what} bank is absent or too short"))?;
        let physical = translate(offset).ok_or_else(|| format!("{what} outside arm-io ranges"))?;
        Ok::<_, String>((physical, bytes))
    };
    let wrapper = place(&asc, 0, asc::WRAPPER_BYTES, "gfx-asc wrapper")?;
    let block = place(&sgx, 0, 1, "sgx register")?;
    let info = place(&sgx, 1, 1, "sgx info")?;
    let banks = sgx_banks(block, info)?;
    agx::sgx::covers(gpu.family, &banks)?;
    let irqs = asc
        .cells32("interrupts")
        .ok_or("gfx-asc has no interrupts")?;
    let irq = |index: usize| -> Result<u16, String> {
        irqs.get(index)
            .and_then(|&n| u16::try_from(n).ok())
            .ok_or_else(|| "gfx-asc needs four valid mailbox interrupts".into())
    };
    if sgx.property("gptbat-ready").is_none() {
        return Err("sgx has no gptbat-ready: the boot stage published no GPU TTBAT".into());
    }
    let ttbat = sgx
        .property("ttbat-phys-addr-base")
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(|page| u64::from(u32::from_le_bytes(page)) << agx::uat::PAGE_SHIFT)
        .filter(|&base| base != 0)
        .ok_or("sgx ttbat-phys-addr-base is not one nonzero 32-bit page number")?;
    let u64_property = |name: &str| {
        sgx.property(name)
            .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
            .map(u64::from_le_bytes)
    };
    let shared_l2 = match (
        u64_property("gfx-shared-l2-region-base"),
        u64_property("gfx-shared-l2-region-size"),
    ) {
        (Some(base), Some(agx::uat::PAGE_BYTES)) if base != 0 => base,
        _ => return Err("sgx gfx-shared-l2-region is not one nonzero 16 KiB page".into()),
    };
    Ok(Some(GfxController {
        gpu,
        wrapper,
        interrupts: [irq(0)?, irq(1)?, irq(2)?, irq(3)?],
        sgx: banks,
        ttbat,
        shared_l2,
    }))
}

/// A platform function property is the provider's phandle, the function's
/// four-character code and its arguments, all little-endian u32 cells
/// (`function-reg_on` = smc-pmu, `pKW4`, `gP0d`, 0x8000).
const SMC_GPIO_WRITE: u32 = smc::code(b"pKW4");

fn smc_controller(
    root: &Node<'_>,
    io: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
) -> Result<Option<SmcController>, String> {
    let Some(node) = io
        .child("smc")
        .filter(|n| n.compatible(ASC) && n.property("role") == Some(b"SMC\0".as_slice()))
    else {
        return Ok(None);
    };
    let nub = rtbuddy_nub(&node, "SMC")?;
    let regs = node.pairs("reg").ok_or("SMC has no reg pairs")?;
    let place = |index: usize, minimum: u64, what: &str| -> Result<(u64, u64), String> {
        let &(offset, bytes) = regs
            .get(index)
            .filter(|(_, bytes)| *bytes >= minimum)
            .ok_or_else(|| format!("SMC {what} bank is absent or too short"))?;
        let physical =
            translate(offset).ok_or_else(|| format!("SMC {what} outside arm-io ranges"))?;
        Ok((physical, bytes))
    };
    let wrapper = place(0, asc::WRAPPER_BYTES, "wrapper")?;
    let watchdog = node
        .first_u32("timers-reg-index")
        .map(|index| place(index as usize, smc::WATCHDOG_BYTES, "watchdog"))
        .transpose()?;
    let irqs = node.cells32("interrupts").ok_or("SMC has no interrupts")?;
    let irq = |index: usize| -> Result<u16, String> {
        irqs.get(index)
            .and_then(|&n| u16::try_from(n).ok())
            .ok_or_else(|| "SMC needs four valid mailbox interrupts".into())
    };
    let interrupts = [irq(0)?, irq(1)?, irq(2)?, irq(3)?];
    let read64 = |name: &str| {
        nub.property(name)
            .and_then(|value| value.try_into().ok())
            .map(u64::from_le_bytes)
    };
    let (base, size) = read64("region-base")
        .zip(read64("region-size"))
        .ok_or("SMC nub has no region-base/region-size")?;
    if size < smc::SRAM_BYTES {
        return Err("SMC region is smaller than the shared page".into());
    }
    let mut gpio_keys = Vec::new();
    let mut wake_bits = smc::WakeBits::default();
    // By name: the loader removes a hidden `smc-pmu`'s compatible, but the
    // keys its functions name are the SMC's whatever the AP binds.
    if let Some(pmu) = nub.child("smc-pmu") {
        // AppleSMCPMU names each set MBSW bit by its `event_name-bitN`
        // (`nameWakeReason`, file 0x2da12ec).
        for (name, value) in pmu.properties().unwrap_or_default() {
            let Some(bit) = name
                .strip_prefix(b"event_name-bit")
                .and_then(|digits| core::str::from_utf8(digits).ok())
                .and_then(|digits| digits.parse::<u8>().ok())
                .filter(|&bit| bit < 64)
            else {
                continue;
            };
            match value.split(|&b| b == 0).next() {
                Some(b"pwrbtn") => wake_bits.power_button = Some(bit),
                Some(b"rtc") => wake_bits.rtc = Some(bit),
                _ => {}
            }
        }
        let phandle = pmu
            .first_u32("AAPL,phandle")
            .ok_or("smc-pmu has no phandle")?;
        root.visit(&mut |candidate| {
            for (name, value) in candidate.properties().unwrap_or_default() {
                if name.starts_with(b"function-")
                    && let Some([provider, function, key, _]) = cells_of(value)
                    && provider == phandle
                    && function == SMC_GPIO_WRITE
                {
                    gpio_keys.push(key);
                }
            }
        })
        .ok_or("DeviceTree walk failed")?;
    }
    gpio_keys.sort_unstable();
    gpio_keys.dedup();
    Ok(Some(SmcController {
        wrapper,
        interrupts,
        watchdog,
        region: (base, size),
        gpio_keys,
        quiesced: nub.property("quiesced").is_some(),
        wake_bits,
    }))
}

/// Every visible `aapl,spmi` controller under `/arm-io`. The `interrupts`
/// cells pair with `interrupt-parent` entries in order, the last parent
/// covering the remaining cells; the one whose parent is the AIC is the
/// controller's line, the others its own vectors.
fn spmi_controllers(
    io: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
    aic: u32,
) -> Result<Vec<SpmiController>, String> {
    let mut controllers = Vec::new();
    for node in io.children().ok_or("/arm-io children are malformed")? {
        if !node.compatible(SPMI) {
            continue;
        }
        if node.property("gen").is_none_or(|bytes| bytes.len() != 4) {
            return Err("SPMI generation is not one full32 word".into());
        }
        let profile = match node.first_u32("gen") {
            Some(1) => spmi::Profile::Gen1,
            Some(2) => spmi::Profile::Gen2,
            _ => return Err("SPMI controller generation is unqualified".into()),
        };
        let regs = node.pairs("reg").ok_or("SPMI controller has no reg")?;
        if node
            .property("reg")
            .is_none_or(|bytes| bytes.len() != regs.len() * 16)
        {
            return Err("SPMI controller has partial reg pairs".into());
        }
        let bank = |index: usize| -> Result<(u64, u64), String> {
            let &(offset, bytes) = regs
                .get(index)
                .filter(|(_, bytes)| *bytes == profile.bank_bytes())
                .ok_or("SPMI controller banks do not match the qualified handler geometry")?;
            let physical = translate(offset).ok_or("SPMI bank outside arm-io ranges")?;
            if !physical.is_multiple_of(4)
                || offset.checked_add(bytes - 1).and_then(translate)
                    != physical.checked_add(bytes - 1)
            {
                return Err("SPMI bank is unaligned or crosses arm-io ranges".into());
            }
            Ok((physical, bytes))
        };
        let parents = node
            .cells32("interrupt-parent")
            .ok_or("SPMI controller has no interrupt-parent")?;
        let cells = node
            .cells32("interrupts")
            .ok_or("SPMI controller has no interrupts")?;
        let irq = parents
            .iter()
            .position(|&parent| parent == aic)
            .and_then(|index| cells.get(index).copied())
            .ok_or("SPMI controller has no AIC line")?;
        let local = node
            .first_u32("AAPL,phandle")
            .ok_or("SPMI has no phandle")?;
        if node
            .property("AAPL,phandle")
            .is_none_or(|bytes| bytes.len() != 4)
            || node
                .property("interrupt-parent")
                .is_none_or(|bytes| bytes.len() != 12)
            || node
                .property("interrupts")
                .is_none_or(|bytes| !bytes.len().is_multiple_of(4))
            || parents.as_slice() != [local, aic, local]
            || cells.len() < 2
            || cells
                .iter()
                .enumerate()
                .any(|(index, &vector)| index != 1 && vector >= 288)
        {
            return Err("SPMI interrupt-parent/vector routing is unqualified".into());
        }
        let queue_bytes: [u32; 2] = node
            .cells32("queue-depth")
            .filter(|_| {
                node.property("queue-depth")
                    .is_some_and(|bytes| bytes.len() == 8)
            })
            .and_then(|cells| cells.try_into().ok())
            .ok_or("SPMI has no two FIFO byte depths")?;
        let configuration =
            spmi::Configuration::new(profile, cells[0], queue_bytes).map_err(String::from)?;
        let counters = match node.property("fault-counters-enabled") {
            None => false,
            Some(bytes) if bytes.len() == 4 => match node.first_u32("fault-counters-enabled") {
                Some(0) => false,
                Some(1) => true,
                _ => return Err("SPMI fault-counter enable encoding is unqualified".into()),
            },
            _ => return Err("SPMI fault-counter enable is not one full32 word".into()),
        };
        let fault_counters = if counters && profile == spmi::Profile::Gen1 {
            let &(offset, bytes) = regs
                .get(2)
                .filter(|(_, bytes)| Some(*bytes) == profile.counter_bytes())
                .ok_or("SPMI Gen1 needs its separate fault-counter bank")?;
            let physical = translate(offset).ok_or("SPMI fault counters outside arm-io ranges")?;
            if !physical.is_multiple_of(4)
                || offset.checked_add(bytes - 1).and_then(translate)
                    != physical.checked_add(bytes - 1)
            {
                return Err("SPMI fault counters are unaligned or cross arm-io ranges".into());
            }
            Some((physical, bytes))
        } else {
            None
        };
        let expected = if fault_counters.is_some() { 3 } else { 2 };
        if regs.len() != expected {
            return Err("SPMI has an unqualified extra register view".into());
        }
        let mut pmus = Vec::new();
        for child in node.children().ok_or("SPMI children are malformed")? {
            if child.compatible(PMU) {
                let pmu = spmi_pmu(&child, io)?;
                if pmu.interrupt.is_some()
                    && (child
                        .property("interrupt-parent")
                        .is_none_or(|bytes| bytes.len() != 4)
                        || child.first_u32("interrupt-parent") != Some(local))
                {
                    return Err("PMU output is not parented by its own SPMI controller".into());
                }
                pmus.push(pmu);
            }
        }
        controllers.push(SpmiController {
            configuration,
            fault_counters,
            banks: [bank(0)?, bank(1)?],
            irq,
            pmus,
        });
    }
    if controllers
        .iter()
        .flat_map(|controller| &controller.pmus)
        .filter(|pmu| pmu.primary)
        .count()
        > 1
    {
        return Err("multiple primary PMU system-service owners".into());
    }
    Ok(controllers)
}

/// A PMU's slave ID (`reg` cell 0) and its `info-*` windows: pairs are
/// `<base bytes>`, single cells one byte, except the legacy scratchpad.
fn spmi_pmu(node: &Node<'_>, io: &Node<'_>) -> Result<SpmiPmu, String> {
    let sid = node
        .first_u32("reg")
        .and_then(|sid| u8::try_from(sid).ok())
        .filter(|&sid| sid <= 0xf)
        .ok_or("PMU has no four-bit SPMI slave ID")?;
    let primary = match node.property("is-primary") {
        None => false,
        Some(bytes) if bytes.len() == 4 => match node.first_u32("is-primary") {
            Some(0) => false,
            Some(1) => true,
            _ => return Err("PMU primary-service encoding is unqualified".into()),
        },
        _ => return Err("PMU is-primary is not one full32 word".into()),
    };
    let interrupt = match node.property("interrupts") {
        None => None,
        Some(bytes) if bytes.len() == 4 => Some(
            node.first_u32("interrupts")
                .and_then(|vector| u16::try_from(vector).ok())
                .filter(|&vector| vector < 288)
                .ok_or("PMU local interrupt vector exceeds the SPMI input bank")?,
        ),
        _ => return Err("PMU interrupt vector is not one full32 word".into()),
    };
    let address = |value: u32| u16::try_from(value).map_err(|_| "PMU address above 16 bits");
    let pair = |name: &str| -> Result<Option<pmu::Window>, String> {
        match node.cells32(name).as_deref() {
            None => Ok(None),
            Some(&[base, bytes]) if node.property(name).is_some_and(|value| value.len() == 8) => {
                Ok(Some(pmu::Window {
                    base: address(base)?,
                    bytes: address(bytes)?,
                }))
            }
            Some(_) => Err(format!("PMU {name} is not <base bytes>")),
        }
    };
    let single = |name: &str| -> Result<Option<u16>, String> {
        if node.property(name).is_some_and(|bytes| bytes.len() != 4) {
            return Err(format!("PMU {name} is not one full32 word"));
        }
        node.first_u32(name)
            .map(address)
            .transpose()
            .map_err(String::from)
    };
    let scratch = pair("info-scrpad")?;
    let mut windows = Vec::new();
    windows.extend(scratch);
    windows.extend(pair("info-fault_shadow")?);
    let fault_log = match pair("info-fault_log")? {
        None => None,
        Some(log) => {
            let end = u32::from(log.base) + u32::from(log.bytes);
            if log.bytes == 0 || log.bytes > u16::from(u8::MAX) || end > 0x10000 {
                return Err(
                    "PMU fault-log count or extent exceeds the qualified byte-count resource"
                        .into(),
                );
            }
            if let Some(scratch) = scratch {
                let scratch_end = u32::from(scratch.base) + u32::from(scratch.bytes);
                let overlaps = u32::from(log.base) < scratch_end && u32::from(scratch.base) < end;
                if overlaps {
                    if log.base < scratch.base || end > scratch_end {
                        return Err("PMU fault log partially aliases scratch storage".into());
                    }
                    None // Same canonical scratch owner; original zero-clear form.
                } else {
                    Some(log)
                }
            } else {
                Some(log)
            }
        }
    };
    if let Some(base) = single("info-leg_scrpad")? {
        windows.push(pmu::Window {
            base,
            bytes: pmu::LEGACY_SCRATCH_BYTES,
        });
    }
    if let Some(base) = single("info-pm_setting")? {
        windows.push(pmu::Window { base, bytes: 1 });
    }
    // The SOCD and LPM windows lie inside the scratchpad.
    let inside = |base: u16, bytes: u16| {
        windows.iter().any(|w| {
            base >= w.base
                && u32::from(base) + u32::from(bytes) <= u32::from(w.base) + u32::from(w.bytes)
        })
    };
    if let Some(socd) = pair("info-scrpad_socd")?
        && !inside(socd.base, socd.bytes)
    {
        return Err("PMU SOCD scratchpad outside its scratchpad".into());
    }
    for name in ["info-scrpad_lpm_log", "info-scrpad_lpm_ctrl"] {
        if let Some(base) = single(name)?
            && !inside(base, 1)
        {
            return Err(format!("PMU {name} outside its scratchpad"));
        }
    }
    let rtc = match single("info-rtc")? {
        None => None,
        Some(upcount) => {
            let need = |name: &str| -> Result<u16, String> {
                single(name)?.ok_or_else(|| format!("PMU RTC has no {name}"))
            };
            let clock_offset = pair("info-clock_offset")?
                .filter(|w| w.bytes == 6)
                .ok_or("PMU RTC clock offset is not six bytes")?;
            if node
                .property("info-rtc_alarm_ctrl_en_mask")
                .is_none_or(|bytes| bytes.len() != 4)
            {
                return Err("PMU alarm enable mask is not one full32 word".into());
            }
            let alarm_enable = node
                .first_u32("info-rtc_alarm_ctrl_en_mask")
                .and_then(|mask| u8::try_from(mask).ok())
                .ok_or("PMU RTC has no alarm enable mask")?;
            let bits = |name: &str| -> Result<Option<u8>, String> {
                if node.property(name).is_some_and(|bytes| bytes.len() != 4) {
                    return Err(format!("PMU {name} is not one full32 word"));
                }
                node.first_u32(name)
                    .map(|mask| {
                        u8::try_from(mask).map_err(|_| format!("PMU {name} exceeds a byte"))
                    })
                    .transpose()
            };
            Some(pmu::Rtc {
                upcount,
                clock_offset: clock_offset.base,
                alarm_control: need("info-rtc_alarm_ctrl")?,
                alarm_enable,
                alarm_offset: need("info-rtc_alarm_offset")?,
                alarm_event: need("info-rtc_alarm_event")?,
                irq_mask: need("info-rtc_irq_mask_offset")?,
                event_mask: bits("info-rtc_alarm_event_mask")?.unwrap_or(pmu::DEFAULT_EVENT_MASK),
                interrupt_mask: bits("info-rtc_alarm_mask")?
                    .ok_or("PMU RTC has no info-rtc_alarm_mask")?,
            })
        }
    };
    let alarm_monitor = if rtc.is_some() {
        single("info-rtc_alarm_monitor_mask")?
            .and_then(|mask| u8::try_from(mask).ok())
            .ok_or("PMU RTC has no byte monitor mask")?
    } else {
        0
    };
    if (primary || interrupt.is_some()) && rtc.is_none() {
        return Err("PMU global service/output requires a qualified RTC owner".into());
    }
    let rtc_helper = match node.property("function-rtc_read_helper") {
        None => None,
        Some(bytes) => {
            if !primary || rtc.is_none() || bytes.len() != 12 {
                return Err(
                    "RTC helper requires a primary RTC and complete three-cell descriptor".into(),
                );
            }
            let source = io
                .child("smc")
                .filter(|node| {
                    node.compatible(ASC) && node.property("role") == Some(b"SMC\0".as_slice())
                })
                .ok_or("RTC helper has no qualified visible SMC provider")?;
            let nub = rtbuddy_nub(&source, "SMC")?;
            let provider = nub
                .child("smc-pmu")
                .ok_or("RTC helper has no SMC PMU provider")?;
            if provider
                .property("AAPL,phandle")
                .is_none_or(|bytes| bytes.len() != 4)
            {
                return Err("SMC PMU provider phandle is not one full32 word".into());
            }
            let provider = provider
                .first_u32("AAPL,phandle")
                .ok_or("SMC PMU has no phandle")?;
            let cells = node
                .cells32("function-rtc_read_helper")
                .ok_or("RTC helper has no cells")?;
            Some(smc::RtcKeyProfile::from_function(&cells, provider).map_err(String::from)?)
        }
    };
    let identity = pair("info-id")?;
    let mut configuration =
        pmu::Configuration::new(windows.clone(), rtc, alarm_monitor).map_err(String::from)?;
    if let Some(log) = fault_log {
        // Validate geometry only. This temporary value never becomes a PMU;
        // actual placement separately requires explicit resource history.
        configuration = configuration
            .with_fault_history(log, alloc::vec![0; usize::from(log.bytes)])
            .map_err(String::from)?;
    }
    if let Some(identity) = identity {
        configuration
            .with_unqualified_identity(identity)
            .map_err(String::from)?;
    }
    Ok(SpmiPmu {
        sid,
        primary,
        interrupt,
        alarm_monitor,
        rtc_helper,
        identity,
        fault_log,
        windows,
        rtc,
    })
}

fn cells_of(value: &[u8]) -> Option<[u32; 4]> {
    let cells = value.as_chunks::<4>().0;
    let cell = |i: usize| cells.get(i).map(|c| u32::from_le_bytes(*c));
    Some([cell(0)?, cell(1)?, cell(2)?, cell(3)?])
}

/// Only explicitly visible ANS2 hardware is placed. Do not preserve all
/// ASC compatibles in the loader: SIO, AOP and others need their own
/// native application protocols before they can be exposed.
/// `iboot_security` is `/defaults nvme-iboot-sptm-security`: the boot
/// stage has configured the controller, linear submission mode included,
/// so the kernel and SPTM leave its linear-SQ, PRP-check and command
/// permission registers alone (`AppleANS3CGv2Controller::EnableLinearSQ`
/// 0x3db9064, `AppleANS2CGv2Controller::DisablePRPNullCheck` 0x3de5b3c,
/// `AppleANS2CGv2Controller::EnableAutoQueueManage` 0x3de5adc, read by
/// `AppleANS2NVMeController::CheckEDTProperties` 0x3dc1740). Without it
/// the kernel read-modify-writes 0x24004 and 0x24008, which have no model.
fn ans_controller(
    io: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
    iboot_security: bool,
) -> Result<Option<AnsController>, String> {
    let Some(node) = io.child("ans").filter(|n| n.compatible(ASC)) else {
        return Ok(None);
    };
    if node.property("role") != Some(b"ANS2\0".as_slice()) {
        return Err("/arm-io/ans role is not the modeled ANS2".into());
    }
    if !iboot_security {
        return Err(
            "ANS2 without /defaults nvme-iboot-sptm-security selects kernel-programmed ANS2 registers the model does not carry"
                .into(),
        );
    }
    if node.property("nvme-linear-sq").is_none() {
        return Err("ANS2 requires the modeled linear submission contract".into());
    }
    let geometry = AnsQueueGeometry::linear(
        node.first_u32("nvme-queue-entries")
            .ok_or("ANS2 has no nvme-queue-entries handoff")?,
    )
    .map_err(String::from)?;
    if let Some(flag) = UNMODELED_ANS_SPTM
        .into_iter()
        .find(|flag| node.property(flag).is_some())
    {
        return Err(format!(
            "ANS2 {flag} selects an SPTM NVMe contract the model does not carry"
        ));
    }
    rtbuddy_nub(&node, "ANS2")?;
    let regs = node.pairs("reg").ok_or("ANS2 has no reg pairs")?;
    let parent = node
        .first_u32("iommu-parent")
        .ok_or("ANS2 has no iommu-parent")?;
    let mut found = None;
    let mut duplicate = false;
    io.visit(&mut |candidate| {
        if candidate.first_u32("AAPL,phandle") == Some(parent) {
            duplicate |= found.is_some();
            found = Some(name_of(candidate));
        }
    })
    .ok_or("DeviceTree walk failed")?;
    if duplicate {
        return Err("ANS2 iommu-parent is ambiguous".into());
    }
    let sart_node = found
        .and_then(|name| io.child(&name))
        .filter(|n| n.compatible(SART) && n.first_u32("sart-version") == Some(3))
        .ok_or("ANS2 iommu-parent is not SART v3")?;
    let sart_regs = sart_node.pairs("reg").ok_or("SART has no reg pairs")?;
    let place = |pairs: &[(u64, u64)], index: usize, minimum: u64| -> Result<(u64, u64), String> {
        let &(offset, bytes) = pairs
            .get(index)
            .filter(|(_, bytes)| *bytes >= minimum)
            .ok_or("ANS2/SART register bank is absent or too short")?;
        let first = translate(offset).ok_or("ANS2/SART bank outside arm-io ranges")?;
        let last = offset
            .checked_add(bytes - 1)
            .and_then(translate)
            .ok_or("ANS2/SART bank end outside arm-io ranges")?;
        if first.checked_add(bytes - 1) != Some(last) {
            return Err("ANS2/SART bank crosses arm-io translations".into());
        }
        Ok((first, bytes))
    };
    let wrapper = place(&regs, 0, asc::WRAPPER_BYTES)?;
    let nvme = place(&regs, 3, ans::REGISTER_BYTES)?;
    let vdma = node
        .property("nvme-vdma-wa")
        .map(|_| place(&regs, 13, ans::VDMA_CACHE_OFFSET + geometry.vdma_bytes()))
        .transpose()?;
    let sart = place(&sart_regs, 0, sart::REGISTER_BYTES)?;
    let power = place(&sart_regs, 2, 4)?;
    let offset = u64::from(
        sart_node
            .first_u32("sart-power-reg-offset")
            .ok_or("SART has no idle register offset")?,
    );
    if offset + 4 > power.1 {
        return Err("SART idle word outside reg[2]".into());
    }
    let sart_idle = power
        .0
        .checked_add(offset)
        .ok_or("SART idle address wraps")?;
    if sart_idle < nvme.0 || sart_idle + 4 > nvme.0 + nvme.1 {
        return Err("SART idle word is not inside the shared NVMe bank".into());
    }
    let irqs = node.cells32("interrupts").ok_or("ANS2 has no interrupts")?;
    let index = node
        .first_u32("nvme-interrupt-idx")
        .ok_or("ANS2 has no nvme-interrupt-idx")? as usize;
    if index < 4 {
        return Err("ANS2 completion interrupt overlaps ASC mailbox lines".into());
    }
    let irq = |index: usize| -> Result<u16, String> {
        irqs.get(index)
            .and_then(|&n| u16::try_from(n).ok())
            .ok_or_else(|| "ANS2 interrupt index/number is invalid".into())
    };
    let interrupts = [irq(0)?, irq(1)?, irq(2)?, irq(3)?];
    let completion_irq = irq(index)?;
    let namespaces = ans::Description::decode(
        node.property("namespaces")
            .ok_or("ANS2 has no namespaces")?,
    )
    .map_err(String::from)?;
    Ok(Some(AnsController {
        geometry,
        wrapper,
        nvme,
        vdma,
        sart,
        sart_idle,
        sart_exclusive_bounds: sart_node.property("exclusive-bounds").is_some(),
        interrupts,
        completion_irq,
        namespaces,
        clock_gates: node
            .cells32("clock-gates")
            .ok_or("ANS2 has no clock-gates")?,
        power_gates: node
            .cells32("power-gates")
            .ok_or("ANS2 has no power-gates")?,
    }))
}

/// The AMCC as `/chosen/lock-regs/amcc` describes it: its apertures and
/// each aperture's planes and lock registers (`platform::apple::amcc`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryController {
    pub apertures: Vec<u64>,
    pub layout: amcc::Layout,
}

/// The property iBoot's AMCC map always states.
const APERTURE_COUNT: &str = "aperture-count";

/// A `<name>-reg-offset`, `-reg-mask` and, for a bit register,
/// `-reg-value` triple.
fn lock_register(
    node: &Node<'_>,
    path: &str,
    name: &str,
    bit: bool,
) -> Result<amcc::Register, String> {
    let field = |suffix: &str| {
        node.first_u32(&format!("{name}-reg-{suffix}"))
            .ok_or_else(|| format!("{path} has no {name}-reg-{suffix}"))
    };
    let mask = field("mask")?;
    let value = if bit { field("value")? } else { 0 };
    if value & !mask != 0 {
        return Err(format!("{path} {name}-reg-value has bits outside its mask"));
    }
    Ok(amcc::Register {
        offset: u64::from(field("offset")?),
        mask,
        value,
    })
}

fn lock_register_optional(
    node: &Node<'_>,
    path: &str,
    name: &str,
) -> Result<Option<amcc::Register>, String> {
    let present = ["offset", "mask", "value"]
        .iter()
        .any(|suffix| node.property(&format!("{name}-reg-{suffix}")).is_some());
    present
        .then(|| lock_register(node, path, name, true))
        .transpose()
}

fn memory_controller(chosen: &Node<'_>) -> Result<Option<MemoryController>, String> {
    memory_controller_named(chosen, "amcc")
}

/// The AMCC map of `/chosen/lock-regs/amcc`, or `None` without one. The
/// IPSW templates carry the node and its group children empty; a node the
/// boot chain left so (no `aperture-count`, on a SoC whose iBoot map the
/// loader lacks, `stela_loader::lock_regs`) describes no controller, and
/// SPTM's own `ctrr_dt_get_lock_group` stops on it.
fn memory_controller_named(
    chosen: &Node<'_>,
    controller: &str,
) -> Result<Option<MemoryController>, String> {
    let Some(node) = chosen
        .child("lock-regs")
        .and_then(|regs| regs.child(controller))
        .filter(|node| node.property(APERTURE_COUNT).is_some())
    else {
        return Ok(None);
    };
    let path = format!("/chosen/lock-regs/{controller}");
    let number = |name: &str| {
        node.first_u32(name)
            .ok_or_else(|| format!("{path} has no {name}"))
    };
    let count = number(APERTURE_COUNT)? as usize;
    let apertures: Vec<u64> = node
        .property("aperture-phys-addr")
        .map(|value| {
            value
                .as_chunks::<8>()
                .0
                .iter()
                .map(|cell| u64::from_le_bytes(*cell))
                .collect()
        })
        .unwrap_or_default();
    if count == 0
        || apertures.len() != count
        || node
            .property("aperture-phys-addr")
            .is_none_or(|bytes| bytes.len() != count * 8)
    {
        return Err(format!(
            "{path} aperture-phys-addr does not list aperture-count apertures"
        ));
    }
    let group_path = format!("{path}/{controller}-ctrr-a");
    let group = node
        .child(&format!("{controller}-ctrr-a"))
        .ok_or_else(|| format!("missing lock group {group_path}"))?;
    for suffix in ["b", "c", "d"] {
        let name = format!("{controller}-ctrr-{suffix}");
        if node
            .child(&name)
            .is_some_and(|empty| empty.property("page-size-shift").is_some())
        {
            return Err(format!(
                "{path}/{name} is a lock group the AMCC model does not implement"
            ));
        }
    }
    let register = |name: &str, bit: bool| lock_register(&group, &group_path, name, bit);
    let optional_register = |name: &str| lock_register_optional(&group, &group_path, name);
    let dram_base = chosen
        .property("dram-base")
        .and_then(|value| {
            value
                .first_chunk::<8>()
                .map(|cell| u64::from_le_bytes(*cell))
        })
        .ok_or("/chosen has no dram-base")?;
    let layout = amcc::Layout {
        aperture_bytes: u64::from(number("aperture-size")?),
        planes: number("plane-count")?,
        stride: u64::from(number("plane-stride")?),
        cache_status: if controller == "amcc" {
            Some(lock_register(&node, &path, "cache-status", true)?)
        } else {
            lock_register_optional(&node, &path, "cache-status")?
        },
        group: amcc::LockGroup {
            page_size_shift: group
                .first_u32("page-size-shift")
                .ok_or_else(|| format!("{group_path} has no page-size-shift"))?,
            lower_limit: register("lower-limit", false)?,
            upper_limit: register("upper-limit", false)?,
            enable: optional_register("enable")?,
            write_disable: optional_register("write-disable")?,
            lock: optional_register("lock")?,
        },
        // SPTM normalizes IOA absolute page limits by subtracting the
        // DRAM page base (T6000 26A434 VA 0xfffffff0270d7748..d777c).
        dram_base: if controller == "ioa" { 0 } else { dram_base },
    };
    if layout.aperture_bytes == 0 || (layout.stride == 0 && layout.planes != 1) {
        return Err(format!("{path} has an empty aperture or plane stride"));
    }
    Ok(Some(MemoryController { apertures, layout }))
}

/// The `name` of an `/arm-io` child, for messages.
fn name_of(node: &Node<'_>) -> String {
    node.property("name")
        .and_then(|name| core::str::from_utf8(name).ok())
        .map_or_else(|| "?".into(), |name| name.trim_end_matches('\0').into())
}

/// The watchdog's side registers, each one aligned word outside its timer
/// window, as `AppleARMWatchdogTimer::start` (26A434 file 0x1ca362c) maps
/// device memory 1..=4: the panic-save scratch, the mechanism command, the
/// AP watchdog configuration and the panic force-power-off flags
/// (`panic-forcepoweroff-flag-bit`); the last two are optional. `triggers`
/// are the `trigger-config` records it maps per CPU: a physical word, a
/// mask and the value it sets under that mask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchdogSide {
    pub words: Vec<u64>,
    pub triggers: Vec<(u64, u32, u32)>,
}

fn watchdog_side(
    node: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
) -> Result<Option<WatchdogSide>, String> {
    let reg = node.pairs("reg").ok_or("watchdog has no reg")?;
    if reg.len() == 1 {
        return Ok(None);
    }
    let bit = |name| node.first_u32(name).is_some_and(|bit| bit < 32);
    if !(3..=5).contains(&reg.len())
        || !bit("panic-save-flag-bit")
        || (reg.len() == 5 && !bit("panic-forcepoweroff-flag-bit"))
    {
        return Err(
            "watchdog side controls need reg[1]/reg[2], valid flag bits and at most reg[4]".into(),
        );
    }
    let mut words = Vec::new();
    for &(address, bytes) in &reg[1..] {
        if bytes != 4 || !address.is_multiple_of(4) {
            return Err("watchdog side register is not one aligned full32 word".into());
        }
        let physical =
            translate(address).ok_or("watchdog side register is outside arm-io ranges")?;
        if address.checked_add(3).and_then(translate) != physical.checked_add(3) {
            return Err("watchdog side range translation is not contiguous".into());
        }
        words.push(physical);
    }
    let mut triggers = Vec::new();
    if let Some(records) = node.property("trigger-config") {
        let (records, rest) = records.as_chunks::<16>();
        if !rest.is_empty() {
            return Err("watchdog trigger-config holds a partial record".into());
        }
        for record in records {
            let word = |at: usize| u32::from_le_bytes(record[at..at + 4].try_into().expect("word"));
            let physical = u64::from_le_bytes(record[..8].try_into().expect("address"));
            let (mask, value) = (word(8), word(12));
            if !physical.is_multiple_of(4) || mask == 0 || value & !mask != 0 {
                return Err(
                    "watchdog trigger-config record is unaligned or exceeds its mask".into(),
                );
            }
            triggers.push((physical, mask, value));
        }
    }
    Ok(Some(WatchdogSide { words, triggers }))
}

/// A CPU's CoreSight aperture; components exist only within its DT length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreSight {
    pub cpu: usize,
    pub physical: u64,
    pub bytes: u64,
}

impl CoreSight {
    /// The UTTDBG region base, only when the DT aperture contains its sampler.
    pub fn pc_sampler(&self) -> Option<u64> {
        (self.bytes >= coresight::UTT_OFFSET + coresight::PC_SAMPLE + 8)
            .then(|| self.physical.checked_add(coresight::UTT_OFFSET))
            .flatten()
    }
}

/// Validate the DT aperture before placing its lock pair and, when it fits,
/// the UTTDBG PC sampler. Preserve the owner even when other PEs lack a map.
fn place_coresight(cpu: usize, pairs: &[(u64, u64)]) -> Result<CoreSight, String> {
    let [(physical, bytes)] = pairs else {
        return Err("CPU CoreSight map must describe one component".into());
    };
    if *bytes < coresight::STATUS + 4
        || !physical.is_multiple_of(coresight::BYTES)
        || physical.checked_add(*bytes).is_none()
    {
        return Err("CPU CoreSight component is empty, unaligned or overflows its page".into());
    }
    Ok(CoreSight {
        cpu,
        physical: *physical,
        bytes: *bytes,
    })
}

/// The SoC's CPU start registers, and its CPU clusters and always-on eFuses
/// where its row describes them, when the DeviceTree shows the SoC's PMGR
/// ([`pmgr`]) and its `reg` places each cluster's register window and
/// performance-state table and the eFuse block.
fn pmgr_registers(
    io: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
    chip_id: u32,
    processors: &[Identity],
) -> Result<PmgrRegisters, String> {
    let none = PmgrRegisters {
        clusters: Vec::new(),
        aon_fuses: None,
        cpu_start: None,
        wake_masks: None,
        energy: Vec::new(),
        performance: Vec::new(),
        power_banks: Vec::new(),
        soc_dpe: None,
        bridges: Vec::new(),
        cluster_events: Vec::new(),
    };
    let Some(soc) = SOCS
        .iter()
        .find(|soc| soc.chip_id == chip_id && soc.pmgr_modeled())
    else {
        return Ok(none);
    };
    let Some(node) = io.child("pmgr").filter(|node| node.compatible(soc.pmgr)) else {
        return Ok(none);
    };
    // Each `reg` entry in guest PA, by index; None outside `/arm-io` ranges.
    let reg: Vec<Option<(u64, u64)>> = node
        .pairs("reg")
        .unwrap_or_default()
        .into_iter()
        .map(|(offset, bytes)| Some((translate(offset)?, bytes)))
        .collect();
    let covered = |start: u64, bytes: u64| {
        reg.iter()
            .flatten()
            .any(|&(base, size)| base <= start && start + bytes <= base + size)
    };
    let clusters = soc
        .clusters
        .map(|clusters| clusters.to_vec())
        .unwrap_or_default();
    for cluster in &clusters {
        let cpm_base = cluster
            .base
            .checked_add(cpm::OFFSET)
            .ok_or("CPM base overflows")?;
        for offset in cpm::Cpm::new(cluster.counter_map).offsets() {
            if !covered(cpm_base + offset, 8) {
                return Err("PMGR reg does not cover a CPM power register".into());
            }
        }
        for offset in cluster::SCRATCH {
            if !covered(cluster.base + offset, 8) {
                return Err("PMGR reg does not cover CPU state scratch".into());
            }
        }
        let window = cluster.base + cluster::ACC_OFFSET;
        let table = cluster.pstates as u64 * cluster::PSTATE_BYTES;
        if !reg.contains(&Some((window, cluster::ACC_BYTES)))
            || !covered(cluster.base + cluster::PSTATE_OFFSET, table)
        {
            return Err(format!(
                "/arm-io/pmgr reg does not place the CPU cluster at {:#x}",
                cluster.base
            ));
        }
    }
    let fuses = soc
        .aon_fuses
        .map(|index| {
            reg.get(index)
                .copied()
                .flatten()
                .filter(|&(_, bytes)| bytes == fuse::FUSE_BYTES)
                .ok_or_else(|| format!("/arm-io/pmgr reg[{index}] is not the eFuse block"))
        })
        .transpose()?;
    let mut cluster_ids: Vec<u64> = processors.iter().map(|pe| (pe.mpidr >> 8) & 0xff).collect();
    cluster_ids.sort_unstable();
    cluster_ids.dedup();
    let clusters_started = cluster_ids.last().map_or(0, |&last| last as u8 + 1);
    let cpu_start = match (soc.cpu_start, reg.first().copied().flatten()) {
        (None, _) => None,
        (Some(offset), Some((base, bytes)))
            if offset + cpustart::bytes(clusters_started) <= bytes =>
        {
            Some((base + offset, clusters_started))
        }
        (Some(_), _) => {
            return Err("/arm-io/pmgr reg[0] does not hold the CPU start registers".into());
        }
    };
    let bridges = place_bridges(&node, &reg, soc.bridge_fields)?;
    let cluster_events = acc_events(&node, clusters.len())?;
    let power_banks = place_power_banks(&reg, soc.power_banks)?;
    let soc_dpe = soc
        .dpe_reg
        .map(|i| place_soc_dpe(&node, &reg, i))
        .transpose()?;
    let energy = energy_banks(&node, &reg, &clusters)?;
    let performance = performance_banks(&node, &reg)?;
    let wake_masks = soc
        .wake_masks
        .map(|layout| wake_bank(&node, &reg, layout))
        .transpose()?;
    Ok(PmgrRegisters {
        cluster_events,
        bridges,
        soc_dpe,
        power_banks,
        wake_masks,
        performance,
        energy,
        clusters,
        aon_fuses: fuses,
        cpu_start,
    })
}

/// Special CPU event types2/7 select E/P ACC accessors, not the SOC-bank
/// selector formula (kernel 0x2b93ac4..0x2b93cec). Byte6 is the event index.
fn acc_events(node: &Node<'_>, clusters: usize) -> Result<Vec<Vec<u8>>, String> {
    let mut events = alloc::vec![Vec::new();clusters];
    let data = node.property("events").unwrap_or_default();
    if !data.len().is_multiple_of(24) {
        return Err("ACC events property is not whole records".into());
    }
    for entry in data.as_chunks::<24>().0 {
        let cluster = match entry[2] {
            2 => 0,
            7 => 1,
            _ => continue,
        };
        let bank = events
            .get_mut(cluster)
            .ok_or("ACC event names a missing CPU cluster")?;
        if entry[6] >= 27 {
            return Err("ACC event selector exceeds the accessor range".into());
        }
        if !bank.contains(&entry[6]) {
            bank.push(entry[6]);
        }
    }
    Ok(events)
}

/// Bridge map and source decoding: kernel file 0x2b71bd8..0x2b71fd8,
/// device dependencies 0x2b73c80 and version3 counter programmer 0x2b96214.
/// `reg` always passes through arm-io ranges, including high PCIe windows.
fn place_bridges(
    node: &Node<'_>,
    reg: &[Option<(u64, u64)>],
    fields: Option<&[&[(u64, u32)]]>,
) -> Result<Vec<BridgeBank>, String> {
    let Some(first) = node.first_u32("bridge-reg-index") else {
        return Ok(Vec::new());
    };
    let fields = fields.ok_or("this SoC has no documented bridge register layouts")?;
    let count = node
        .first_u32("#bridges")
        .ok_or("PMGR has no bridge count")? as usize;
    if count > fields.len()
        || node.first_u32("bridge-settings-version") != Some(1)
        || node.first_u32("bridge-counter-version") != Some(3)
    {
        return Err("unsupported bridge count or configuration version".into());
    }
    let headers = node
        .property("bridge-counters")
        .ok_or("PMGR has no bridge counter headers")?;
    let configs = node.property("bridge-counter-configs").unwrap_or_default();
    let dependencies = node.property("device-bridges").unwrap_or_default();
    let axi = node.property("axi2af-axi-config");
    if headers.len() != count * 4
        || !configs.len().is_multiple_of(36)
        || !dependencies.len().is_multiple_of(76)
        || axi.is_some_and(|a| a.len() != count * 4)
    {
        return Err("PMGR bridge properties have partial records or wrong counts".into());
    }
    let all_configs = configs.as_chunks::<36>().0;
    let mut banks = Vec::new();
    let optional = node.first_u32("optional-bridge-mask").unwrap_or(0);
    if optional != 0 {
        return Err("optional bridge suppression requires an established selection policy".into());
    }
    for (id, tunables) in fields.iter().enumerate().take(count) {
        let index = (first as usize)
            .checked_add(id)
            .ok_or("bridge reg index overflows")?;
        let (physical, bytes) = reg
            .get(index)
            .copied()
            .flatten()
            .ok_or("bridge names an unmapped DT reg window")?;
        let header: [u8; 4] = headers[id * 4..id * 4 + 4].try_into().expect("header");
        let start = usize::from(header[2]);
        let end = start + usize::from(header[3]);
        let selected = all_configs
            .get(start..end)
            .ok_or("bridge counter header exceeds configuration records")?
            .to_vec();
        let axi = axi.map(|a| a[id * 4..id * 4 + 4].try_into().expect("4 bytes"));
        let model = bridge::Bridge::new(tunables, header, &selected, axi).map_err(String::from)?;
        for (o, n) in model.spans() {
            if o.checked_add(n).is_none_or(|end| end > bytes)
                || physical.checked_add(o + n).is_none()
            {
                return Err("bridge configuration lies outside its DT range".into());
            }
        }
        let mut devices = Vec::new();
        for entry in dependencies.as_chunks::<76>().0 {
            // The first slot may be bridge0; subsequent zero slots terminate
            // the list. Names and device IDs never choose a hardware base.
            for (slot, &bridge) in entry[4..].iter().enumerate() {
                if slot != 0 && bridge == 0 {
                    break;
                }
                if usize::from(bridge) >= count {
                    return Err("device-bridges names an absent bridge".into());
                }
                if usize::from(bridge) == id && !devices.contains(&entry[3]) {
                    devices.push(entry[3]);
                }
            }
        }
        banks.push(BridgeBank {
            physical,
            fields: tunables.to_vec(),
            header,
            configs: selected,
            axi,
            devices,
        });
    }
    Ok(banks)
}

/// SOC DPE direct split-word records have group 0x1d, die mask 1,
/// command flag 0, split flag 1 and width 64 (PMGR parser 0x2b7796c).
fn place_soc_dpe(
    node: &Node<'_>,
    reg: &[Option<(u64, u64)>],
    index: usize,
) -> Result<SocDpe, String> {
    let (physical, bytes) = reg
        .get(index)
        .copied()
        .flatten()
        .ok_or("SOC DPE has no mapped DT reg bank")?;
    let data = node.property("hw-dpe-reg").unwrap_or_default();
    if !data.len().is_multiple_of(40) {
        return Err("SOC DPE hw-dpe-reg has partial records".into());
    }
    let mut samples = Vec::new();
    for entry in data.as_chunks::<40>().0 {
        if entry[16..18] != [0x1d, 0] || entry[19] != 0 {
            continue;
        }
        if entry[18] != 1 || entry[20] != 1 || entry[23] != 64 {
            return Err("unsupported SOC DPE sampling flags".into());
        }
        let address = u64::from_le_bytes(entry[..8].try_into().expect("8 bytes"));
        let offset = address
            .checked_sub(physical)
            .ok_or("SOC DPE sample below its reg bank")?;
        samples.push((offset, dpe::RESTORE.contains(&offset)));
    }
    let model = dpe::Dpe::new(&samples).map_err(String::from)?;
    for (o, n) in model.spans() {
        if o.checked_add(n).is_none_or(|end| end > bytes) || physical.checked_add(o + n).is_none() {
            return Err("SOC DPE register outside its DT bank".into());
        }
    }
    Ok(SocDpe { physical, samples })
}

/// Bind documented RegMap roles to DT addresses, validating every modeled
/// word against the selected range rather than claiming a broad PMGR bank.
fn place_power_banks(
    reg: &[Option<(u64, u64)>],
    layouts: &[(usize, power::Kind)],
) -> Result<Vec<PowerBank>, String> {
    layouts
        .iter()
        .map(|&(index, kind)| {
            let (physical, bytes) = reg
                .get(index)
                .copied()
                .flatten()
                .ok_or("PMGR power bank names an unmapped reg entry")?;
            for offset in kind.offsets() {
                if offset.checked_add(4).is_none_or(|end| end > bytes)
                    || physical.checked_add(offset + 4).is_none()
                    || !physical.is_multiple_of(4)
                {
                    return Err("PMGR power register lies outside its DT range".into());
                }
            }
            Ok(PowerBank { physical, kind })
        })
        .collect()
}

/// `ap-wake-sources` is (u32 source, 32-byte name), kernel parser
/// `ApplePMGR` and `setAPWakeupSources` 0x2fa3f84. Reported sources are
/// validated against hardware capabilities, not used as a reset mask.
fn wake_bank(
    node: &Node<'_>,
    reg: &[Option<(u64, u64)>],
    layout: WakeLayout,
) -> Result<WakeBank, String> {
    const RECORD: usize = 36;
    let (base, bytes) = reg
        .get(layout.reg)
        .copied()
        .flatten()
        .ok_or("PMGR AOP wake masks have no mapped reg bank")?;
    if bytes < wake::OFFSET + wake::BYTES {
        return Err("PMGR AOP wake masks exceed their reg bank".into());
    }
    base.checked_add(wake::OFFSET + wake::BYTES)
        .ok_or("PMGR AOP wake mask span overflows")?;
    let physical = base + wake::OFFSET;
    let data = node.property("ap-wake-sources").unwrap_or_default();
    if !data.len().is_multiple_of(RECORD) {
        return Err("PMGR ap-wake-sources is not whole records".into());
    }
    let mut sources = Vec::new();
    let mut smc_wake = None;
    for entry in data.as_chunks::<RECORD>().0 {
        let source = u32::from_le_bytes(entry[..4].try_into().expect("4 bytes"));
        if entry[4..].split(|&b| b == 0).next() == Some(SMC_WAKE_SOURCE) {
            smc_wake = u8::try_from(source).ok();
        }
        let id =
            u8::try_from(source).map_err(|_| "PMGR wake source exceeds hardware mask width")?;
        if layout.valid[source as usize / u32::BITS as usize] & (1 << (source % u32::BITS)) == 0
            || sources.contains(&id)
        {
            return Err("PMGR ap-wake-sources contains an unsupported or duplicate source".into());
        }
        sources.push(id);
    }
    Ok(WakeBank {
        physical,
        valid: layout.valid,
        sources,
        smc_wake,
    })
}

/// The `ap-wake-sources` name of the SMC's wake of the AP.
const SMC_WAKE_SOURCE: &[u8] = b"SMC.CPUWakeupAP";

/// Version-1 group layout: `_initPerfCountersV1` (kernel file 0x2b79ec0),
/// `_getPerfCounterOffset` (0x2b8e974) and the selector consumers
/// (0x2b92ddc..0x2b93010, 0x2b95884..0x2b95964). No physical address or
/// counter index is inferred from a reporting name or device ID.
fn performance_banks(node: &Node<'_>, reg: &[Option<(u64, u64)>]) -> Result<Vec<PerfBank>, String> {
    use crate::platform::apple::perf::{COUNTER_BASE, STRIDE};
    const GROUP: usize = 16;
    const SOURCE: usize = 24;
    const DEVICE_COUNTER: u8 = 0x20;
    let data = node.property("perf-regs").unwrap_or_default();
    if !data.len().is_multiple_of(GROUP) {
        return Err("/arm-io/pmgr perf-regs is not whole groups".into());
    }
    let mut banks = Vec::new();
    let mut counts = Vec::new();
    for entry in data.as_chunks::<GROUP>().0 {
        let index = u32::from_le_bytes(entry[..4].try_into().expect("4 bytes")) as usize;
        let offset = u64::from(u32::from_le_bytes(entry[4..8].try_into().expect("4 bytes")));
        let count = u16::from_le_bytes(entry[8..10].try_into().expect("2 bytes"));
        // Version zero defaults to one. Parent/global indirection and the
        // busy protocol of classes 1/2 need separate semantics.
        if !matches!(entry[12], 0 | 3) || entry[13] > 1 || entry[15] != 0 {
            return Err("/arm-io/pmgr perf-regs has an unsupported class, layout or flags".into());
        }
        let (base, bytes) = reg
            .get(index)
            .copied()
            .flatten()
            .ok_or("/arm-io/pmgr perf-regs names an unmapped reg bank")?;
        if count == 0
            || count > 256
            || !offset.is_multiple_of(4)
            || offset + COUNTER_BASE + u64::from(count) * STRIDE > bytes
        {
            return Err(
                "/arm-io/pmgr perf-regs counters exceed their reg bank or selector width".into(),
            );
        }
        base.checked_add(offset + COUNTER_BASE + u64::from(count) * STRIDE)
            .ok_or("PMGR performance bank span overflows")?;
        let physical = base + offset;
        banks.push(PerfBank {
            physical,
            selectors: Vec::new(),
        });
        counts.push(count);
    }
    if banks.is_empty() {
        return Ok(banks);
    }
    let mut select = |group: u8, index: u8| -> Result<(), String> {
        let bank = banks
            .get_mut(usize::from(group))
            .ok_or("PMGR counter source names a missing perf-regs group")?;
        let index = u16::from(index);
        if index >= counts[usize::from(group)] {
            return Err("PMGR counter source exceeds its perf-regs count".into());
        }
        if !bank.selectors.contains(&index) {
            bank.selectors.push(index);
        }
        Ok(())
    };
    let devices = node.property("devices").unwrap_or_default();
    if !devices.len().is_multiple_of(PMGR_DEVICE) {
        return Err("/arm-io/pmgr devices is not whole entries".into());
    }
    for entry in devices.as_chunks::<PMGR_DEVICE>().0 {
        if entry[0] & DEVICE_COUNTER != 0 {
            select(entry[9], entry[8])?;
        }
    }
    for property in ["clocks", "power-domains", "events"] {
        let data = node.property(property).unwrap_or_default();
        if !data.len().is_multiple_of(SOURCE) {
            return Err(format!(
                "/arm-io/pmgr {property} is not whole counter records"
            ));
        }
        for entry in data.as_chunks::<SOURCE>().0 {
            match property {
                "clocks" if entry[2] & 1 != 0 => select(entry[1], entry[0])?,
                "power-domains" if (entry[2], entry[1]) != (0, 0) => select(entry[2], entry[1])?,
                // Types 2/7 use the ACC accessor, and flag bit 0 selects
                // another event path; neither authorizes a SOC selector.
                "events" if entry[1] & 1 == 0 => match entry[2] {
                    0 => select(entry[7], entry[6])?,
                    1 | 5 | 6 => {
                        select(entry[7], entry[6])?;
                        select(entry[5], entry[4])?;
                    }
                    2 | 7 => (),
                    _ => return Err("PMGR events has an unsupported counter type".into()),
                },
                _ => (),
            }
        }
    }
    for bank in &mut banks {
        bank.selectors.sort_unstable();
    }
    Ok(banks)
}

/// `hw-dpe-reg` records are 40 bytes (`ApplePMGR` parser, kernel file
/// 0x2b7796c..0x2b77af8). The first u64 is an absolute PA, not an arm-io
/// bus address. Direct, single-load, 64-bit CPU records have group 0,
/// die mask 1, command/split flags 0 and behavior flags 1/0. Other groups
/// (GPU/PMP, ANE, SOC DPE) belong to separate models, not CPU accumulators.
fn energy_banks(
    node: &Node<'_>,
    reg: &[Option<(u64, u64)>],
    clusters: &[CpuCluster],
) -> Result<Vec<EnergyBank>, String> {
    const RECORD: usize = 40;
    let data = node.property("hw-dpe-reg").unwrap_or_default();
    if !data.len().is_multiple_of(RECORD) {
        return Err("/arm-io/pmgr hw-dpe-reg is not whole records".into());
    }
    let mut banks = Vec::new();
    for entry in data.as_chunks::<RECORD>().0 {
        if entry[16..18] != [0, 0] || entry[19] != 0 {
            continue;
        }
        if entry[18..24] != [1, 0, 0, 1, 0, 64] {
            return Err(
                "PMGR CPU hw-dpe-reg has unsupported die, sampling, behavior or width flags".into(),
            );
        }
        let physical = u64::from_le_bytes(entry[..8].try_into().expect("8 bytes"));
        let cpm = clusters
            .iter()
            .any(|c| c.base.checked_add(energy::CPM_OFFSET) == Some(physical));
        let bytes = if cpm {
            energy::CONTROL_OFFSET + 8
        } else {
            energy::COUNTER_BYTES
        };
        let covered = reg.iter().flatten().any(|&(base, size)| {
            base <= physical
                && physical
                    .checked_add(bytes)
                    .zip(base.checked_add(size))
                    .is_some_and(|(end, limit)| end <= limit)
                && (cpm
                    || size == energy::CORE_BYTES
                        && base.checked_add(energy::CORE_OFFSET) == Some(physical))
        });
        if !physical.is_multiple_of(8)
            || !covered
            || banks.iter().any(|b: &EnergyBank| b.physical == physical)
        {
            return Err(format!(
                "/arm-io/pmgr CPU hw-dpe-reg PA {physical:#x} is duplicated or outside its reg bank"
            ));
        }
        banks.push(EnergyBank { physical, cpm });
    }
    Ok(banks)
}

/// The PMGR registers the machine models besides its power states.
struct PmgrRegisters {
    cluster_events: Vec<Vec<u8>>,
    bridges: Vec<BridgeBank>,
    soc_dpe: Option<SocDpe>,
    power_banks: Vec<PowerBank>,
    wake_masks: Option<WakeBank>,
    performance: Vec<PerfBank>,
    energy: Vec<EnergyBank>,
    clusters: Vec<CpuCluster>,
    aon_fuses: Option<(u64, u64)>,
    cpu_start: Option<(u64, u8)>,
}

/// `/arm-io/mcc`, if it is a modeled memory cache controller. Its planes
/// (`reg[1]`) are the lock-regs planes of the one AMCC aperture, which also
/// holds its shared registers (`reg[0]`) and broadcast window (`reg[3]`);
/// its PTD slot (`reg[pmp_ptd_reg_idx]` plus `pmp_ptd_update_space_offset`)
/// lies in the PMP's PTD update registers.
fn memory_cache(
    io: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
    chip_id: u32,
    controller: Option<&MemoryController>,
) -> Result<Option<MemoryCache>, String> {
    let Some(node) = io.child("mcc").filter(|node| node.compatible(MCC)) else {
        return Ok(None);
    };
    const PATH: &str = "/arm-io/mcc";
    let controller =
        controller.ok_or_else(|| format!("{PATH} has no /chosen/lock-regs/amcc aperture"))?;
    let [aperture] = controller.apertures[..] else {
        return Err(format!(
            "{PATH} behind several AMCC apertures is not modeled"
        ));
    };
    let layout = &controller.layout;
    let (bytes, ways) = SOCS
        .iter()
        .find(|soc| soc.chip_id == chip_id)
        .and_then(|soc| soc.memory_cache)
        .ok_or_else(|| format!("ApChipID {chip_id:#x} has no memory cache geometry"))?;
    let range = |owner: &Node<'_>, path: &str, index: usize| -> Result<(u64, u64), String> {
        owner
            .pairs("reg")
            .unwrap_or_default()
            .get(index)
            .and_then(|&(offset, bytes)| Some((translate(offset)?, bytes)))
            .ok_or_else(|| format!("{path} reg[{index}] is missing or outside /arm-io ranges"))
    };
    let in_aperture = |index: usize| -> Result<(u64, u64), String> {
        let (physical, bytes) = range(&node, PATH, index)?;
        physical
            .checked_sub(aperture)
            .filter(|&offset| offset < layout.aperture_bytes)
            .map(|offset| (offset, bytes))
            .ok_or_else(|| format!("{PATH} reg[{index}] is outside the AMCC aperture"))
    };
    if in_aperture(1)? != (0, layout.stride * u64::from(layout.planes)) {
        return Err(format!("{PATH} reg[1] is not the lock-regs planes"));
    }
    let channels = range(&node, PATH, 2)?;
    let count = node
        .first_u32("dcs_num_channels")
        .filter(|&count| count != 0 && channels.1 % u64::from(count) == 0)
        .ok_or_else(|| format!("{PATH} dcs_num_channels does not divide reg[2]"))?;
    let number = |name: &str| {
        node.first_u32(name)
            .ok_or_else(|| format!("{PATH} has no {name}"))
    };
    let bank = range(&node, PATH, number("pmp_ptd_reg_idx")? as usize)?;
    if bank.1 != ptd::PTD_BYTES
        || u64::from(number("pmp_ptd_update_space_offset")?) != ptd::UPDATE_OFFSET
    {
        return Err(format!("{PATH} PTD registers are not one PTD bank"));
    }
    let pmp = io
        .child("pmp")
        .ok_or_else(|| format!("{PATH} names PTD registers but there is no /arm-io/pmp"))?;
    let index = pmp
        .first_u32("ptd-update-reg-index")
        .ok_or("/arm-io/pmp has no ptd-update-reg-index")?;
    let updates = range(&pmp, "/arm-io/pmp", index as usize)?;
    let slots = bank.0 + ptd::UPDATE_OFFSET..bank.0 + ptd::PTD_BYTES;
    if !slots.contains(&updates.0) || updates.0 + updates.1 > slots.end {
        return Err("/arm-io/pmp PTD updates lie outside the PTD bank".into());
    }
    let records = pmp
        .child("iop-pmp-nub")
        .and_then(|nub| nub.property("ptd-range"))
        .filter(|records| !records.is_empty() && records.len() % PTD_RANGE == 0)
        .ok_or("/arm-io/pmp/iop-pmp-nub has no whole ptd-range records")?;
    let (ranges, interrupts) = memory_resources::publication_ranges(
        records,
        ((ptd::PTD_BYTES - ptd::UPDATE_OFFSET) / 8) as usize,
    )?;
    let ptd = PtdBank {
        physical: bank.0,
        ranges,
        interrupts,
    };
    Ok(Some(MemoryCache {
        cache: amcc::Cache {
            shared: in_aperture(0)?,
            broadcast: in_aperture(3)?.0,
            bytes,
            ways,
        },
        channels: (channels.0, channels.1, count as usize),
        ptd,
    }))
}

/// The modeled AES engine under `/arm-io`, if the DeviceTree keeps one; its
/// `iommu-parent` must be a mapper of a modeled DART.
fn aes_engine(
    io: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
    darts: &[Iommu],
) -> Result<Option<AesEngine>, String> {
    let Some(node) = io.child("aes").filter(|node| node.compatible(AES)) else {
        return Ok(None);
    };
    const PATH: &str = "/arm-io/aes";
    let reg = node.pairs("reg").unwrap_or_default();
    let &[block, key_disable] = reg.as_slice() else {
        return Err(format!("{PATH} has {} register ranges, not two", reg.len()));
    };
    let place = |(offset, bytes): (u64, u64)| {
        translate(offset)
            .map(|physical| (physical, bytes))
            .ok_or_else(|| format!("{PATH} lies outside /arm-io ranges"))
    };
    let number = |name: &str| {
        node.first_u32(name)
            .ok_or_else(|| format!("{PATH} has no {name}"))
    };
    let phandle =
        native_dma_phandle(&node, "AAPL,phandle").map_err(|why| format!("{PATH} {why}"))?;
    let parent = native_dma_phandle(&node, "iommu-parent")
        .map_err(|why| format!("{PATH} {why}"))?
        .ok_or_else(|| format!("{PATH} has no iommu-parent"))?;
    let mut matching = darts.iter().enumerate().flat_map(|(index, dart)| {
        dart.mappers
            .iter()
            .filter(move |(phandle, _)| *phandle == parent)
            .map(move |&(_, context)| (index, context))
    });
    let (iommu, mapper_context) = matching
        .next()
        .ok_or_else(|| format!("{PATH} iommu-parent {parent:#x} is no modeled DART's mapper"))?;
    if matching.next().is_some() {
        return Err(format!("{PATH} mapper ownership is ambiguous"));
    }
    if darts[iommu].instances.len() != 1 {
        return Err(format!(
            "{PATH} DMA instance routing is undetermined for a multi-instance DART"
        ));
    }
    let stream = native_mapper_input(&darts[iommu], mapper_context)
        .map_err(|why| format!("{PATH} {why}"))?;
    Ok(Some(AesEngine {
        phandle,
        mapper: parent,
        mapper_context,
        instance: 0,
        ranges: [place(block)?, place(key_disable)?],
        version: number("aes-version")?,
        irq: number("interrupts")?,
        iommu,
        stream,
    }))
}

/// Every `usb-drd,t8112` (J473AP usb-drd0 and usb-drd1), in DeviceTree
/// order: ADT reg/interrupts/iommu-parent (research transport section 1).
fn usb_controllers(
    io: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
    darts: &[Iommu],
) -> Result<Vec<UsbController>, String> {
    let mut controllers = Vec::new();
    let mut failure = None;
    io.visit(&mut |node| {
        if failure.is_none() && node.compatible(USB_DRD) {
            match usb_controller(node, translate, darts) {
                Ok(controller) => controllers.push(controller),
                Err(error) => failure = Some(error),
            }
        }
    })
    .ok_or("USB controller walk failed")?;
    failure.map_or(Ok(controllers), Err)
}

/// Resolve all arm-io ranges, including the identity USB window; no fixed
/// 8 GiB bias. The separate USB-DART worker owns multi-instance DART
/// parsing; this consumer uses the mapper stream that it publishes.
fn usb_controller(
    node: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
    darts: &[Iommu],
) -> Result<UsbController, String> {
    let name = node
        .property("name")
        .and_then(|name| core::str::from_utf8(name.split(|&b| b == 0).next()?).ok())
        .unwrap_or("usb-drd");
    let err = |why: &str| format!("{name} {why}");
    let raw: [(u64, u64); 9] = node
        .pairs("reg")
        .unwrap_or_default()
        .try_into()
        .map_err(|_| err("requires nine register windows"))?;
    let mut ranges = [(0, 0); 9];
    for (slot, (offset, bytes)) in ranges.iter_mut().zip(raw) {
        if bytes == 0 {
            return Err(err("has an empty register extent"));
        }
        let physical = translate(offset).ok_or_else(|| err("lies outside arm-io ranges"))?;
        let last = offset.checked_add(bytes - 1).and_then(translate);
        if last.is_none() || last != physical.checked_add(bytes - 1) {
            return Err(err("extent crosses arm-io ranges"));
        }
        *slot = (physical, bytes);
    }
    if ranges[0].1 < 0x11800
        || ranges[2] != (ranges[0].0 + 0xc000, 0x5800)
        || ranges[8] != (ranges[0].0 + 0xd000, 0x4000)
    {
        return Err(err("has an undescribed DWC3 alias layout"));
    }
    if [1, 3, 4, 5, 6, 7].iter().any(|&n| ranges[n].1 != 0x4000) {
        return Err(err("platform window is not 16 KiB"));
    }
    let irqs: [u32; 5] = node
        .cells32("interrupts")
        .unwrap_or_default()
        .try_into()
        .map_err(|_| err("requires five ADT interrupts"))?;
    if irqs.iter().any(|&irq| u16::try_from(irq).is_err()) {
        return Err(err("interrupt exceeds AIC input encoding"));
    }
    let phandle = native_dma_phandle(node, "AAPL,phandle").map_err(|why| err(&why))?;
    let parent = native_dma_phandle(node, "iommu-parent")
        .map_err(|why| err(&why))?
        .ok_or_else(|| err("has no iommu-parent"))?;
    let mut matching = darts.iter().enumerate().flat_map(|(index, dart)| {
        dart.mappers
            .iter()
            .filter(move |(phandle, _)| *phandle == parent)
            .map(move |&(_, stream)| (index, stream))
    });
    let (iommu, mapper_context) = matching
        .next()
        .ok_or_else(|| err("iommu-parent is no modeled DART mapper"))?;
    if matching.next().is_some() {
        return Err(err("iommu-parent is ambiguous"));
    }
    let stream = native_mapper_input(&darts[iommu], mapper_context).map_err(|why| err(&why))?;
    let port = node
        .first_u32("port-number")
        .filter(|&port| port != 0)
        .ok_or_else(|| err("has no Type-C port number"))?;
    Ok(UsbController {
        ranges,
        irqs,
        iommu,
        phandle,
        mapper: parent,
        mapper_context,
        stream,
        port,
        retention: node.property("retention").is_some(),
        phy: node
            .first_u32("atc-phy-parent")
            .ok_or_else(|| err("has no atc-phy-parent"))?,
    })
}

/// J473AP `/arm-io/sep` supplies two ranges and four mailbox lines. Its
/// `iommu-parent` is mapper-sep stream 0; `reg` addresses use arm-io ranges.
/// `AppleSEPManager::start` obtains that mapper (kernel file 0x2d66f64).
fn sep_device(
    root: &Node<'_>,
    io: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
    darts: &[Iommu],
) -> Result<Option<SepDevice>, String> {
    let Some(node) = io.child("sep").filter(|node| node.compatible(SEP)) else {
        return Ok(None);
    };
    const PATH: &str = "/arm-io/sep";
    if node.property("aarch64").is_none() || node.first_u32("iop-version") != Some(1) {
        return Err(format!("{PATH} requires the modeled AArch64 IOP version 1"));
    }
    if !node
        .child("iop-sep-nub")
        .is_some_and(|nub| nub.compatible(SEP_NUB))
    {
        return Err(format!(
            "{PATH} requires an iop-nub,sep; RTBuddy is not the SEP protocol"
        ));
    }
    let reg = node.pairs("reg").unwrap_or_default();
    let &[first, second] = reg.as_slice() else {
        return Err(format!("{PATH} requires two register ranges"));
    };
    if first.1 < crate::platform::apple::asc::WRAPPER_BYTES || second.1 == 0 {
        return Err(format!("{PATH} has an incomplete register aperture"));
    }
    let place = |(offset, bytes): (u64, u64)| -> Result<_, String> {
        let physical =
            translate(offset).ok_or_else(|| format!("{PATH} lies outside /arm-io ranges"))?;
        let last = offset.checked_add(bytes - 1).and_then(translate);
        if last.is_none() || last != physical.checked_add(bytes - 1) {
            return Err(format!(
                "{PATH} register extent lies outside /arm-io ranges"
            ));
        }
        Ok((physical, bytes))
    };
    let irqs: [u32; 4] = node
        .cells32("interrupts")
        .unwrap_or_default()
        .try_into()
        .map_err(|_| format!("{PATH} requires four mailbox interrupts"))?;
    if irqs.iter().any(|&irq| u16::try_from(irq).is_err()) {
        return Err(format!(
            "{PATH} mailbox interrupt is outside the AIC input encoding"
        ));
    }
    let parent = node
        .property("iommu-parent")
        .ok_or_else(|| format!("{PATH} has no iommu-parent"))?;
    let parent: [u8; 4] = parent
        .try_into()
        .map_err(|_| format!("{PATH} iommu-parent is not one phandle"))?;
    let parent = u32::from_le_bytes(parent);
    if parent == 0 {
        return Err(format!("{PATH} iommu-parent is zero"));
    }
    let mut matches = darts.iter().enumerate().flat_map(|(index, dart)| {
        dart.mappers
            .iter()
            .filter(move |(phandle, _)| *phandle == parent)
            .map(move |&(_, context)| (index, dart, context))
    });
    let (iommu, dart, mapper_context) = matches
        .next()
        .ok_or_else(|| format!("{PATH} iommu-parent is no modeled DART's mapper"))?;
    if matches.next().is_some() {
        return Err(format!("{PATH} mapper ownership is ambiguous"));
    }
    if dart.instances.len() != 1 {
        return Err(format!(
            "{PATH} DMA owner requires explicit multiple-TRAD selection"
        ));
    }
    if !dart.sids.is_empty() && !dart.sids.contains(&mapper_context) {
        return Err(format!(
            "{PATH} mapper context is absent from the original SID set"
        ));
    }
    let stream =
        native_mapper_input(dart, mapper_context).map_err(|why| format!("{PATH} {why}"))?;
    let firmware = root
        .child("chosen")
        .and_then(|n| n.child("memory-map"))
        .and_then(|n| n.property("SEPFW"))
        .map(|bytes| {
            let cells: &[u8; 16] = bytes
                .try_into()
                .map_err(|_| String::from("SEPFW is not a base/length pair"))?;
            let base = u64::from_le_bytes(cells[..8].try_into().expect("base"));
            let length = u64::from_le_bytes(cells[8..].try_into().expect("length"));
            if length == 0 || base.checked_add(length).is_none() {
                return Err(String::from("SEPFW has an empty or overflowing extent"));
            }
            Ok((base, length))
        })
        .transpose()?;
    let chosen = root.child("chosen");
    let flag = |name| {
        chosen
            .as_ref()
            .and_then(|n| n.first_u32(name))
            .map(|value| value != 0)
    };
    let security = flag("effective-production-status-ap")
        .zip(flag("effective-security-mode-ap"))
        .map(
            |(production, secure)| crate::platform::apple::sep::SecurityMode { production, secure },
        );
    let ecid = chosen
        .as_ref()
        .and_then(|n| n.first_u64("unique-chip-id"))
        .filter(|&value| value != 0);
    Ok(Some(SepDevice {
        ranges: [place(first)?, place(second)?],
        irqs,
        iommu,
        instance: 0,
        mapper: parent,
        mapper_context,
        stream,
        firmware,
        security,
        ecid,
    }))
}

/// Owner properties are one nonzero phandle, never a truncated first word.
fn native_dma_phandle(node: &Node<'_>, key: &str) -> Result<Option<u32>, String> {
    node.property(key)
        .map(|bytes| {
            let value: [u8; 4] = bytes
                .try_into()
                .map_err(|_| format!("{key} is not one native DMA owner phandle"))?;
            let value = u32::from_le_bytes(value);
            if value == 0 {
                return Err(format!("{key} native DMA owner phandle is zero"));
            }
            Ok(value)
        })
        .transpose()
}

/// Display pipes declare primary and PIODMA mapper parents in order.
fn native_dma_mapper_list(node: &Node<'_>, key: &str) -> Result<Vec<u32>, String> {
    let Some(bytes) = node.property(key) else {
        return Ok(Vec::new());
    };
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return Err(format!("{key} is not a complete native DMA mapper list"));
    }
    let mut parents = Vec::new();
    for word in bytes.as_chunks::<4>().0 {
        let parent = u32::from_le_bytes(*word);
        if parent == 0 || parents.contains(&parent) {
            return Err(format!("{key} has a zero or duplicate native DMA mapper"));
        }
        parents.push(parent);
    }
    Ok(parents)
}

/// Assign a modeled native endpoint its declared incoming route while
/// retaining its OS mapper context. This is a Stela endpoint assignment,
/// not an observation of an Apple bus transaction.
fn native_mapper_input(dart: &Iommu, context: u32) -> Result<u32, String> {
    if !dart.sids.is_empty() && !dart.sids.contains(&context) {
        return Err("mapper context is absent from the original SID set".into());
    }
    let input = dart
        .profile
        .mapper_input_stream(usize::from(dart.streams), context as usize, &dart.remap)
        .map_err(String::from)?;
    u32::try_from(input).map_err(|_| "native DMA input exceeds u32".into())
}

/// One selected external coprocessor, its expert and pipe, with distinct
/// incoming DMA stream and OS mapper context. Refuse incomplete graphs and
/// ambiguous owners before retaining an instance ordinal.
fn dcp_device(
    io: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
    darts: &[Iommu],
) -> Result<Option<DcpController>, String> {
    let children = io.children().ok_or("DCP arm-io children are malformed")?;
    let mut matches = children.iter().filter_map(|n| {
        n.compatible(ASC)
            .then(|| n.property("role").and_then(external_output))
            .flatten()
            .map(|profile| (n, profile))
    });
    let Some((node, profile)) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err("one GOP resource cannot back two external pipelines".into());
    }
    let path = format!("/arm-io/{}", profile.controller);
    let err = |reason: &str| format!("{path}: {reason}");
    let place = |offset: u64, bytes: u64| -> Result<(u64, u64), String> {
        if bytes == 0 {
            return Err(err("aperture is empty"));
        }
        let physical = io
            .translate_range(offset, bytes)
            .ok_or_else(|| err("complete aperture is not owned by contiguous arm-io ranges"))?;
        if translate(offset) != Some(physical) {
            return Err(err(
                "aperture translation differs from its declared arm-io owner",
            ));
        }
        Ok((physical, bytes))
    };
    let nub = rtbuddy_nub(node, profile.role)?;
    if profile
        .external_index
        .is_some_and(|index| nub.property("external-index") != Some(index.to_le_bytes().as_slice()))
    {
        return Err(err(
            "RTBuddy external-index differs from its native output identity",
        ));
    }
    let mut experts = children
        .iter()
        .filter(|n| n.compatible(DCP_EXPERT) && n.property("role") == Some(profile.role_property));
    let expert = experts
        .next()
        .ok_or_else(|| err("required same-role DCP expert is absent"))?;
    if experts.next().is_some() {
        return Err(err("same-role DCP experts are ambiguous"));
    }
    if expert.property("reg").is_some()
        || expert.property("join-power-plane") != Some(1u32.to_le_bytes().as_slice())
        || DCP_EXPERT_HARDWARE_FEATURES
            .iter()
            .any(|flag| expert.property(flag).is_some())
    {
        return Err(err(
            "DCP expert requires an unmodeled hardware power operation",
        ));
    }
    let pipe = io
        .child(profile.pipe)
        .filter(|n| n.compatible(profile.compatible))
        .ok_or_else(|| err("matching external display pipe is absent"))?;
    if profile.external_index.is_some() && pipe.first_u32("external") != Some(1) {
        return Err(err(
            "selected external pipe lacks its original external marker",
        ));
    }
    let wrapper = node
        .pairs("reg")
        .unwrap_or_default()
        .first()
        .copied()
        .ok_or_else(|| err("ASC has no register range"))?;
    if wrapper.1 < asc::WRAPPER_BYTES {
        return Err(err("ASC aperture is incomplete"));
    }
    let interrupts: [u32; 4] = node
        .cells32("interrupts")
        .unwrap_or_default()
        .as_slice()
        .try_into()
        .ok()
        .filter(|_| {
            node.property("interrupts")
                .is_some_and(|bytes| bytes.len() == 16)
        })
        .ok_or_else(|| err("ASC requires exactly four mailbox interrupts"))?;
    if interrupts.iter().any(|&irq| u16::try_from(irq).is_err()) {
        return Err(err("mailbox interrupt exceeds the AIC encoding"));
    }
    let route = |parent: u32| -> Result<(usize, usize, u32, u32), String> {
        let mut found = darts.iter().enumerate().flat_map(|(index, dart)| {
            dart.mappers
                .iter()
                .filter(move |(phandle, _)| *phandle == parent)
                .map(move |&(_, context)| (index, dart, context))
        });
        let (index, dart, context) = found.next().ok_or_else(|| err("mapper is not mounted"))?;
        if found.next().is_some() {
            return Err(err("mapper ownership is ambiguous"));
        }
        if dart.instances.len() != 1 {
            return Err(err("DMA owner requires explicit multiple-TRAD selection"));
        }
        if !dart.sids.is_empty() && !dart.sids.contains(&context) {
            return Err(err("mapper context is absent from the original SID set"));
        }
        // DART owner supplies this pure join. It preserves mapper context0
        // while returning incoming5 for the original remap5->0.
        let input = dart
            .profile
            .mapper_input_stream(usize::from(dart.streams), context as usize, &dart.remap)
            .map_err(err)?;
        let input = u32::try_from(input).map_err(|_| err("DMA input stream overflows"))?;
        Ok((index, 0, context, input))
    };
    let phandle = native_dma_phandle(node, "AAPL,phandle").map_err(|why| err(&why))?;
    let mapper = native_dma_phandle(node, "iommu-parent")
        .map_err(|why| err(&why))?
        .ok_or_else(|| err("controller has no iommu-parent"))?;
    let surface_phandle = native_dma_phandle(&pipe, "AAPL,phandle").map_err(|why| err(&why))?;
    let surface_mappers = native_dma_mapper_list(&pipe, "iommu-parent").map_err(|why| err(&why))?;
    let (iommu, instance, mapper_context, stream) = route(mapper)?;
    let surface_routes = surface_mappers
        .into_iter()
        .map(|mapper| {
            let (iommu, instance, mapper_context, stream) = route(mapper)?;
            Ok(DcpMapperRoute {
                mapper,
                iommu,
                instance,
                mapper_context,
                stream,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let primary_route = surface_routes
        .first()
        .ok_or_else(|| err("pipe has no surface iommu-parent"))?;
    let pipe_reg = pipe
        .property("reg")
        .ok_or_else(|| err("pipe has no register apertures"))?;
    if pipe_reg.is_empty() || !pipe_reg.len().is_multiple_of(16) {
        return Err(err("pipe register apertures are incomplete"));
    }
    let mut regions = pipe
        .pairs("reg")
        .unwrap_or_default()
        .into_iter()
        .map(|(base, bytes)| {
            if bytes == 0 {
                return Err(err("pipe register aperture is empty"));
            }
            let range = place(base, bytes)?;
            if range.0.checked_add(range.1).is_none() {
                return Err(err("pipe register aperture overflows"));
            }
            Ok((profile.pipe, range))
        })
        .collect::<Result<Vec<_>, String>>()?;
    // Preserve existing optional J473 aperture placement. These physical-link
    // services remain outside admission; they are not invented T6000 nodes.
    if profile.identity == dcp::ExternalIdentity::Unnumbered {
        for (name, compatible) in [
            ("dptx-phy", DPTX_PHY),
            ("display-crossbar0", DISPLAY_CROSSBAR),
        ] {
            if let Some(child) = io.child(name).filter(|n| n.compatible(compatible)) {
                let reg = child
                    .pairs("reg")
                    .unwrap_or_default()
                    .first()
                    .copied()
                    .ok_or_else(|| err("display aperture lacks reg"))?;
                regions.push((name, place(reg.0, reg.1)?));
            }
        }
    }
    Ok(Some(DcpController {
        phandle,
        mapper,
        surface_phandle,
        surface_instance: Some(primary_route.instance),
        surface: Some((primary_route.iommu, primary_route.stream)),
        surface_routes,
        role: profile.role,
        identity: profile.identity,
        instance,
        mapper_context,
        wrapper: place(wrapper.0, wrapper.1)?,
        interrupts,
        quiesced: nub.property("quiesced").is_some(),
        regions,
        iommu,
        stream,
        window: node.property("truncate-dvas").map(|_| darts[iommu].vm_base),
    }))
}

/// The board a DeviceTree describes, or why the engine cannot model it: its
/// chip and PEs ([`cpus`], from `/chosen` `chip-id`, `/product`
/// `product-soc-name` and each `/cpus` node with a `cluster-type`) and the
/// devices the engine models, each of which must be `compatible` with its
/// model. An `/arm-io` child's `reg` is translated through `/arm-io`
/// `ranges`; the AIC's input count is one more than the highest
/// `interrupts` value of any node whose `interrupt-parent` is its phandle.
pub fn board(tree: &[u8]) -> Result<Board, String> {
    let root = Node::root(tree).ok_or("DeviceTree has no root")?;
    let chip_id = root
        .child("chosen")
        .and_then(|chosen| chosen.first_u32("chip-id"))
        .ok_or("DeviceTree has no /chosen chip-id")?;
    let soc_name = root
        .child("product")
        .and_then(|product| product.property("product-soc-name"))
        .and_then(|name| core::str::from_utf8(name).ok())
        .map(|name| name.trim_end_matches('\0'))
        .ok_or("DeviceTree has no /product product-soc-name")?;
    let mut found = Vec::new();
    let mut blocks = Vec::new();
    let mut debug_components = Vec::new();
    root.child("cpus")
        .ok_or("DeviceTree has no /cpus")?
        .visit(&mut |node| {
            if let Some(cluster_type) = node.property("cluster-type") {
                if node.property("coresight-reg").is_some() {
                    debug_components.push((found.len(), node.pairs("coresight-reg")));
                }
                found.push((
                    cluster_type.first().copied(),
                    node.first_u32("reg"),
                    node.first_u32("l2-cache-size"),
                ));
                for (index, name) in ["cpu-impl-reg", "cpm-impl-reg"].into_iter().enumerate() {
                    let pe = (index == 0).then(|| found.len() - 1);
                    blocks.push((index, name, node.pairs(name), pe));
                }
            }
        })
        .ok_or("DeviceTree walk failed")?;
    let coresight = debug_components
        .into_iter()
        .map(|(cpu, pairs)| {
            place_coresight(
                cpu,
                &pairs.ok_or("CPU CoreSight reg contains partial records")?,
            )
        })
        .collect::<Result<Vec<_>, String>>()?;
    let processors = found
        .into_iter()
        .map(|found| match found {
            (Some(cluster_type), Some(reg), l2_bytes) => Ok(Processor {
                cluster_type,
                reg,
                l2_bytes,
            }),
            _ => Err("a /cpus node has no reg or an empty cluster-type"),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let cpus = cpus(chip_id, soc_name, &processors)?;
    let mut counters = Vec::new();
    if let Some(layout) = core_counters::layout(chip_id) {
        let end = layout
            .windows()
            .map(|(offset, bytes)| offset + bytes)
            .max()
            .unwrap_or(0);
        for (_, name, pairs, cpu) in blocks.iter().filter(|block| block.0 == 0) {
            let (physical, bytes) = pairs
                .as_ref()
                .and_then(|pairs| pairs.first().copied())
                .ok_or_else(|| format!("a /cpus node has no {name}"))?;
            if end > bytes {
                return Err(format!("{name} at {physical:#x} has no sampler counters"));
            }
            counters.push(CounterBlock {
                cpu: cpu.expect("every cpu-impl-reg names its PE"),
                physical,
                layout,
            });
        }
    }
    let mut lockdown: Vec<LockdownBlock> = Vec::new();
    for (index, name, pairs, cpu) in blocks.into_iter().filter(|_| cpus.lockdown.is_some()) {
        let (physical, bytes) = pairs
            .and_then(|pairs| pairs.first().copied())
            .ok_or_else(|| format!("a /cpus node has no {name}"))?;
        let control = cpus.lockdown.expect("filtered")[index];
        if control + 16 > bytes {
            return Err(format!("{name} at {physical:#x} has no lockdown registers"));
        }
        if !lockdown.iter().any(|block| block.physical == physical) {
            lockdown.push(LockdownBlock {
                name,
                physical,
                bytes,
                control,
                cpu,
            });
        }
    }
    let io = root.child("arm-io").ok_or("DeviceTree has no /arm-io")?;
    let ranges = io.ranges().ok_or("/arm-io has no ranges")?;
    let translate = |offset: u64| {
        ranges
            .iter()
            .find(|(child, _, size)| (*child..child + size).contains(&offset))
            .map(|(child, parent, _)| parent + (offset - child))
    };
    let place = |name: &str, model: Option<&str>| -> Result<(Node<'_>, u64, u64), String> {
        let node = io
            .child(name)
            .ok_or_else(|| format!("DeviceTree has no /arm-io/{name}"))?;
        if let Some(model) = model
            && !node.compatible(model)
        {
            return Err(format!("/arm-io/{name} is not {model}, the modeled device"));
        }
        let (offset, bytes) = node
            .pairs("reg")
            .and_then(|reg| reg.first().copied())
            .ok_or_else(|| format!("/arm-io/{name} has no reg"))?;
        let physical = translate(offset)
            .ok_or_else(|| format!("/arm-io/{name} lies outside /arm-io ranges"))?;
        Ok((node, physical, bytes))
    };
    let device = |name: &str, model: &str| -> Result<Device, String> {
        let (node, physical, bytes) = place(name, Some(model))?;
        let irq = node
            .first_u32("interrupts")
            .ok_or_else(|| format!("/arm-io/{name} has no interrupts"))?;
        Ok(Device {
            physical,
            bytes,
            irq,
        })
    };
    let uart = device("uart0", UART)?;
    let watchdog = device("wdt", WATCHDOG)?;
    let watchdog_side = watchdog_side(&io.child("wdt").expect("device was placed"), &translate)?;
    let (version, event) = cpus
        .aic
        .ok_or("the SoC's AIC event register offset is unknown")?;
    let (aic, physical, _) = place("aic", Some(version))?;
    let layout = aic_layout(&aic, version, event)?;
    let phandle = aic
        .first_u32("AAPL,phandle")
        .ok_or("/arm-io/aic has no phandle")?;
    let mut highest = None;
    root.visit(&mut |node| {
        if node.first_u32("interrupt-parent") == Some(phandle)
            && let Some(cells) = node.cells32("interrupts")
        {
            highest = cells.into_iter().chain(highest).max();
        }
    })
    .ok_or("DeviceTree walk failed")?;
    let highest = highest.ok_or("no node names the AIC as its interrupt parent")?;
    let inputs = u16::try_from(highest + 1).map_err(|_| "AIC interrupt number above 65534")?;
    let chosen = root.child("chosen").ok_or("DeviceTree has no /chosen")?;
    let memory_controller = memory_controller(&chosen)?;
    let io_access_controller = memory_controller_named(&chosen, "ioa")?;
    let gpio = gpio_bank(&io, &translate, phandle)?;
    let aux_gpios = aux_gpio_banks(&root, &io, &translate, phandle)?;
    let (i2cs, typec_phys) = typec_devices(&io, &translate, phandle, gpio.as_ref())?;
    let darts = iommus(&io, &translate)?;
    let aes = aes_engine(&io, &translate, &darts)?;
    let iboot_security = root
        .child("defaults")
        .is_some_and(|defaults| defaults.property("nvme-iboot-sptm-security").is_some());
    let ans = ans_controller(&io, &translate, iboot_security)?;
    let smc = smc_controller(&root, &io, &translate)?;
    let pmp = pmp_controller(&io, &translate)?;
    let gfx = gfx_controller(&io, &translate, chip_id)?;
    let sep = sep_device(&root, &io, &translate, &darts)?;
    let usbs = usb_controllers(&io, &translate, &darts)?;
    let power_states = power_states(&root, &translate, chip_id)?;
    let PmgrRegisters {
        cluster_events,
        bridges,
        soc_dpe,
        power_banks,
        wake_masks,
        performance,
        energy,
        clusters,
        aon_fuses,
        cpu_start,
    } = pmgr_registers(&io, &translate, chip_id, &cpus.processors)?;
    let memory_cache = memory_cache(&io, &translate, chip_id, memory_controller.as_ref())?;
    let direct_memory_cache =
        memory_resources::direct_memory_cache(&io, &translate, memory_controller.as_ref())?;
    let spi_nor = spi_nor(&root, &io, &translate, phandle, gpio.as_ref())?;
    let spmis = spmi_controllers(&io, &translate, phandle)?;
    let dcp = dcp_device(&io, &translate, &darts)?;
    Ok(Board {
        spmis,
        dcp,
        gpio,
        aux_gpios,
        i2cs,
        typec_phys,
        cluster_events,
        bridges,
        soc_dpe,
        power_banks,
        spi_nor,
        wake_masks,
        performance,
        energy,
        cpus,
        uart,
        watchdog,
        watchdog_side,
        lockdown,
        counters,
        coresight,
        memory_controller,
        io_access_controller,
        darts,
        aes,
        ans,
        smc,
        pmp,
        gfx,
        sep,
        usbs,
        power_states,
        memory_cache,
        direct_memory_cache,
        clusters,
        aon_fuses,
        cpu_start,
        aic: InterruptController {
            physical,
            inputs,
            layout,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The T8112 row's PMGR compatible.
    const PMGR: &str = "pmgr1,t8112";

    fn layout_of(layout: &[(u8, u32)]) -> Vec<Processor> {
        layout
            .iter()
            .map(|&(cluster_type, reg)| Processor {
                cluster_type,
                reg,
                l2_bytes: Some(if cluster_type == b'P' {
                    16 << 20
                } else {
                    4 << 20
                }),
            })
            .collect()
    }

    #[test]
    fn io_access_description_preserves_optional_controls_and_absolute_page_basis() {
        use crate::machine::adt::encode;
        let chosen = |partial_enable: bool, extra_address_byte: bool| {
            let mut properties: Vec<(String, Vec<u8>)> = vec![
                ("name".into(), b"ioa-ctrr-a\0".to_vec()),
                ("page-size-shift".into(), 14u32.to_le_bytes().to_vec()),
            ];
            for (name, offset, mask, value) in [
                ("lower-limit", 0x220u32, u32::MAX, None),
                ("upper-limit", 0x224, u32::MAX, None),
                ("enable", 0x228, 1, Some(1u32)),
            ] {
                properties.push((format!("{name}-reg-offset"), offset.to_le_bytes().to_vec()));
                properties.push((format!("{name}-reg-mask"), mask.to_le_bytes().to_vec()));
                if let Some(value) = value
                    && !partial_enable
                {
                    properties.push((format!("{name}-reg-value"), value.to_le_bytes().to_vec()));
                }
            }
            let refs: Vec<_> = properties
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_slice()))
                .collect();
            let group = encode(&refs, &[]);
            let mut addresses = 0x282000000u64.to_le_bytes().to_vec();
            if extra_address_byte {
                addresses.push(0);
            }
            let controller = encode(
                &[
                    ("name", b"ioa\0"),
                    ("aperture-count", &1u32.to_le_bytes()),
                    ("aperture-size", &0x4000u32.to_le_bytes()),
                    ("aperture-phys-addr", &addresses),
                    ("plane-count", &1u32.to_le_bytes()),
                    ("plane-stride", &0u32.to_le_bytes()),
                ],
                &[group],
            );
            let registers = encode(&[("name", b"lock-regs\0")], &[controller]);
            encode(
                &[("dram-base", &0x10000000000u64.to_le_bytes())],
                &[registers],
            )
        };
        let bytes = chosen(false, false);
        let root = Node::root(&bytes).unwrap();
        assert!(memory_controller(&root).unwrap().is_none());
        let ioa = memory_controller_named(&root, "ioa").unwrap().unwrap();
        assert_eq!(ioa.apertures, [0x282000000]);
        assert_eq!(ioa.layout.dram_base, 0);
        assert_eq!(ioa.layout.stride, 0);
        assert_eq!(ioa.layout.cache_status, None);
        assert_eq!(ioa.layout.group.lower_limit.offset, 0x220);
        assert_eq!(ioa.layout.group.enable.unwrap().offset, 0x228);
        assert_eq!(ioa.layout.group.write_disable, None);
        assert_eq!(ioa.layout.group.lock, None);
        for bytes in [chosen(true, false), chosen(false, true)] {
            assert!(memory_controller_named(&Node::root(&bytes).unwrap(), "ioa").is_err());
        }
    }

    #[test]
    fn coresight_lock_uses_the_dt_component_base_and_stays_inside_its_region() {
        assert_eq!(
            place_coresight(3, &[(0x2_1001_0000, 0x300c8)]).unwrap(),
            CoreSight {
                cpu: 3,
                physical: 0x2_1001_0000,
                bytes: 0x300c8
            }
        );
        let mut component = place_coresight(3, &[(0x2_1001_0000, 0x300c8)]).unwrap();
        assert_eq!(component.pc_sampler(), Some(0x2_1004_0000));
        component.bytes = coresight::UTT_OFFSET + coresight::PC_SAMPLE + 7;
        assert_eq!(component.pc_sampler(), None);
        component.bytes += 1;
        assert_eq!(component.pc_sampler(), Some(0x2_1004_0000));
        for pairs in [
            vec![],
            vec![(0x2_1001_0001, 0x3c8)],
            vec![(0, 0)],
            vec![(0, 0x3c8)],
            vec![(u64::MAX - 0xfff, 4)],
        ] {
            assert!(place_coresight(0, &pairs).is_err());
        }
    }

    #[test]
    fn dart_supply_ids_and_retention_come_from_dt_properties() {
        use crate::machine::adt::encode;
        let reg = [0x35004000u64, 0x4000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        let tree = |gates: &[u8], retention: bool, no_sleep: bool| {
            let mut props = vec![
                ("compatible", b"dart,t8110\0".as_slice()),
                ("reg", reg.as_slice()),
                ("instance", b"TRAD\0\0\0\0DART\0\0\0\0".as_slice()),
                ("sid-count", &b"\x10\0\0\0"[..]),
                ("interrupts", &b"\x01\x03\0\0"[..]),
                ("power-gates", gates),
            ];
            if retention {
                props.push(("retention", &[]));
            }
            if no_sleep {
                props.push(("no-sleep", &[]));
            }
            encode(&props, &[])
        };
        let gates = [0x212u32, 0x216]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let encoded = tree(&gates, true, false);
        let node = Node::root(&encoded).unwrap();
        let dart = iommu(&node, &|a| Some(a + 0x2_0000_0000)).unwrap();
        assert_eq!(dart.power_gates, vec![0x212, 0x216]);
        assert!(dart.retention);
        for encoded in [
            tree(&gates[..3], false, false),
            tree(&u32::MAX.to_le_bytes(), false, false),
            tree(&gates, true, true),
        ] {
            assert!(iommu(&Node::root(&encoded).unwrap(), &Some).is_err());
        }
    }

    #[test]
    fn watchdog_side_words_use_independent_translated_dt_ranges() {
        use crate::machine::adt::encode;
        let reg = [
            0x1000u64, 0x4000, 0xc218, 4, 0x8008, 4, 0x800c, 4, 0x8020, 4,
        ]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect::<Vec<_>>();
        let trigger = [0x10020304u32, 2, 0xf, 1, 0x10120304, 2, 0xf, 1]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let bit = |n: u32| n.to_le_bytes();
        let (zero, two) = (bit(0), bit(2));
        let tree = encode(
            &[
                ("reg", &reg),
                ("panic-save-flag-bit", &zero),
                ("panic-forcepoweroff-flag-bit", &two),
                ("trigger-config", &trigger),
            ],
            &[],
        );
        let n = Node::root(&tree).unwrap();
        assert_eq!(
            watchdog_side(&n, &|a| Some(a + 0x2_0000_0000)).unwrap(),
            Some(WatchdogSide {
                words: vec![0x2_0000_c218, 0x2_0000_8008, 0x2_0000_800c, 0x2_0000_8020],
                // Trigger words are absolute physical addresses.
                triggers: vec![(0x2_1002_0304, 0xf, 1), (0x2_1012_0304, 0xf, 1)],
            })
        );
        assert!(watchdog_side(&n, &|_| None).is_err());
        let tree = encode(&[("reg", &reg), ("panic-save-flag-bit", &zero)], &[]);
        // reg[4] needs its force-power-off flag bit.
        assert!(watchdog_side(&Node::root(&tree).unwrap(), &Some).is_err());
        let tree = encode(
            &[
                ("reg", &reg[..48]),
                ("panic-save-flag-bit", &32u32.to_le_bytes()),
            ],
            &[],
        );
        assert!(watchdog_side(&Node::root(&tree).unwrap(), &Some).is_err());
        let tree = encode(&[("reg", &reg[..48]), ("panic-save-flag-bit", &zero)], &[]);
        assert_eq!(
            watchdog_side(&Node::root(&tree).unwrap(), &Some)
                .unwrap()
                .unwrap()
                .words,
            [0xc218, 0x8008]
        );
        let tree = encode(&[("reg", &reg[..16])], &[]);
        assert_eq!(
            watchdog_side(&Node::root(&tree).unwrap(), &Some).unwrap(),
            None
        );
    }

    #[test]
    #[ignore = "requires original 26A434 J314s DT through STELA_TEST_DART_DT"]
    fn original_j314s_watchdog_mounts_one_shared_panic_flags_word() {
        use crate::machine::{
            Devices,
            apple::{AppleDevices, Range},
        };
        let data = std::fs::read(std::env::var("STELA_TEST_DART_DT").unwrap()).unwrap();
        assert_eq!(
            crate::sha256(&data),
            "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
        );
        let root = Node::root(&data).unwrap();
        let io = root.child("arm-io").unwrap();
        let ranges = io.ranges().unwrap();
        let translate = |offset: u64| {
            ranges.iter().find_map(|&(child, parent, bytes)| {
                offset
                    .checked_sub(child)
                    .filter(|&delta| delta < bytes)
                    .and_then(|delta| parent.checked_add(delta))
            })
        };
        let node = io.child("wdt").unwrap();
        let side = watchdog_side(&node, &translate).unwrap().unwrap();
        assert_eq!(
            side.words,
            [0x2922b8020, 0x2922b802c, 0x2922b8008, 0x2922b8020]
        );
        assert_eq!(node.first_u32("panic-save-flag-bit"), Some(0));
        assert_eq!(node.first_u32("panic-forcepoweroff-flag-bit"), Some(2));
        assert_eq!(side.triggers.len(), 10);
        let (offset, bytes) = node.pairs("reg").unwrap()[0];
        let mut devices = AppleDevices::new();
        devices
            .add_watchdog_with_side(
                Range {
                    physical: translate(offset).unwrap(),
                    bytes,
                },
                Some(&side),
                None,
                0,
            )
            .unwrap();
        devices.write(0, side.words[0], 4, 1, 0).unwrap();
        let word = devices.read(0, side.words[3], 4, 0).unwrap();
        devices.write(0, side.words[3], 4, word | 4, 0).unwrap();
        assert_eq!(devices.read(0, side.words[0], 4, 0), Ok(5));
    }

    #[test]
    fn s5l_gpio_admission_requires_qualified_pair_and_ap_role() {
        let compatible = b"gpio,t6000\0gpio,s5l8960x\0";
        for role in [
            b"AP\0".as_slice(),
            b"AOP\0",
            b"SMC\0",
            b"NUB\0",
            b"unknown\0",
        ] {
            let property = |key: &str| match key {
                "compatible" => Some(compatible.as_slice()),
                "role" => Some(role),
                _ => None,
            };
            for name in [GPIO_T6000, GPIO_S5L] {
                assert_eq!(models(name, property), role == b"AP\0");
            }
        }
        for compatible in [
            b"gpio,s5l8960x\0".as_slice(),
            b"gpio,t9999\0gpio,s5l8960x\0",
            b"gpio,t6000\0gpio,t8101\0gpio,s5l8960x\0",
        ] {
            assert!(!models(GPIO_S5L, |key| match key {
                "compatible" => Some(compatible),
                "role" => Some(b"AP\0"),
                _ => None,
            }));
        }
    }

    #[test]
    fn s5l_ap_geometry_preserves_validated_restoration_exclusions() {
        use crate::machine::adt::encode;
        let make = |excluded: &[u8], override_key: Option<&str>| {
            let reg = [0x19b028000u64, 0x4000]
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>();
            let irqs = (427u32..434).flat_map(u32::to_le_bytes).collect::<Vec<_>>();
            let pins = 255u32.to_le_bytes();
            let groups = 7u32.to_le_bytes();
            let parent = 130u32.to_le_bytes();
            let phandle = 136u32.to_le_bytes();
            let mut properties = vec![
                ("compatible", b"gpio,t6000\0gpio,s5l8960x\0".as_slice()),
                ("role", b"AP\0"),
                ("reg", reg.as_slice()),
                ("#gpio-pins", &pins),
                ("#gpio-int-groups", &groups),
                ("interrupt-parent", &parent),
                ("interrupts", irqs.as_slice()),
                ("AAPL,phandle", &phandle),
                ("no-restore-gpio-pins", excluded),
            ];
            if let Some(key) = override_key {
                properties.push((key, b""));
            }
            encode(&properties, &[])
        };
        let excluded = [114u32, 115, 119]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let data = make(&excluded, None);
        let bank = gpio_geometry(
            &Node::root(&data).unwrap(),
            &|value| value.checked_add(0x200000000),
            130,
        )
        .unwrap();
        assert_eq!(bank.profile, gpio::Profile::S5l8960x);
        assert_eq!(bank.physical, 0x39b028000);
        assert_eq!(bank.no_restore_pins, [114, 115, 119]);
        for values in [vec![114u32, 114], vec![255], vec![u32::MAX]] {
            let raw = values
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>();
            let data = make(&raw, None);
            assert!(gpio_geometry(&Node::root(&data).unwrap(), &Some, 130).is_err());
        }
        let data = make(&excluded[..3], None);
        assert!(gpio_geometry(&Node::root(&data).unwrap(), &Some, 130).is_err());
        for key in [
            "no-resume-restore",
            "supported-int-groups",
            "wake-events",
            "wake-no-interrupt-group",
        ] {
            let data = make(&excluded, Some(key));
            assert!(gpio_geometry(&Node::root(&data).unwrap(), &Some, 130).is_err());
        }
    }

    #[test]
    #[ignore = "requires original26A434J314sDT throughSTELA_TEST_GPIO_DT"]
    fn original_j314s_ap_gpio_qualifies_without_auxiliary_or_lifecycle_claims() {
        let data = std::fs::read(std::env::var("STELA_TEST_GPIO_DT").unwrap()).unwrap();
        assert_eq!(
            crate::sha256(&data),
            "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
        );
        let root = Node::root(&data).unwrap();
        let io = root.child("arm-io").unwrap();
        let ranges = io.ranges().unwrap();
        let translate = |offset| {
            ranges
                .iter()
                .find(|(child, _, bytes)| (*child..child + bytes).contains(&offset))
                .map(|(child, parent, _)| parent + (offset - child))
        };
        let bank = gpio_bank(&io, &translate, 130).unwrap().unwrap();
        assert_eq!(bank.profile, gpio::Profile::S5l8960x);
        assert_eq!(
            (
                bank.physical,
                bank.bytes,
                bank.pins,
                bank.groups,
                bank.phandle
            ),
            (0x39b028000, 0x4000, 255, 7, 136)
        );
        assert_eq!(bank.lines, [427, 428, 429, 430, 431, 432, 433]);
        assert_eq!(bank.no_restore_pins, [114, 115, 119]);
        for name in ["aop-gpio0", "nub-gpio0", "smc-gpio"] {
            let node = io.child(name).unwrap();
            assert!(gpio_profile(|key| node.property(key)).is_none());
        }
        assert_eq!(
            io.child("spi1").unwrap().cells32("function-spi_cs0"),
            Some(vec![136, GPIO_FUNCTION, 33, 0x10001])
        );
    }

    #[test]
    fn other_gpio_banks_carry_the_pins_their_clients_name() {
        use crate::machine::adt::encode;
        let words = |v: &[u32]| v.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>();
        let pairs = |v: &[u64]| v.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>();
        // J473AP's aop-gpio, its dp2hdmi-gpio client and a hidden smc-gpio.
        let aop = encode(
            &[
                ("name", b"aop-gpio\0"),
                ("compatible", b"gpio,t8101\0"),
                ("reg", &pairs(&[0x4a820000, 0x4000])),
                ("#gpio-pins", &words(&[0x36])),
                ("#gpio-int-groups", &words(&[7])),
                ("AAPL,phandle", &words(&[0x6b])),
                ("interrupt-parent", &words(&[99])),
                (
                    "interrupts",
                    &words(&[0x12d, 0x12e, 0x12f, 0x130, 0x131, 0x132, 0x133]),
                ),
            ],
            &[],
        );
        let hidden = encode(
            &[
                ("name", b"smc-gpio\0"),
                ("reg", &pairs(&[0x3e820000, 0x4000])),
                ("AAPL,phandle", &words(&[0x6d])),
            ],
            &[],
        );
        let client = encode(
            &[
                ("name", b"dp2hdmi-gpio\0"),
                ("interrupt-parent", &words(&[0x6b])),
                ("interrupts", &words(&[0x31, 0x500_0004])),
                (
                    "function-hdmi_hpd",
                    &words(&[0x6b, GPIO_FUNCTION, 0x31, 0x100]),
                ),
                (
                    "function-force-dpfu",
                    &words(&[0x6b, GPIO_FUNCTION, 0x28, 0x1]),
                ),
                (
                    "function-hdmi_pwr_en",
                    &words(&[0x91, u32::from_be_bytes(*b"pKW4"), 0x6750_3136, 0x80_0000]),
                ),
            ],
            &[],
        );
        let io = encode(&[("name", b"arm-io\0")], &[aop, hidden, client]);
        let data = encode(&[("name", b"device-tree\0")], &[io]);
        let root = Node::root(&data).unwrap();
        let io = root.child("arm-io").unwrap();
        let translate = |v: u64| v.checked_add(0x2_0000_0000);
        let banks = aux_gpio_banks(&root, &io, &translate, 99).unwrap();
        assert_eq!(banks.len(), 1);
        assert_eq!(banks[0].name, "aop-gpio");
        assert_eq!(banks[0].bank.physical, 0x2_4a82_0000);
        assert_eq!(banks[0].bank.pins, 0x36);
        assert_eq!(banks[0].client_pins, [0x28, 0x31]);
        assert!(aux_gpio_banks(&root, &io, &translate, 100).is_err());
    }

    #[test]
    fn spi_nor_placement_uses_dt_ranges_bank_proxy_and_gpio_function() {
        use crate::machine::adt::encode;
        let words = |v: &[u32]| v.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>();
        let pairs = |v: &[u64]| v.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>();
        let partitions: Vec<_> = [
            ("firmware", nor::FIRMWARE),
            ("anvram", nor::ANVRAM),
            ("syscfg", nor::SYSCFG),
        ]
        .into_iter()
        .map(|(name, (offset, size))| {
            encode(
                &[("name", name.as_bytes()), ("reg", &words(&[offset, size]))],
                &[],
            )
        })
        .collect();
        let flash = encode(
            &[
                ("name", b"spinor"),
                ("compatible", NOR.as_bytes()),
                ("reg", &words(&[0, 25, 0x08010000, 0, 20, 0, 0, 0])),
                ("ranges", &words(&[0, 0, nor::CAPACITY as u32])),
            ],
            &partitions,
        );
        let spi = encode(
            &[
                ("name", b"spi1"),
                ("compatible", SPI.as_bytes()),
                ("spi-version", &words(&[1])),
                ("reg", &pairs(&[0x35104000, 0x4000])),
                ("interrupts", &words(&[749])),
                ("interrupt-parent", &words(&[99])),
                (
                    "function-spi_cs0",
                    &words(&[106, GPIO_FUNCTION, 49, 0x10001]),
                ),
            ],
            &[flash],
        );
        let gpio = encode(
            &[
                ("name", b"gpio"),
                ("compatible", GPIO.as_bytes()),
                ("reg", &pairs(&[0x3c100000, 0x100000])),
                ("#gpio-pins", &words(&[213])),
                ("#gpio-int-groups", &words(&[7])),
                ("AAPL,phandle", &words(&[106])),
                ("interrupt-parent", &words(&[99])),
                ("interrupts", &words(&[199, 200, 201, 202, 203, 204, 205])),
            ],
            &[],
        );
        let i2c = encode(
            &[
                ("name", b"i2c2"),
                ("gpio-iic_sda", &words(&[0x56, 0x10102, AP_GPIO_BANK])),
                ("gpio-lstx", &words(&[0x1c, 0x100, 0x504f41])),
                ("gpio-iic_scl", &words(&[0x57, 0x10102, 0x504f41])),
            ],
            &[],
        );
        let io = encode(&[("name", b"arm-io")], &[spi, gpio, i2c]);
        let chosen = encode(
            &[
                ("name", b"chosen"),
                ("nvram-proxy-data", &nor::nvram::empty_bank()),
                ("nvram-bank-size", &words(&[65536])),
                ("nvram-bank-count", &words(&[2])),
                ("nvram-current-bank", &words(&[0])),
            ],
            &[],
        );
        let data = encode(&[("name", b"device-tree")], &[chosen, io]);
        let root = Node::root(&data).unwrap();
        let io = root.child("arm-io").unwrap();
        let translate = |v: u64| v.checked_add(0x2_0000_0000);
        let bank = gpio_bank(&io, &translate, 99).unwrap().unwrap();
        assert_eq!(bank.physical, 0x2_3c10_0000);
        assert_eq!(bank.lines, [199, 200, 201, 202, 203, 204, 205]);
        // Only the AP bank's I2C line; the AOP-bank pin belongs elsewhere.
        assert_eq!(bank.i2c_lines, [0x56]);
        assert!(gpio_bank(&io, &translate, 100).is_err());
        let placed = spi_nor(&root, &io, &translate, 99, Some(&bank))
            .unwrap()
            .unwrap();
        assert_eq!(placed.device.physical, 0x2_3510_4000);
        assert_eq!(placed.device.irq, 749);
        assert_eq!(placed.select, Some(49));
        assert_eq!(placed.image.bank(0).unwrap(), nor::nvram::empty_bank());
        assert!(spi_nor(&root, &io, &|_| None, 99, Some(&bank)).is_err());
        assert!(spi_nor(&root, &io, &Some, 100, Some(&bank)).is_err());
        assert!(spi_nor(&root, &io, &translate, 99, None).is_err());
    }

    #[test]
    fn ans2_placement_uses_phandles_interrupt_index_and_sparse_register_banks() {
        use crate::machine::adt::encode;
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let cells = |values: &[u32]| {
            values
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let pairs = |values: &[(u64, u64)]| {
            values
                .iter()
                .flat_map(|&(a, b)| [a, b])
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>()
        };
        let mut banks = vec![
            (0x7740_0000, 0x6c000),
            (0x7705_0000, 0x4000),
            (0, 0),
            (0x7bcc_0000, 0x60000),
        ];
        banks.resize(13, (0, 0));
        banks.push((0x7b10_0000, 0x44000));
        let banks = pairs(&banks);
        let flagged = |flags: &[&'static str], version: u32, parent: u32, interrupt_index: u32| {
            let nub = encode(
                &[("name", &z("iop-ans-nub")), ("compatible", &z(RTBUDDY))],
                &[],
            );
            let (name, compatible, role) = (z("ans"), z(ASC), z("ANS2"));
            let (entries, index) = (cells(&[64]), cells(&[interrupt_index]));
            let interrupts = cells(&[718, 717, 720, 719, 724]);
            let iommu = cells(&[parent]);
            let namespaces = cells(&[1, 1, 0, 2, 8, 768, 3, 13, 32768]);
            let gates = cells(&[125]);
            let mut properties: Vec<(&str, &[u8])> = vec![
                ("name", &name),
                ("compatible", &compatible),
                ("role", &role),
                ("reg", &banks),
                ("nvme-linear-sq", &[]),
                ("nvme-queue-entries", &entries),
                ("nvme-interrupt-idx", &index),
                ("interrupts", &interrupts),
                ("iommu-parent", &iommu),
                ("namespaces", &namespaces),
                ("clock-gates", &gates),
                ("power-gates", &gates),
            ];
            properties.extend(flags.iter().map(|&flag| (flag, [].as_slice())));
            let ans = encode(&properties, &[nub]);
            let sart = encode(
                &[
                    ("name", &z("sart-ans")),
                    ("compatible", &z(SART)),
                    ("sart-version", &cells(&[version])),
                    ("AAPL,phandle", &cells(&[0x8e])),
                    ("sart-power-reg-offset", &cells(&[0x13e8])),
                    (
                        "reg",
                        &pairs(&[(0x7bc5_0000, 0xc000), (0, 0), (0x7bcc_0000, 0x4000)]),
                    ),
                ],
                &[],
            );
            encode(&[("name", &z("arm-io"))], &[ans, sart])
        };
        let tree =
            |version, parent, interrupt_index| flagged(&[], version, parent, interrupt_index);
        let bytes = tree(3, 0x8e, 4);
        let io = Node::root(&bytes).unwrap();
        let placed = ans_controller(&io, &|offset| Some(0x2_0000_0000 + offset), true)
            .unwrap()
            .unwrap();
        assert_eq!(placed.wrapper, (0x2_7740_0000, 0x6c000));
        assert_eq!(placed.nvme, (0x2_7bcc_0000, 0x60000));
        assert_eq!(placed.sart, (0x2_7bc5_0000, 0xc000));
        assert_eq!(placed.sart_idle, 0x2_7bcc_13e8);
        assert!(!placed.sart_exclusive_bounds);
        assert_eq!(placed.completion_irq, 724);
        assert_eq!(placed.interrupts, [718, 717, 720, 719]);
        assert_eq!(
            placed.namespaces[2],
            ans::Description {
                id: 3,
                kind: 13,
                blocks: 32768
            }
        );
        assert_eq!(placed.clock_gates, [125]);
        // reg[13] is SPTM's VDMA cache only under nvme-vdma-wa.
        assert_eq!(placed.vdma, None);
        let vdma = flagged(&["nvme-vdma-wa"], 3, 0x8e, 4);
        let placed = ans_controller(&Node::root(&vdma).unwrap(), &|a| Some(a), true)
            .unwrap()
            .unwrap();
        assert_eq!(placed.vdma, Some((0x7b10_0000, 0x44000)));
        for flag in UNMODELED_ANS_SPTM {
            let bytes = flagged(&[flag], 3, 0x8e, 4);
            let error =
                ans_controller(&Node::root(&bytes).unwrap(), &|a| Some(a), true).unwrap_err();
            assert!(error.contains(flag), "{error}");
        }
        for bytes in [
            tree(2, 0x8e, 4),
            tree(3, 0x99, 4),
            tree(3, 0x8e, 3),
            tree(3, 0x8e, 5),
        ] {
            assert!(ans_controller(&Node::root(&bytes).unwrap(), &|a| Some(a), true).is_err());
        }
        assert!(ans_controller(&io, &|_| None, true).is_err());
        // Without the boot stage's security hand-off the kernel programs
        // registers the model does not carry.
        assert!(ans_controller(&io, &|offset| Some(0x2_0000_0000 + offset), false).is_err());
        // These compatibles are shared by other hardware. The partial ANS
        // controller cannot authorize advertising every ASC/RTBuddy/SART.
        assert!(!models(ASC, |_| None));
        assert!(!models(RTBUDDY, |_| None));
        assert!(!models(SART, |_| None));
    }

    #[test]
    fn pmp_placement_reads_its_wrapper_and_needs_a_user_managed_nub() {
        use crate::machine::adt::encode;
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let cells = |values: &[u32]| {
            values
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let pairs = |values: &[(u64, u64)]| {
            values
                .iter()
                .flat_map(|&(a, b)| [a, b])
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>()
        };
        let tree = |managed: u32| {
            let nub = encode(
                &[
                    ("name", &z("iop-pmp-nub")),
                    ("compatible", &z(RTBUDDY)),
                    ("user-power-managed", &cells(&[managed])),
                ],
                &[],
            );
            let pmp = encode(
                &[
                    ("name", &z("pmp")),
                    ("compatible", &z(ASC)),
                    ("role", &z("PMP")),
                    (
                        "reg",
                        &pairs(&[
                            (0x3bc0_0000, 0x6c000),
                            (0x3b85_0000, 0x4000),
                            (0x3b50_0000, 0x80000),
                            (0x3b3d_0000, 0x4000),
                        ]),
                    ),
                    ("interrupts", &cells(&[0x275, 0x274, 0x277, 0x276])),
                ],
                &[nub],
            );
            let io = encode(&[("name", &z("arm-io"))], &[pmp]);
            encode(&[("name", &z("device-tree"))], &[io])
        };
        let translate = |v: u64| v.checked_add(0x2_0000_0000);
        let data = tree(1);
        let root = Node::root(&data).unwrap();
        let io = root.child("arm-io").unwrap();
        assert_eq!(
            pmp_controller(&io, &translate).unwrap(),
            Some(PmpController {
                wrapper: (0x2_3bc0_0000, 0x6c000),
                interrupts: [0x275, 0x274, 0x277, 0x276],
                quiesced: false,
            })
        );
        let data = tree(0);
        let root = Node::root(&data).unwrap();
        assert!(pmp_controller(&root.child("arm-io").unwrap(), &translate).is_err());
        assert!(models(ASC, |key| (key == "role").then_some(b"PMP\0".as_slice())));
    }

    #[test]
    fn rtbuddy_endpoint_selection_uses_protocol_and_rejects_ambiguity() {
        use crate::machine::adt::encode;
        let endpoint = |name: &str, compatible: &str| {
            let name = [name.as_bytes(), &[0]].concat();
            let compatible = [compatible.as_bytes(), &[0]].concat();
            encode(&[("name", &name), ("compatible", &compatible)], &[])
        };
        for name in ["iop-gfx-nub", "iop-gfx-nub0", "arbitrary-label"] {
            let data = encode(&[], &[endpoint(name, RTBUDDY)]);
            let root = Node::root(&data).unwrap();
            assert_eq!(
                rtbuddy_nub(&root, "GFX").unwrap().property("name"),
                Some([name.as_bytes(), &[0]].concat().as_slice())
            );
        }
        let missing = encode(&[], &[endpoint("iop-gfx-nub", "unknown")]);
        assert!(rtbuddy_nub(&Node::root(&missing).unwrap(), "GFX").is_err());
        let duplicate = encode(&[], &[endpoint("a", RTBUDDY), endpoint("b", RTBUDDY)]);
        assert!(
            rtbuddy_nub(&Node::root(&duplicate).unwrap(), "GFX")
                .err()
                .unwrap()
                .contains("ambiguous")
        );
        let child = encode(
            &[
                ("compatible", b"iop-nub,rtbuddy-v2\0"),
                ("remote-only", b""),
            ],
            &[],
        );
        let data = encode(&[], &[child]);
        assert!(
            rtbuddy_nub(&Node::root(&data).unwrap(), "GFX")
                .err()
                .unwrap()
                .contains("remote-only")
        );
    }

    #[test]
    fn rtbuddy_nubs_the_ap_does_not_wait_for_refuse() {
        use crate::machine::adt::encode;
        let name = b"iop-pmp-nub ".to_vec();
        let set = 1u32.to_le_bytes().to_vec();
        let plain = encode(&[("name", &name)], &[]);
        assert!(awaited_nub(&Node::root(&plain).unwrap(), "PMP").is_ok());
        for flag in UNAWAITED_NUB {
            let data = encode(&[("name", &name), (flag, &set)], &[]);
            let error = awaited_nub(&Node::root(&data).unwrap(), "PMP").unwrap_err();
            assert!(error.contains(flag));
        }
    }

    #[test]
    fn the_gfx_role_claims_a_native_rtkit_nub_and_waits_for_gpu_admission() {
        let gfx_role = |key: &str| (key == "role").then_some(b"GFX\0".as_slice());
        let claim = ROLE_MODELS
            .iter()
            .find(|claim| claim.compatible == ASC && claim.property == ("role", b"GFX\0"))
            .unwrap();
        assert_eq!(claim.children.len(), 1);
        assert_eq!(claim.children[0].compatible, RTBUDDY);
        let preloaded = |name| {
            claim.children[0]
                .boot_properties
                .iter()
                .any(|&(key, _)| key == name)
        };
        assert!(preloaded("pre-loaded") && preloaded("running"));
        // The coprocessor, the GPU and its firmware mapper are admitted
        // together; the SEP and SMC claims are untouched.
        assert_eq!(models(ASC, gfx_role), GPU_ADMITTED);
        assert_eq!(
            model_children(ASC, gfx_role).len(),
            usize::from(GPU_ADMITTED)
        );
        for gpu in [
            "gpu,t8112",
            "gpu,t8103",
            "gpu,t6000",
            "gpu,t6020",
            "gpu,t6021",
            "gpu,t6022",
        ] {
            assert_eq!(models(gpu, |_| None), GPU_ADMITTED);
        }
        // A GPU whose family the firmware model does not implement stays
        // hidden.
        assert!(!models("gpu,t8122", |_| None));
        assert!(!models("gpu,t6041", |_| None));
        assert_eq!(models(GFX_MAPPER, |_| None), GPU_ADMITTED);
        assert!(!models(ASC, |key| (key == "role").then_some(b"GFX2\0".as_slice())));
        assert!(models(SEP, |key| (key == "role").then_some(b"SEP\0".as_slice())));
        assert!(models(ASC, |key| (key == "role").then_some(b"SMC\0".as_slice())));
    }

    #[test]
    fn gfx_placement_needs_the_coprocessor_and_the_gpu_together() {
        use crate::machine::adt::encode;
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let cells = |values: &[u32]| {
            values
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let pairs = |values: &[(u64, u64)]| {
            values
                .iter()
                .flat_map(|&(a, b)| [a, b])
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>()
        };
        let tree = |asc_visible: bool, sgx_visible: bool| {
            let nub = encode(
                &[("name", &z("iop-gfx-nub0")), ("compatible", &z(RTBUDDY))],
                &[],
            );
            let (name, role, asc_compatible) = (z("gfx-asc"), z("GFX"), z(ASC));
            let asc_reg = pairs(&[(0x640_0000, 0x6c000), (0x605_0000, 8)]);
            let irqs = cells(&[0x2c6, 0x2c5, 0x2c8, 0x2c7]);
            let mut asc: Vec<(&str, &[u8])> = vec![
                ("name", &name),
                ("role", &role),
                ("reg", &asc_reg),
                ("interrupts", &irqs),
            ];
            if asc_visible {
                asc.push(("compatible", &asc_compatible));
            }
            let (sgx_name, sgx_compatible) = (z("sgx"), z("gpu,t8112"));
            let sgx_reg = pairs(&[(0x400_0000, 0x400_0000), (0x4d0_0000, 0x2_0000)]);
            let ttbat_page = cells(&[0x20_0011]);
            let l2_base = 0x8_0008_8000u64.to_le_bytes();
            let l2_size = 0x4000u64.to_le_bytes();
            let mut sgx: Vec<(&str, &[u8])> = vec![
                ("name", &sgx_name),
                ("reg", &sgx_reg),
                ("gptbat-ready", b""),
                ("ttbat-phys-addr-base", &ttbat_page),
                ("gfx-shared-l2-region-base", &l2_base),
                ("gfx-shared-l2-region-size", &l2_size),
            ];
            if sgx_visible {
                sgx.push(("compatible", &sgx_compatible));
            }
            let io = encode(
                &[("name", &z("arm-io"))],
                &[encode(&asc, &[nub]), encode(&sgx, &[])],
            );
            encode(&[("name", &z("device-tree"))], &[io])
        };
        let translate = |offset| Some(0x2_0000_0000 + offset);
        let placed_on = |asc: bool, sgx: bool, chip_id: u32| {
            let bytes = tree(asc, sgx);
            let root = Node::root(&bytes).unwrap();
            let io = root.child("arm-io").unwrap();
            gfx_controller(&io, &translate, chip_id)
        };
        let placed = |asc: bool, sgx: bool| placed_on(asc, sgx, 0x8112);
        assert_eq!(
            placed(true, true).unwrap(),
            Some(GfxController {
                gpu: agx::generation::by_chip(0x8112).unwrap(),
                wrapper: (0x2_0640_0000, 0x6c000),
                interrupts: [0x2c6, 0x2c5, 0x2c8, 0x2c7],
                sgx: vec![(0x2_0400_0000, 0x400_0000, 0)],
                ttbat: 0x8_0004_4000,
                shared_l2: 0x8_0008_8000,
            })
        );
        assert_eq!(placed(false, false).unwrap(), None);
        assert!(placed(true, false).is_err());
        assert!(placed(false, true).is_err());
        // The `sgx` must be the board chip's own GPU.
        assert!(placed_on(true, true, 0x8103).is_err());
    }

    /// The census `sgx` layouts: T8112's `reg[1]` inside `reg[0]`, the
    /// T6000's 1 MiB `reg[0]` with the registers in `reg[1]`, and the
    /// T6020's longer `reg[1]` that holds the G14X core masks.
    #[test]
    fn sgx_banks_place_the_registers_at_their_offsets_from_reg0() {
        use agx::generation::{G13X, G14G, G14X};
        let t8112 = sgx_banks((0x2_0400_0000, 0x400_0000), (0x2_04d0_0000, 0x2_0000)).unwrap();
        assert_eq!(t8112, [(0x2_0400_0000, 0x400_0000, 0)]);
        assert_eq!(agx::sgx::covers(&G14G, &t8112), Ok(()));
        let t6000 = sgx_banks((0x2_0400_0000, 0x10_0000), (0x2_04d0_0000, 0x2_0000)).unwrap();
        assert_eq!(
            t6000,
            [
                (0x2_0400_0000, 0x10_0000, 0),
                (0x2_04d0_0000, 0x2_0000, 0xd0_0000)
            ]
        );
        assert_eq!(agx::sgx::covers(&G13X, &t6000), Ok(()));
        // The G14X core masks at 0xe01500 need T6020's 0x16c000-byte bank.
        assert!(agx::sgx::covers(&G14X, &t6000).is_err());
        let t6020 = sgx_banks((0x2_0400_0000, 0x10_0000), (0x2_04d0_0000, 0x16_c000)).unwrap();
        assert_eq!(agx::sgx::covers(&G14X, &t6020), Ok(()));
        assert!(sgx_banks((0x2_0400_0000, 0x10_0000), (0x2_0000_0000, 0x10)).is_err());
        assert!(sgx_banks((0x2_0400_0000, 0x10_0000), (0x2_040f_0000, 0x2_0000)).is_err());
    }

    /// The J473AP SMC subtree: its wrapper and watchdog banks, the nub's
    /// shared-page region and the `pKW4` functions other nodes route
    /// through `smc-pmu`.
    #[test]
    fn smc_placement_reads_its_banks_region_and_function_keys() {
        use crate::machine::adt::encode;
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let cells = |values: &[u32]| {
            values
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let pairs = |values: &[(u64, u64)]| {
            values
                .iter()
                .flat_map(|&(a, b)| [a, b])
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>()
        };
        let function =
            |key: &[u8; 4], value: u32| cells(&[0x91, smc::code(b"pKW4"), smc::code(key), value]);
        let tree = |region_size: u64| {
            let pmu = encode(
                // Hidden: the loader removed its compatible.
                &[
                    ("name", &z("smc-pmu")),
                    ("AAPL,phandle", &cells(&[0x91])),
                    ("event_name-bit0", &z("pwrbtn")),
                    ("event_name-bit13", &z("wifibt")),
                    ("event_name-bit48", &z("rtc")),
                ],
                &[],
            );
            let nub = encode(
                &[
                    ("name", &z("iop-smc-nub")),
                    ("compatible", &z(RTBUDDY)),
                    ("region-base", &0x2_3fe0_0000u64.to_le_bytes()),
                    ("region-size", &region_size.to_le_bytes()),
                    ("quiesced", &[]),
                ],
                &[pmu],
            );
            let smc = encode(
                &[
                    ("name", &z("smc")),
                    ("compatible", &z(ASC)),
                    ("role", &z("SMC")),
                    (
                        "reg",
                        &pairs(&[
                            (0x3e40_0000, 0x6c000),
                            (0x3e05_0000, 0x4000),
                            (0x3e81_0000, 0x14),
                        ]),
                    ),
                    ("interrupts", &cells(&[0x1f4, 0x1f3, 0x1f6, 0x1f5])),
                    ("timers-reg-index", &cells(&[2])),
                ],
                &[nub],
            );
            let hdmi = encode(
                &[
                    ("name", &z("dp2hdmi-gpio")),
                    ("function-reset", &function(b"gP09", 0x100)),
                    ("function-hdmi_pwr_en", &function(b"gP16", 0x8000)),
                ],
                &[],
            );
            let standby = encode(
                &[
                    ("name", &z("pmu-main")),
                    (
                        "function-external_standby",
                        &cells(&[0x91, smc::code(b"keyW"), smc::code(b"MBSE")]),
                    ),
                ],
                &[],
            );
            let io = encode(&[("name", &z("arm-io"))], &[smc, hdmi, standby]);
            let amfm = encode(
                &[
                    ("name", &z("amfm")),
                    ("function-reg_on", &function(b"gP0d", 0x8000)),
                ],
                &[],
            );
            encode(&[("name", &z("device-tree"))], &[io, amfm])
        };
        let bytes = tree(0x10_0000);
        let root = Node::root(&bytes).unwrap();
        let io = root.child("arm-io").unwrap();
        let translate = |offset| Some(0x2_0000_0000 + offset);
        let placed = smc_controller(&root, &io, &translate).unwrap().unwrap();
        assert_eq!(placed.wrapper, (0x2_3e40_0000, 0x6c000));
        assert_eq!(placed.watchdog, Some((0x2_3e81_0000, 0x14)));
        assert_eq!(placed.interrupts, [0x1f4, 0x1f3, 0x1f6, 0x1f5]);
        assert_eq!(placed.region, (0x2_3fe0_0000, 0x10_0000));
        assert!(placed.quiesced);
        assert_eq!(
            placed.wake_bits,
            smc::WakeBits {
                power_button: Some(0),
                rtc: Some(48),
            }
        );
        // Sorted; `keyW` is not a GPIO write.
        assert_eq!(
            placed.gpio_keys,
            [smc::code(b"gP09"), smc::code(b"gP0d"), smc::code(b"gP16")]
        );
        let small = tree(0x1000);
        let root = Node::root(&small).unwrap();
        let io = root.child("arm-io").unwrap();
        assert!(smc_controller(&root, &io, &translate).is_err());
        // The SMC claim owns its nub and the nub's PMU child; the buttons
        // the PMU provides are a modeled compatible.
        let smc_role = |key: &str| (key == "role").then_some(b"SMC\0".as_slice());
        let [nub] = model_children(ASC, smc_role) else {
            panic!("the SMC claim owns one nub");
        };
        assert_eq!(nub.compatible, RTBUDDY);
        assert_eq!(
            nub.children
                .iter()
                .map(|child| child.compatible)
                .collect::<Vec<_>>(),
            [SMC_PMU]
        );
        assert!(models(BUTTONS, |_| None));
        assert!(!models(SMC_PMU, |_| None));
    }

    #[test]
    #[ignore = "requires original 26A434 J314s DT through STELA_TEST_SPMI_DT"]
    fn original_j314s_spmi_parent_qualifies_all_seven_independent_resource_owners() {
        use crate::machine::Devices;
        let data = std::fs::read(std::env::var("STELA_TEST_SPMI_DT").unwrap()).unwrap();
        assert_eq!(
            crate::sha256(&data),
            "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
        );
        let root = Node::root(&data).unwrap();
        let io = root.child("arm-io").unwrap();
        let ranges = io.ranges().unwrap();
        let translate = |offset| {
            ranges
                .iter()
                .find(|(child, _, bytes)| (*child..child + bytes).contains(&offset))
                .map(|(child, parent, _)| parent + (offset - child))
        };
        let controllers = spmi_controllers(&io, &translate, 130).unwrap();
        assert_eq!(controllers.len(), 7);
        assert_eq!(
            controllers
                .iter()
                .flat_map(|c| &c.pmus)
                .filter(|p| p.primary)
                .count(),
            1
        );
        assert_eq!(
            controllers
                .iter()
                .flat_map(|c| &c.pmus)
                .filter(|p| p.rtc.is_some())
                .count(),
            2
        );
        let mut devices = crate::machine::apple::AppleDevices::new();
        let smc = smc_controller(&root, &io, &translate).unwrap().unwrap();
        devices.add_smc(&smc).unwrap();
        let epoch = pmu::RtcEpoch {
            counter: 100,
            ticks: 0,
        };
        for controller in &controllers {
            if controller
                .pmus
                .iter()
                .any(|pmu| pmu.rtc_helper.is_some() || pmu.fault_log.is_some())
            {
                assert!(
                    devices.add_spmi(controller, None).is_err(),
                    "no implicit resource inputs"
                );
            }
            let history = controller
                .pmus
                .iter()
                .filter_map(|pmu| {
                    pmu.fault_log
                        .map(|log| (pmu.sid, vec![0; usize::from(log.bytes)]))
                })
                .collect::<Vec<_>>();
            devices
                .add_spmi_with_resources(controller, None, epoch, &history)
                .unwrap();
        }
        assert_eq!(
            controllers
                .iter()
                .flat_map(|c| &c.pmus)
                .filter(|pmu| pmu.rtc_helper.is_some())
                .count(),
            1
        );
        assert!(
            devices
                .read(0, smc.wrapper.0 + 0x44, 4, epoch.counter - 1)
                .is_err()
        );
        assert_eq!(
            devices.read(0, smc.wrapper.0 + 0x44, 4, epoch.counter),
            Ok(1 << 4)
        );
        let mut bases = Vec::new();
        for controller in controllers {
            assert_eq!(controller.configuration.profile(), spmi::Profile::Gen1);
            assert_eq!(controller.configuration.response_vector(), 192);
            assert_eq!(controller.configuration.queue_bytes(), [256, 256]);
            for (base, bytes) in controller.banks {
                assert_eq!(bytes, 0x100);
                assert!(!bases.contains(&base));
                bases.push(base);
            }
            let (base, bytes) = controller.fault_counters.unwrap();
            assert_eq!(bytes, 0x78);
            assert!(!bases.contains(&base));
            bases.push(base);
        }
        // Both original RTC register banks mount while the single primary
        // service owns the global alarm output and the resolved SMC helper
        // shares its actual oscillator. Epoch/fault history are explicitly
        // created native inputs, not observed physical reset/persistent data.
        // Autonomous sleep/wake and whole-board admission remain separate.
    }

    #[test]
    fn spmi_placement_reads_banks_aic_line_and_pmu_windows() {
        use crate::machine::adt::encode;
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let cells = |values: &[u32]| {
            values
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let pairs = |values: &[(u64, u64)]| {
            values
                .iter()
                .flat_map(|&(a, b)| [a, b])
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>()
        };
        // The J473AP pmu-main and its controller, trimmed.
        let tree = |offset: &[u32]| {
            let pmu = encode(
                &[
                    ("name", &z("pmu-main")),
                    ("compatible", b"pmu,spmi\0pmu,stowe\0"),
                    ("reg", &cells(&[0xe, 3, 0, 4, 0, 0])),
                    ("info-scrpad", &cells(&[0x8000, 0x2800])),
                    ("info-scrpad_socd", &cells(&[0x8b00, 0x1800])),
                    ("info-scrpad_lpm_ctrl", &cells(&[0xa7dc])),
                    ("info-leg_scrpad", &cells(&[0xf700])),
                    ("info-fault_log", &cells(&[0xfa00, 5])),
                    ("info-pm_setting", &cells(&[0xf801])),
                    ("info-rtc", &cells(&[0xf802])),
                    ("info-clock_offset", &cells(offset)),
                    ("info-rtc_alarm_ctrl", &cells(&[0xf800])),
                    ("info-rtc_alarm_ctrl_en_mask", &cells(&[0x40])),
                    ("info-rtc_alarm_monitor_mask", &cells(&[1])),
                    ("is-primary", &cells(&[1])),
                    ("info-rtc_alarm_offset", &cells(&[0xf808])),
                    ("info-rtc_alarm_event", &cells(&[0xf80c])),
                    ("info-rtc_irq_mask_offset", &cells(&[0xf80e])),
                    ("info-rtc_alarm_mask", &cells(&[0x1])),
                ],
                &[],
            );
            // Hidden: the loader removed its compatible.
            let btm = encode(&[("name", &z("btm")), ("reg", &cells(&[0xe]))], &[]);
            let spmi = encode(
                &[
                    ("name", &z("nub-spmi0")),
                    ("compatible", &z(SPMI)),
                    ("gen", &cells(&[2])),
                    ("queue-depth", &cells(&[256, 256])),
                    ("AAPL,phandle", &cells(&[0xae])),
                    (
                        "reg",
                        &pairs(&[(0x3d71_4000, 0x4000), (0x3d70_4000, 0x4000)]),
                    ),
                    ("interrupt-parent", &cells(&[0xae, 0x63, 0xae])),
                    ("interrupts", &cells(&[0x100, 0x180, 0x119, 0x104])),
                ],
                &[pmu, btm],
            );
            encode(&[("name", &z("arm-io"))], &[spmi])
        };
        let translate = |offset| Some(0x2_0000_0000 + offset);
        let bytes = tree(&[0xf900, 6]);
        let io = Node::root(&bytes).unwrap();
        let [controller] = &spmi_controllers(&io, &translate, 0x63).unwrap()[..] else {
            panic!("one controller");
        };
        assert_eq!(
            controller.banks,
            [(0x2_3d71_4000, 0x4000), (0x2_3d70_4000, 0x4000)]
        );
        assert_eq!(controller.irq, 0x180);
        let [pmu] = &controller.pmus[..] else {
            panic!("one visible PMU");
        };
        assert_eq!(pmu.sid, 0xe);
        assert!(pmu.primary);
        assert_eq!(pmu.alarm_monitor, 1);
        assert_eq!(pmu.interrupt, None);
        let window = |base, bytes| pmu::Window { base, bytes };
        assert_eq!(
            pmu.windows,
            [
                window(0x8000, 0x2800),
                window(0xf700, pmu::LEGACY_SCRATCH_BYTES),
                window(0xf801, 1),
            ]
        );
        assert_eq!(pmu.fault_log, Some(window(0xfa00, 5)));
        assert_eq!(pmu.rtc_helper, None);
        let rtc = pmu.rtc.unwrap();
        assert_eq!(
            (rtc.upcount, rtc.clock_offset, rtc.alarm_enable),
            (0xf802, 0xf900, 0x40)
        );
        // J473AP gives no event mask: the driver's default holds.
        assert_eq!((rtc.event_mask, rtc.interrupt_mask), (0x1, 0x1));
        // A clock offset that is not six bytes refuses.
        let bytes = tree(&[0xf900, 4]);
        let io = Node::root(&bytes).unwrap();
        assert!(spmi_controllers(&io, &translate, 0x63).is_err());
    }

    #[test]
    fn a_board_takes_its_chip_and_pes_from_the_device_tree() {
        // J473AP (Mac14,3): cpu0-3 Blizzard E cores, cpu4-7 Avalanche P cores.
        let layout: Vec<(u8, u32)> = (0..8)
            .map(|cpu| {
                (
                    if cpu < 4 { b'E' } else { b'P' },
                    ((cpu / 4) << 8) | (cpu % 4),
                )
            })
            .collect();
        let found = cpus(0x8112, "Apple M2", &layout_of(&layout)).unwrap();
        assert_eq!(
            (found.chip, found.aic),
            (Chip::AppleM2, Some(("aic,2", 0x8000)))
        );
        let identities = found.processors;
        assert_eq!(
            identities[0],
            Identity {
                midr: 0x611f_0320,
                mpidr: 0x8000_0000,
                clock: Some(2_424_000_000),
                caches: Some(
                    Caches::split_unified(
                        cache(128 << 10, 8),
                        cache(64 << 10, 8),
                        cache(4 << 20, 16)
                    )
                    .unwrap()
                ),
            }
        );
        assert_eq!(
            identities[7],
            Identity {
                midr: 0x611f_0330,
                mpidr: 0x8001_0103,
                clock: Some(3_504_000_000),
                caches: Some(
                    Caches::split_unified(
                        cache(192 << 10, 6),
                        cache(128 << 10, 8),
                        cache(16 << 20, 16)
                    )
                    .unwrap()
                ),
            }
        );
        // The level 2's capacity is the cpu node's.
        let mut sizeless = layout_of(&layout);
        sizeless[5].l2_bytes = None;
        assert!(cpus(0x8112, "Apple M2", &sizeless).is_err());
        // J604AP (Mac16,1): six M4 E cores and four P cores.
        let layout = [(b'E', 0), (b'E', 5), (b'P', 0x100), (b'P', 0x103)];
        let found = cpus(0x8132, "Apple M4", &layout_of(&layout)).unwrap();
        assert_eq!((found.chip, found.aic), (Chip::AppleM4, None));
        let identities = found.processors;
        assert_eq!(identities[1].midr, 0x611f_0520);
        assert_eq!(
            identities[3],
            Identity {
                midr: 0x611f_0530,
                mpidr: 0x8001_0103,
                clock: None,
                caches: Some(
                    Caches::split_unified(
                        cache(192 << 10, 6),
                        cache(128 << 10, 8),
                        cache(16 << 20, 16)
                    )
                    .unwrap()
                ),
            }
        );
        // An M2 Pro's AIC2 has its event register at +0xc000.
        assert_eq!(
            cpus(0x6020, "Apple M2 Pro", &layout_of(&layout))
                .unwrap()
                .aic,
            Some(("aic,2", 0xc000))
        );
        // The M3's AICv3 has it at +0x40000.
        assert_eq!(
            cpus(0x8122, "Apple M3", &layout_of(&layout)).unwrap().aic,
            Some(("aic,3", 0x40000))
        );
        assert_eq!(dram_base(0x8112), Ok(0x8_0000_0000));
        assert_eq!(dram_base(0x6021), Ok(0x100_0000_0000));
        assert!(dram_base(0x8132).is_err());
        // Every ApChipID appears once.
        for (index, soc) in SOCS.iter().enumerate() {
            assert!(
                SOCS[index + 1..]
                    .iter()
                    .all(|other| other.chip_id != soc.chip_id)
            );
        }
    }

    #[test]
    fn a_board_without_evidence_refuses() {
        let one = layout_of(&[(b'E', 0)]);
        // M2 Ultra: two M2 Max dies, the second die's P cores at Aff1 9.
        let ultra = cpus(
            0x6022,
            "Apple M2 Ultra",
            &layout_of(&[(b'E', 0x800), (b'P', 0x903)]),
        )
        .unwrap();
        assert_eq!(ultra.processors[0].mpidr, 0x8000_0800);
        assert_eq!(ultra.processors[1].mpidr, 0x8001_0903);
        assert_eq!(ultra.processors[1].midr, 0x611f_0390);
        // A SoC without a row.
        assert_eq!(
            cpus(0x6050, "Apple M5 Max", &one),
            Err("ApChipID 0x6050 (Apple M5 Max) has no public MIDR part".into())
        );
        assert!(cpus(0x8112, "Apple M2 Pro", &one).is_err());
        assert!(cpus(0x8112, "Apple M2", &[]).is_err());
        // The M6's M cores and a second die's affinity.
        assert_eq!(
            cpus(0x8152, "Apple M6", &layout_of(&[(b'M', 0)])),
            Err("Apple M6 cluster type M has no public MIDR part".into())
        );
        assert!(cpus(0x6031, "Apple M3 Max", &layout_of(&[(b'P', 0x1000)])).is_err());
    }

    /// A J473AP-shaped DeviceTree: two PEs, `/arm-io` child 0 at PA
    /// 0x2_0000_0000, and the UART, watchdog and AIC as `compatibles` names.
    fn tree(chip_id: u32, soc: &str, compatibles: [&str; 3]) -> Vec<u8> {
        tree_with(chip_id, soc, compatibles, &[])
    }
    /// [`tree`] with more `/arm-io/aic` properties.
    fn tree_with(
        chip_id: u32,
        soc: &str,
        compatibles: [&str; 3],
        aic_properties: &[(&str, u32)],
    ) -> Vec<u8> {
        tree_with_io(chip_id, soc, compatibles, aic_properties, &[])
    }
    /// [`tree_with`] with more `/arm-io` children.
    fn tree_with_io(
        chip_id: u32,
        soc: &str,
        compatibles: [&str; 3],
        aic_properties: &[(&str, u32)],
        io_children: &[Vec<u8>],
    ) -> Vec<u8> {
        use crate::machine::adt::encode;
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let u32s = |cells: &[u32]| {
            cells
                .iter()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let u64s = |cells: &[u64]| {
            cells
                .iter()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>()
        };
        // The J473AP's blocks: cpu0's and cpu4's `cpu-impl-reg`, and their
        // clusters' `cpm-impl-reg`.
        let cpu = |name: &str, kind: &[u8], reg: u32| {
            let cluster = 0x100_0000 * u64::from(reg >> 8);
            encode(
                &[
                    ("name", &z(name)),
                    ("cluster-type", kind),
                    ("reg", &u32s(&[reg])),
                    ("l2-cache-size", &u32s(&[4 << 20 << (2 * (reg >> 8))])),
                    ("cpu-impl-reg", &u64s(&[0x2_1005_0000 + cluster, 0x9010])),
                    ("coresight-reg", &u64s(&[0x2_1001_0000 + cluster, 0x300c8])),
                    ("cpm-impl-reg", &u64s(&[0x2_10e4_0000 + cluster, 0x9010])),
                ],
                &[],
            )
        };
        let device = |name: &str, compatible: &str, reg: u64, irq: u32| {
            encode(
                &[
                    ("name", &z(name)),
                    ("compatible", &z(compatible)),
                    ("reg", &u64s(&[reg, 0x4000])),
                    ("interrupt-parent", &u32s(&[0x63])),
                    ("interrupts", &u32s(&[irq])),
                ],
                &[],
            )
        };
        let (name, compatible) = (z("aic"), z(compatibles[2]));
        let (reg, phandle) = (u64s(&[0x3b0c_0000, 0x2_0000]), u32s(&[0x63]));
        let values: Vec<_> = aic_properties
            .iter()
            .map(|(_, value)| u32s(&[*value]))
            .collect();
        let properties: Vec<(&str, &[u8])> = [
            ("name", name.as_slice()),
            ("compatible", &compatible),
            ("reg", &reg),
            ("AAPL,phandle", &phandle),
        ]
        .into_iter()
        .chain(
            aic_properties
                .iter()
                .zip(&values)
                .map(|((name, _), value)| (*name, value.as_slice())),
        )
        .collect();
        let aic = encode(&properties, &[]);
        let io = encode(
            &[
                ("name", &z("arm-io")),
                (
                    "ranges",
                    &u64s(&[
                        0,
                        0x2_0000_0000,
                        0x1_0000_0000,
                        0x3_8000_0000,
                        0x3_8000_0000,
                        0x1_0000_0000,
                    ]),
                ),
            ],
            &[
                vec![
                    device("uart0", compatibles[0], 0x3520_0000, 739),
                    device("wdt", compatibles[1], 0x3d2b_0000, 379),
                    aic,
                ],
                io_children.to_vec(),
            ]
            .concat(),
        );
        encode(
            &[("name", &z("device-tree"))],
            &[
                encode(
                    &[("name", &z("chosen")), ("chip-id", &u32s(&[chip_id]))],
                    &[],
                ),
                encode(
                    &[("name", &z("product")), ("product-soc-name", &z(soc))],
                    &[],
                ),
                encode(
                    &[("name", &z("cpus"))],
                    &[cpu("cpu0", b"E", 0), cpu("cpu1", b"P", 0x100)],
                ),
                io,
            ],
        )
    }

    #[test]
    fn a_board_states_its_dram_base_or_takes_its_socs() {
        use crate::machine::adt::encode;
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let with_base = |base: Option<&[u8]>| {
            let mcc = base.map(|base| encode(&[("name", &z("mcc")), ("dram-base", base)], &[]));
            encode(
                &[("name", &z("device-tree"))],
                &[encode(&[("name", &z("arm-io"))], mcc.as_slice())],
            )
        };
        let m3 = 0x8122;
        let stated = 0x100_0000_0000_u64.to_le_bytes();
        // The M3's base is in its DeviceTree only.
        assert_eq!(
            board_dram_base(&with_base(Some(&stated)), m3),
            Ok(0x100_0000_0000)
        );
        assert!(board_dram_base(&with_base(None), m3).is_err());
        // The M2's board states none and takes the public base; a stated base
        // must agree with it.
        assert_eq!(board_dram_base(&with_base(None), 0x8112), Ok(0x8_0000_0000));
        assert!(board_dram_base(&with_base(Some(&stated)), 0x8112).is_err());
        assert!(board_dram_base(&with_base(Some(&[0; 4])), m3).is_err());
    }

    #[test]
    fn a_device_tree_places_the_board_or_says_why_it_cannot() {
        const MODELED: [&str; 3] = ["uart-1,samsung", "wdt,s5l8960x", "aic,2"];
        let found = board(&tree(0x8112, "Apple M2", MODELED)).unwrap();
        assert_eq!(found.cpus.chip, Chip::AppleM2);
        assert_eq!(found.cpus.processors[1].mpidr, 0x8001_0100);
        assert_eq!(
            found.uart,
            Device {
                physical: 0x2_3520_0000,
                bytes: 0x4000,
                irq: 739
            }
        );
        assert_eq!(found.watchdog.irq, 379);
        assert_eq!(
            found.coresight,
            vec![
                CoreSight {
                    cpu: 0,
                    physical: 0x2_1001_0000,
                    bytes: 0x300c8
                },
                CoreSight {
                    cpu: 1,
                    physical: 0x2_1101_0000,
                    bytes: 0x300c8
                },
            ]
        );
        // Each PE's cpu-impl-reg and each cluster's cpm-impl-reg, once.
        let block = |name, physical, control, cpu| LockdownBlock {
            name,
            physical,
            bytes: 0x9010,
            control,
            cpu,
        };
        assert_eq!(
            found.lockdown,
            [
                block("cpu-impl-reg", 0x2_1005_0000, 0x5000, Some(0)),
                block("cpm-impl-reg", 0x2_10e4_0000, 0x9000, None),
                block("cpu-impl-reg", 0x2_1105_0000, 0x5000, Some(1)),
                block("cpm-impl-reg", 0x2_11e4_0000, 0x9000, None),
            ]
        );
        // Each PE's sampler counters, in its cpu-impl-reg.
        let layout = core_counters::layout(0x8112).unwrap();
        assert_eq!(
            found.counters,
            [
                CounterBlock {
                    cpu: 0,
                    physical: 0x2_1005_0000,
                    layout
                },
                CounterBlock {
                    cpu: 1,
                    physical: 0x2_1105_0000,
                    layout
                },
            ]
        );
        // The UART's input 739 is the highest that names the AIC.
        assert_eq!(
            found.aic,
            InterruptController {
                physical: 0x2_3b0c_0000,
                inputs: 740,
                layout: AicLayout::aic2(0x8000, 0)
            }
        );
        // The M1's AICv1 has its event register in its core block.
        let m1 = board(&tree(
            0x8103,
            "Apple M1",
            ["uart-1,samsung", "wdt,s5l8960x", "aic,1"],
        ))
        .unwrap();
        assert_eq!(
            (m1.cpus.chip, m1.aic.layout),
            (Chip::AppleM1, AicLayout::V1)
        );
        // The M1's SPTM locks the same blocks at the same offsets
        // (isa/apple-soc-facts.json).
        assert_eq!(m1.lockdown, found.lockdown);
        assert_eq!(
            board(&tree(0x8103, "Apple M1", MODELED)),
            Err("/arm-io/aic is not aic,1, the modeled device".into())
        );
        assert_eq!(
            board(&tree(
                0x8112,
                "Apple M2",
                ["uart-2", "wdt,s5l8960x", "aic,2"]
            )),
            Err("/arm-io/uart0 is not uart-1,samsung, the modeled device".into())
        );
        assert_eq!(
            board(&tree(0x8122, "Apple M3", MODELED)),
            Err("/arm-io/aic is not aic,3, the modeled device".into())
        );
        assert!(board(&[0; 4]).is_err());
    }

    /// J473AP's `dart-sio` and the AES engine behind its `mapper-aes`.
    #[test]
    fn a_board_places_its_darts_and_the_aes_engine_behind_one() {
        use crate::machine::adt::encode;
        const MODELED: [&str; 3] = ["uart-1,samsung", "wdt,s5l8960x", "aic,2"];
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let u32s = |cells: &[u32]| {
            cells
                .iter()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let u64s = |cells: &[u64]| {
            cells
                .iter()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let mapper = |name: &str, phandle: u32, stream: u32| {
            encode(
                &[
                    ("name", &z(name)),
                    ("compatible", &z(IOMMU_MAPPER)),
                    ("AAPL,phandle", &u32s(&[phandle])),
                    ("reg", &u32s(&[stream])),
                ],
                &[],
            )
        };
        let instance = [b"TRAD".as_slice(), &[0; 4], b"DART", &[0; 4]].concat();
        let dart = |instance: &[u8], reg: &[u64]| {
            encode(
                &[
                    ("name", &z("dart-sio")),
                    ("compatible", &z(DART)),
                    ("reg", &u64s(reg)),
                    ("instance", instance),
                    ("sid-count", &u32s(&[16])),
                    ("interrupts", &u32s(&[0x301])),
                ],
                &[mapper("mapper-sio", 0x89, 0), mapper("mapper-aes", 0x8a, 1)],
            )
        };
        let aes = |parent: u32| {
            encode(
                &[
                    ("name", &z("aes")),
                    ("compatible", &z(AES)),
                    ("reg", &u64s(&[0x3500_c000, 0x4000, 0x3d2d_c000, 0x8000])),
                    ("interrupts", &u32s(&[0x2f7])),
                    ("iommu-parent", &u32s(&[parent])),
                    ("aes-version", &u32s(&[3])),
                ],
                &[],
            )
        };
        let sio = dart(&instance, &[0x3500_4000, 0x4000]);
        let found = board(&tree_with_io(
            0x8112,
            "Apple M2",
            MODELED,
            &[],
            &[sio.clone(), aes(0x8a)],
        ))
        .unwrap();
        assert_eq!(
            found.darts,
            [Iommu {
                profile: dart::Profile::T8110,
                instances: vec![DartInstance {
                    physical: 0x2_3500_4000,
                    bytes: 0x4000,
                    number: 0,
                    reg_index: 0,
                    owner: *b"DART\0\0\0\0"
                }],
                sids: vec![],
                remap: vec![],
                vm_base: 0,
                streams: 16,
                irq: 0x301,
                mappers: vec![(0x89, 0), (0x8a, 1)],
                apf: None,
                clock_gates: Vec::new(),
                power_gates: Vec::new(),
                retention: false,
                smmu: None,
            }]
        );
        assert_eq!(
            found.aes,
            Some(AesEngine {
                phandle: None,
                mapper: 0x8a,
                mapper_context: 1,
                instance: 0,
                ranges: [(0x2_3500_c000, 0x4000), (0x2_3d2d_c000, 0x8000)],
                version: 3,
                irq: 0x2f7,
                iommu: 0,
                stream: 1,
            })
        );
        assert_eq!(
            board(&tree_with_io(
                0x8112,
                "Apple M2",
                MODELED,
                &[],
                &[sio, aes(0x99)]
            )),
            Err("/arm-io/aes iommu-parent 0x99 is no modeled DART's mapper".into())
        );
        let bytes = tree_with_io(
            0x8112,
            "Apple M2",
            MODELED,
            &[],
            &[dart(&instance, &[0x35004000, 0x4000]), aes(0x8a)],
        );
        let io = Node::root(&bytes).unwrap().child("arm-io").unwrap();
        let mut routes = found.darts.clone();
        routes[0].profile = dart::Profile::T6000;
        routes[0].remap = vec![(3, 1)];
        routes[0].sids = vec![0, 1, 15];
        let routed = aes_engine(&io, &Some, &routes).unwrap().unwrap();
        assert_eq!(
            (
                routed.instance,
                routed.mapper,
                routed.mapper_context,
                routed.stream
            ),
            (0, 0x8a, 1, 3)
        );
        let good = routes[0].clone();
        routes[0].mappers.push((0x8a, 2));
        assert!(
            aes_engine(&io, &Some, &routes)
                .unwrap_err()
                .contains("ambiguous")
        );
        routes[0] = good.clone();
        routes.push(good.clone());
        assert!(
            aes_engine(&io, &Some, &routes)
                .unwrap_err()
                .contains("ambiguous")
        );
        routes.pop();
        routes[0] = good.clone();
        routes[0].sids = vec![0, 15];
        assert!(
            aes_engine(&io, &Some, &routes)
                .unwrap_err()
                .contains("SID set")
        );
        routes[0] = good.clone();
        routes[0].streams = 1;
        assert!(
            aes_engine(&io, &Some, &routes)
                .unwrap_err()
                .contains("outside the native profile")
        );
        routes[0] = good.clone();
        routes[0].instances.push(good.instances[0].clone());
        assert!(
            aes_engine(&io, &Some, &routes)
                .unwrap_err()
                .contains("multi-instance")
        );
        routes[0].instances.clear();
        assert!(aes_engine(&io, &Some, &routes).is_err());
        // An APF beside the DART needs its slice count.
        let dapf = [instance.as_slice(), b"FPAD", &[0; 4], b"DART", &[0; 4]].concat();
        let pmp = dart(&dapf, &[0x3b30_0000, 0x4000, 0x3b30_4000, 0x4000]);
        assert_eq!(
            board(&tree_with_io(0x8112, "Apple M2", MODELED, &[], &[pmp])),
            Err("/arm-io/dart-sio has no n-apfs-instance-0 slice count".into())
        );
        let three = dart(
            &[dapf.as_slice(), &dapf[16..]].concat(),
            &[
                0x3b30_0000,
                0x4000,
                0x3b30_4000,
                0x4000,
                0x3b30_8000,
                0x4000,
            ],
        );
        assert_eq!(
            board(&tree_with_io(0x8112, "Apple M2", MODELED, &[], &[three])),
            Err(
                "/arm-io/dart-sio has unsupported instance kinds, numbering or APF topology".into()
            )
        );
    }

    #[test]
    fn typec_placement_distinguishes_i2c_addresses_from_mmio_and_preserves_phy_aliases() {
        use crate::machine::adt::encode;
        let c = |v: &[u32]| v.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>();
        let r = |v: &[u64]| v.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>();
        let hpm = |name: &[u8], address: u32, personality: Option<&[u8]>| {
            let mut properties = vec![("name", name), ("compatible", b"usbc,cd3217\0".as_slice())];
            let address = c(&[address]);
            let (provider, port) = (c(&[0x9b]), c(&[1]));
            properties.extend([
                ("hpm-iic-addr", address.as_slice()),
                ("iicProvider", provider.as_slice()),
                ("port-number", port.as_slice()),
            ]);
            properties.extend(personality.map(|p| ("usbc-fw-personality", p)));
            encode(&properties, &[])
        };
        let manager = encode(
            &[
                ("name", b"hpmBusManager\0"),
                ("compatible", b"usbc,manager\0"),
                ("reg", &c(&[0x6b, 2500, 0, 0])),
                ("AAPL,phandle", &c(&[0x9b])),
                ("interrupt-parent", &c(&[0x6a])),
                ("interrupts", &c(&[8, 1])),
            ],
            &[
                hpm(b"hpm0\0", 0x38, Some(b"HPM,47\0")),
                hpm(b"hpm1\0", 0x3f, None),
            ],
        );
        let gpio = GpioBank {
            profile: gpio::Profile::T8101,
            no_restore_pins: Vec::new(),
            physical: 0x23c100000,
            bytes: 0x100000,
            pins: 213,
            groups: 7,
            phandle: 0x6a,
            lines: vec![199],
            i2c_lines: vec![],
        };
        let i2c = encode(
            &[
                ("name", b"i2c0\0"),
                ("compatible", b"i2c,t8101\0"),
                ("reg", &r(&[0x35010000, 0x4000])),
                ("interrupt-parent", &c(&[0x63])),
                ("interrupts", &c(&[761])),
            ],
            &[manager],
        );
        let mut views = vec![(0x383000000, 0x4000); 29];
        views[0] = (0x382a90000, 0x4000);
        views[1] = (0x382800000, 0x4000);
        views[2] = (0x383020000, 0x4000);
        views[4] = (0x383002000, 0x4000);
        let phy_views = |compatible: &[u8], views: &[(u64, u64)]| {
            encode(
                &[
                    ("name", b"atc-phy0\0"),
                    ("compatible", compatible),
                    ("AAPL,phandle", &c(&[0xa2])),
                    ("port-number", &c(&[1])),
                    (
                        "reg",
                        &r(&views.iter().flat_map(|&(a, n)| [a, n]).collect::<Vec<_>>()),
                    ),
                ],
                &[],
            )
        };
        let phy = |compatible: &[u8]| phy_views(compatible, &views);
        let usb = encode(
            &[
                ("name", b"usb-drd0\0"),
                ("device_type", b"usb-drd\0"),
                ("atc-phy-parent", &c(&[0xa2])),
                (
                    "reg",
                    &r(&[
                        0x382280000,
                        0x11800,
                        0x382200000,
                        0x4000,
                        0x38228c000,
                        0x5800,
                        0x382a84000,
                        0x4000,
                        0x382800000,
                        0x4000,
                    ]),
                ),
            ],
            &[],
        );
        // ACIO also references the PHY, but is not its USB pipehandler.
        let acio = encode(
            &[
                ("name", b"acio0\0"),
                ("device_type", b"acio\0"),
                ("atc-phy-parent", &c(&[0xa2])),
                ("reg", &r(&[0x381f00000, 0x100000])),
            ],
            &[],
        );
        let io = encode(
            &[("name", b"arm-io\0")],
            &[i2c.clone(), phy(b"atc-phy,t8112\0"), usb.clone(), acio],
        );
        let translate = |a| Some(if a < 0x100000000 { a + 0x200000000 } else { a });
        let place =
            |io: &[u8], aic, gpio| typec_devices(&Node::root(io).unwrap(), &translate, aic, gpio);
        let (buses, phys) = place(&io, 0x63, Some(&gpio)).unwrap();
        assert_eq!(buses[0].device.physical, 0x235010000);
        assert_eq!(buses[0].device.irq, 761);
        // Both dies share the manager's GPIO line and the flash-updated
        // die's firmware.
        let hpm = |address, port| I2cAddress {
            address,
            compatible: HPM.into(),
            interrupt: Some(8),
            firmware: Some("HPM,47".into()),
            port,
        };
        assert_eq!(
            buses[0].targets,
            [
                I2cAddress {
                    address: 0x6b,
                    compatible: HPM_MANAGER.into(),
                    interrupt: Some(8),
                    firmware: None,
                    port: None,
                },
                hpm(0x38, Some(1)),
                hpm(0x3f, Some(1)),
            ]
        );
        // A board with these buses carries the one image both dies run.
        let mut with_buses = board(&tree(
            0x8112,
            "Apple M2",
            ["uart-1,samsung", "wdt,s5l8960x", "aic,2"],
        ))
        .unwrap();
        assert!(with_buses.firmware_files().is_empty());
        with_buses.i2cs = buses.clone();
        assert_eq!(with_buses.firmware_files(), ["USB-C_HPM,47.bin"]);
        // The manager's line must be a visible AP GPIO pin.
        assert!(place(&io, 0x63, None).is_err());
        assert_eq!(phys[0].usb2, (0x382a90000, 0x4000));
        assert_eq!(phys[0].core, (0x383000000, atc_phy::CORE_BYTES));
        assert_eq!(phys[0].pipe, Some((0x382a84000, 0x4000)));
        assert_eq!(phys[0].events, (0x382800000, 0x4000));
        assert_eq!(phys[0].views, views);
        assert!(place(&io, 0x99, Some(&gpio)).is_err());
        assert!(typec_devices(&Node::root(&io).unwrap(), &|_| None, 0x63, Some(&gpio)).is_err());
        for compatible in [
            I2C,
            HPM_MANAGER,
            HPM,
            ATC_PHY,
            "atc-phy,t6020",
            "atc-phy,t8103",
        ] {
            assert!(models(compatible, |_| None));
        }
        // The T6020 layout has the 28 views the T8112's starts with; its
        // first compatible, not the T8112 one it also lists, selects it.
        let t6020 = |views: &[(u64, u64)]| {
            encode(
                &[("name", b"arm-io\0")],
                &[
                    i2c.clone(),
                    phy_views(b"atc-phy,t6020\0atc-phy,t8112\0", views),
                    usb.clone(),
                ],
            )
        };
        let (_, phys) = place(&t6020(&views[..ATC_PHY_BASE_VIEWS]), 0x63, Some(&gpio)).unwrap();
        assert_eq!(phys[0].core, (0x383000000, atc_phy::CORE_BYTES));
        assert_eq!(phys[0].events, (0x382800000, 0x4000));
        assert!(place(&t6020(&views), 0x63, Some(&gpio)).is_err());
        // A PHY no controller names keeps its event block, without a
        // pipehandler.
        let alone = encode(
            &[("name", b"arm-io\0")],
            &[i2c.clone(), phy(b"atc-phy,t8112\0")],
        );
        let (_, phys) = place(&alone, 0x63, Some(&gpio)).unwrap();
        assert_eq!(
            (phys[0].pipe, phys[0].events),
            (None, (0x382800000, 0x4000))
        );
        // The retimer's register protocol is undetermined: hidden, not refused.
        assert!(!models(RETIMER, |_| None));
        // Hidden PHYs are not parsed or mapped merely because reg survives.
        let io = encode(&[("name", b"arm-io\0")], &[i2c, phy(b"hidden\0"), usb]);
        assert!(place(&io, 0x63, Some(&gpio)).unwrap().1.is_empty());
    }

    #[test]
    fn multiple_darts_preserve_numbered_windows_sids_and_remap_without_guessing_dma_routing() {
        use crate::machine::adt::encode;
        let cells = |values: &[u32]| {
            values
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let pairs = |values: &[u64]| {
            values
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let descriptors = [
            b"TRAD".as_slice(),
            &0u32.to_le_bytes(),
            b"DARTLLT\0",
            b"TRAD",
            &1u32.to_le_bytes(),
            b"DARTBLK\0",
        ]
        .concat();
        let reg = pairs(&[0x382f00000, 0x4000, 0x382f80000, 0x4000]);
        let build = |instance: &[u8], regs: &[u8], sids: &[u32], remap: &[u8]| {
            encode(
                &[
                    ("name", b"dart-usb0\0"),
                    ("compatible", b"dart,t8110\0"),
                    ("reg", regs),
                    ("instance", instance),
                    ("sid-count", &cells(&[16])),
                    ("interrupts", &cells(&[1035])),
                    ("sid", &cells(sids)),
                    ("remap", remap),
                ],
                &[encode(
                    &[
                        ("name", b"mapper-usb0\0"),
                        ("compatible", b"iommu-mapper\0"),
                        ("reg", &cells(&[1])),
                        ("AAPL,phandle", &cells(&[0xa4])),
                    ],
                    &[],
                )],
            )
        };
        let bytes = build(&descriptors, &reg, &[1, 14], &[0, 1, 0, 0]);
        let found = iommu(&Node::root(&bytes).unwrap(), &|a| Some(a)).unwrap();
        assert_eq!(
            found.instances,
            vec![
                DartInstance {
                    physical: 0x382f00000,
                    bytes: 0x4000,
                    number: 0,
                    reg_index: 0,
                    owner: *b"DARTLLT\0"
                },
                DartInstance {
                    physical: 0x382f80000,
                    bytes: 0x4000,
                    number: 1,
                    reg_index: 1,
                    owner: *b"DARTBLK\0"
                },
            ]
        );
        assert_eq!(found.mappers, [(0xa4, 1)]);
        assert_eq!(found.sids, [1, 14]);
        assert_eq!(found.remap, [(0, 1)]);
        for bad in [
            build(&descriptors[..7], &reg, &[1, 14], &[0, 1, 0, 0]),
            build(&descriptors[..31], &reg, &[1, 14], &[0, 1, 0, 0]),
            build(&descriptors, &reg, &[1, 16], &[0, 1, 0, 0]),
            build(&descriptors, &reg, &[1, 1], &[0, 1, 0, 0]),
            build(&descriptors, &reg, &[1, 14], &[0, 1, 1, 2]),
            build(&descriptors, &reg, &[1, 14], &[0, 16, 0, 0]),
            build(&descriptors, &reg, &[1, 14], &[0, 1]),
            build(
                &descriptors,
                &pairs(&[0x382f00000, 0x4000, 0x382f00000, 0x4000]),
                &[1, 14],
                &[0, 1, 0, 0],
            ),
        ] {
            assert!(iommu(&Node::root(&bad).unwrap(), &|a| Some(a)).is_err());
        }
        let mut bad = descriptors.clone();
        bad[20..24].copy_from_slice(&0u32.to_le_bytes());
        let bytes = build(&bad, &reg, &[1, 14], &[0, 1, 0, 0]);
        assert!(iommu(&Node::root(&bytes).unwrap(), &|a| Some(a)).is_err());
        assert!(
            iommu(
                &Node::root(&build(&descriptors, &reg, &[1, 14], &[0, 1, 0, 0])).unwrap(),
                &|_| None
            )
            .is_err()
        );
    }

    /// J473AP ANS gate ancestry and virtual clock IDs, decoded from
    /// ps-regs/devices. Virtual clocks have no hardware power-state word.
    #[test]
    fn ans_power_gates_are_placed_and_virtual_clocks_do_not_invent_registers() {
        use crate::machine::adt::encode;
        let words = |v: &[u32]| v.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>();
        let pairs = |v: &[u64]| v.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>();
        let mut devices = Vec::new();
        for (id, flags, index, block) in [
            (37u16, 0x29u32, 21, 6),
            (89, 1, 9, 8),
            (120, 0x21, 5, 9),
            (125, 0x21, 10, 9),
            (332, 0x10, 0, 0),
            (333, 0x10, 0, 0),
            (334, 0x30, 0, 0),
        ] {
            let mut entry = [0; PMGR_DEVICE];
            entry[..4].copy_from_slice(&flags.to_le_bytes());
            entry[10] = index;
            entry[11] = block;
            entry[26..28].copy_from_slice(&id.to_le_bytes());
            devices.extend(entry);
        }
        let mut blocks = [0; 30];
        for (block, offset) in [(6, 0x100), (8, 0x300), (9, 0x400)] {
            blocks[block * 3 + 1] = offset;
        }
        let pmgr = encode(
            &[
                ("name", b"pmgr"),
                ("compatible", PMGR.as_bytes()),
                ("reg", &pairs(&[0x3b70_0000, 0xcc000])),
                ("ps-regs", &words(&blocks)),
                ("devices", &devices),
            ],
            &[],
        );
        let bytes = encode(&[("name", b"arm-io")], &[pmgr]);
        let found = power_states(
            &Node::root(&bytes).unwrap(),
            &|a| Some(a + 0x2_0000_0000),
            0x8112,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            found.registers,
            [0x2_3b70_01a8, 0x2_3b70_0348, 0x2_3b70_0428, 0x2_3b70_0450]
        );
    }

    /// CPU devices in a block at the PMGR's first range and a device in a
    /// block at its second, with a virtual device that has no register.
    #[test]
    fn a_pmgr_places_each_devices_power_state_register() {
        use crate::machine::adt::encode;
        const MODELED: [&str; 3] = ["uart-1,samsung", "wdt,s5l8960x", "aic,2"];
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let u32s = |cells: &[u32]| {
            cells
                .iter()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let u64s = |cells: &[u64]| {
            cells
                .iter()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let device = |flags: u32, index: u8, block: u8, name: &str| {
            let mut entry = [0u8; PMGR_DEVICE];
            entry[..4].copy_from_slice(&flags.to_le_bytes());
            (entry[10], entry[11]) = (index, block);
            entry[26..28].copy_from_slice(&(u16::from(index) + 1).to_le_bytes());
            if flags & PMGR_VIRTUAL != 0 {
                entry[4..6].copy_from_slice(&1u16.to_le_bytes());
            }
            entry[32..32 + name.len()].copy_from_slice(name.as_bytes());
            entry
        };
        let devices = [
            device(0x2_0000, 0, 1, "ECPU0"),
            device(0x2_0000, 3, 1, "ECPU3"),
            device(PMGR_VIRTUAL, 7, 0, "VIRT"),
            device(0, 2, 0, "SBR"),
        ]
        .concat();
        // J473AP's: the power-state blocks, each cluster's register window
        // (5, 14) and the range its performance-state table lies in (8,
        // 17), and the eFuses (36).
        let mut reg = [[0x3b70_0000, 0xcc000]; 37];
        reg[1] = [0x3d28_0000, 0x7c000];
        reg[4] = [0x3d00_4000, 0x1000];
        reg[5] = [0x10e2_0000, 0x2000];
        reg[7] = [0x10e4_0000, 0x9000];
        reg[10] = [0x1005_0000, 0x10000];
        reg[8] = [0x10e5_0000, 0xe8_1000];
        reg[14] = [0x11e2_0000, 0x2000];
        reg[16] = [0x11e4_0000, 0xb000];
        reg[19] = [0x1105_0000, 0x10000];
        reg[17] = [0x11e5_0000, 0xe8_1000];
        reg[29] = [0x3b20_8000, 0x8000];
        reg[30] = [0x3b70_0000, 0x20000];
        reg[31] = [0x3b72_8000, 0x1000];
        reg[32] = [0x3b72_4000, 0x1000];
        reg[34] = [0x3b78_0000, 0x4000];
        reg[35] = [0x3b76_0000, 0x4000];
        reg[36] = [0x3d2c_8000, 0x4000];
        let reg = reg.concat();
        let energy_record = |address: u64| {
            let mut record = [0u8; 40];
            record[..8].copy_from_slice(&address.to_le_bytes());
            record[16..24].copy_from_slice(&[0, 0, 1, 0, 0, 1, 0, 64]);
            record
        };
        let energy = [
            energy_record(0x2_10e4_8000),
            energy_record(0x2_1005_9000),
            energy_record(0x2_11e4_8000),
            energy_record(0x2_1105_9000),
        ]
        .concat();
        let mut perf_group = [0u8; 16];
        perf_group[..4].copy_from_slice(&1u32.to_le_bytes());
        perf_group[4..8].copy_from_slice(&0x34000u32.to_le_bytes());
        perf_group[8..10].copy_from_slice(&256u16.to_le_bytes());
        perf_group[12] = 3;
        let mut clock = [0u8; 24];
        clock[..3].copy_from_slice(&[24, 0, 1]);
        let pmgr_with = |reg: &[u64]| {
            encode(
                &[
                    ("name", &z("pmgr")),
                    ("compatible", &z(PMGR)),
                    ("reg", &u64s(reg)),
                    ("ps-regs", &u32s(&[1, 0x4000, 0x3ff, 0, 0, 0x3ff])),
                    ("devices", &devices),
                    ("hw-dpe-reg", &energy),
                    ("perf-regs", &perf_group),
                    ("clocks", &clock),
                ],
                &[],
            )
        };
        // A cluster window the PMGR does not place, or an eFuse block of
        // another size, refuses.
        for (index, entry) in [(10, [0x10e2_0000, 0x1000]), (72, [0x3d2c_8000, 0x1000])] {
            let mut other = reg.clone();
            other[index..index + 2].copy_from_slice(&entry);
            let tree = tree_with_io(0x8112, "Apple M2", MODELED, &[], &[pmgr_with(&other)]);
            assert!(board(&tree).is_err());
        }
        for invalid in [
            energy[..39].to_vec(),
            [energy.clone(), energy[..40].to_vec()].concat(),
            {
                let mut unsupported = energy.clone();
                unsupported[20] = 1;
                unsupported
            },
            {
                let mut unsupported = energy.clone();
                unsupported[23] = 32;
                unsupported
            },
            {
                let mut outside = energy.clone();
                outside[..8].copy_from_slice(&0x4_10e4_8000u64.to_le_bytes());
                outside
            },
        ] {
            let pmgr = encode(
                &[
                    ("name", &z("pmgr")),
                    ("compatible", &z(PMGR)),
                    ("reg", &u64s(&reg)),
                    ("hw-dpe-reg", &invalid),
                ],
                &[],
            );
            assert!(board(&tree_with_io(0x8112, "Apple M2", MODELED, &[], &[pmgr])).is_err());
        }
        let pmgr = encode(
            &[
                ("name", &z("pmgr")),
                ("compatible", &z(PMGR)),
                ("reg", &u64s(&reg)),
                ("ps-regs", &u32s(&[1, 0x4000, 0x3ff, 0, 0, 0x3ff])),
                ("devices", &devices),
                ("hw-dpe-reg", &energy),
                ("perf-regs", &perf_group),
                ("clocks", &clock),
            ],
            &[],
        );
        let found = board(&tree_with_io(0x8112, "Apple M2", MODELED, &[], &[pmgr])).unwrap();
        assert_eq!(
            found.energy,
            vec![
                EnergyBank {
                    physical: 0x2_10e4_8000,
                    cpm: true
                },
                EnergyBank {
                    physical: 0x2_1005_9000,
                    cpm: false
                },
                EnergyBank {
                    physical: 0x2_11e4_8000,
                    cpm: true
                },
                EnergyBank {
                    physical: 0x2_1105_9000,
                    cpm: false
                },
            ]
        );
        assert_eq!(
            found.performance,
            vec![PerfBank {
                physical: 0x2_3d2b_4000,
                selectors: vec![24]
            }]
        );
        assert_eq!(found.wake_masks.as_ref().unwrap().physical, 0x2_3d00_4008);
        assert_eq!(found.clusters, T8112_CLUSTERS.to_vec());
        assert_eq!(found.aon_fuses, Some((0x2_3d2c_8000, 0x4000)));
        let states = found.power_states.as_ref().unwrap();
        assert_eq!(
            states.blocks,
            vec![(0x2_3d28_4000, 0x14), (0x2_3b70_0000, 0x1c)]
        );
        assert_eq!(
            states.registers,
            vec![0x2_3b70_0000, 0x2_3b70_0018, 0x2_3d28_4010]
        );
        assert_eq!(
            states
                .domains
                .iter()
                .map(|domain| (domain.id.device, domain.address))
                .collect::<Vec<_>>(),
            [
                (1, Some(0x2_3b70_0000)),
                (4, Some(0x2_3b70_0018)),
                (8, None),
                (3, Some(0x2_3d28_4010))
            ]
        );
        assert_eq!(states.domains[2].parents[0].unwrap().device, 1);
        // Without the PMGR's compatible, nothing is placed.
        assert_eq!(
            board(&tree(0x8112, "Apple M2", MODELED))
                .unwrap()
                .power_states,
            None
        );
    }

    #[test]
    fn special_acc_events_use_the_dt_selector_and_cluster_type() {
        use crate::machine::adt::encode;
        let mut e = [0u8; 24];
        e[2] = 2;
        e[6] = 12;
        let mut p = [0u8; 24];
        p[2] = 7;
        p[6] = 24;
        let data = [e, p].concat();
        let tree = encode(&[("events", &data)], &[]);
        assert_eq!(
            acc_events(&Node::root(&tree).unwrap(), 2).unwrap(),
            vec![vec![12], vec![24]]
        );
        assert!(acc_events(&Node::root(&tree).unwrap(), 1).is_err());
        p[6] = 27;
        let tree = encode(&[("events", &p)], &[]);
        assert!(acc_events(&Node::root(&tree).unwrap(), 2).is_err());
    }

    #[test]
    fn bridge_headers_configs_axi_and_dependencies_place_the_translated_window() {
        use crate::machine::adt::encode;
        let cells = |v: &[u32]| v.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<_>>();
        let mut config = [0u8; 36];
        config[1] = 7;
        let mut dependency = [0u8; 76];
        dependency[3] = 9;
        let tree = encode(
            &[
                ("bridge-reg-index", &cells(&[1])),
                ("#bridges", &cells(&[1])),
                ("bridge-settings-version", &cells(&[1])),
                ("bridge-counter-version", &cells(&[3])),
                ("bridge-counters", &[0, 0x80, 0, 1]),
                ("bridge-counter-configs", &config),
                ("axi2af-axi-config", &[0, 0x20, 0x18, 8]),
                ("device-bridges", &dependency),
            ],
            &[],
        );
        let n = Node::root(&tree).unwrap();
        let fields: &[&[(u64, u32)]] = &[&[(0, 0x103)]];
        let banks =
            place_bridges(&n, &[None, Some((0x6_8c00_0000, 0x1000000))], Some(fields)).unwrap();
        assert_eq!(banks[0].physical, 0x6_8c00_0000);
        assert_eq!(banks[0].devices, vec![9]);
        assert_eq!(banks[0].configs, vec![config]);
        assert_eq!(banks[0].axi, Some([0, 0x20, 0x18, 8]));
        assert!(place_bridges(&n, &[None, Some((0, 0x100))], Some(fields)).is_err());
        assert!(place_bridges(&n, &[None], Some(fields)).is_err());
        assert!(place_bridges(&n, &[], None).is_err());
    }

    #[test]
    fn soc_dpe_samples_are_absolute_and_checked_against_the_selected_dt_bank() {
        use crate::machine::adt::encode;
        let mut sample = [0u8; 40];
        sample[..8].copy_from_slice(&0x5_0000_2708u64.to_le_bytes());
        sample[16..24].copy_from_slice(&[0x1d, 0, 1, 0, 1, 1, 1, 64]);
        let tree = encode(&[("hw-dpe-reg", &sample)], &[]);
        let node = Node::root(&tree).unwrap();
        let bank = place_soc_dpe(&node, &[Some((0x5_0000_0000, 0x8000))], 0).unwrap();
        assert_eq!(bank.samples, vec![(0x2708, true)]);
        assert_eq!(bank.physical, 0x5_0000_0000);
        assert!(place_soc_dpe(&node, &[Some((0, 0x8000))], 0).is_err());
        assert!(place_soc_dpe(&node, &[Some((0x5_0000_0000, 0x3000))], 0).is_err());
    }

    #[test]
    fn soc_power_roles_use_dt_ranges_and_refuse_short_or_overflowed_ranges() {
        let kinds = [
            power::Kind::Volman,
            power::Kind::Marker,
            power::Kind::Gpce,
            power::Kind::Gating,
            power::Kind::Tvm,
        ];
        for kind in kinds {
            let reg = [None, Some((0x5_0000_0000, 0x20000))];
            assert_eq!(
                place_power_banks(&reg, &[(1, kind)]).unwrap(),
                vec![PowerBank {
                    physical: 0x5_0000_0000,
                    kind
                }]
            );
            assert!(place_power_banks(&[None], &[(1, kind)]).is_err());
            assert!(place_power_banks(&[Some((0, 0))], &[(0, kind)]).is_err());
            assert!(place_power_banks(&[Some((u64::MAX - 3, 0x20000))], &[(0, kind)]).is_err());
        }
    }

    #[test]
    fn wake_masks_derive_the_bank_and_validate_dt_sources_without_assuming_reset_masks() {
        use crate::machine::adt::encode;
        let layout = SOCS
            .iter()
            .find(|soc| soc.chip_id == 0x8112)
            .unwrap()
            .wake_masks
            .unwrap();
        let mut reg = [None; 5];
        reg[4] = Some((0x2_3d00_4000, 0x1000));
        let named = |id: u32, name: &[u8]| {
            let mut entry = [0u8; 36];
            entry[..4].copy_from_slice(&id.to_le_bytes());
            entry[4..4 + name.len()].copy_from_slice(name);
            entry
        };
        let source = |id: u32| named(id, b"");
        let records = [source(14), source(157)].concat();
        let tree = encode(&[("ap-wake-sources", &records)], &[]);
        let found = wake_bank(&Node::root(&tree).unwrap(), &reg, layout).unwrap();
        assert_eq!(
            found,
            WakeBank {
                physical: 0x2_3d00_4008,
                valid: layout.valid,
                sources: vec![14, 157],
                smc_wake: None,
            }
        );
        // J473AP names the SMC's wake of the AP source 81.
        let records = [named(14, b"AOP.GPIO.IRQ6"), named(81, b"SMC.CPUWakeupAP")].concat();
        let tree = encode(&[("ap-wake-sources", &records)], &[]);
        let found = wake_bank(&Node::root(&tree).unwrap(), &reg, layout).unwrap();
        assert_eq!(found.smc_wake, Some(81));
        reg[4] = Some((0x5_0000_0000, 0x1000));
        assert_eq!(
            wake_bank(&Node::root(&tree).unwrap(), &reg, layout)
                .unwrap()
                .physical,
            0x5_0000_0008
        );
        for invalid in [
            source(255).to_vec(),
            source(256).to_vec(),
            [source(14), source(14)].concat(),
            records[..35].to_vec(),
        ] {
            let tree = encode(&[("ap-wake-sources", &invalid)], &[]);
            assert!(wake_bank(&Node::root(&tree).unwrap(), &reg, layout).is_err());
        }
        reg[4] = Some((0, wake::OFFSET + wake::BYTES - 1));
        assert!(wake_bank(&Node::root(&tree).unwrap(), &reg, layout).is_err());
        reg[4] = Some((u64::MAX - wake::OFFSET, 0x1000));
        assert!(wake_bank(&Node::root(&tree).unwrap(), &reg, layout).is_err());
        reg[4] = None;
        assert!(wake_bank(&Node::root(&tree).unwrap(), &reg, layout).is_err());
    }

    #[test]
    fn perf_groups_derive_sparse_selectors_from_each_dt_record_kind() {
        use crate::machine::adt::encode;
        let group = |index: u32, offset: u32, count: u16, class: u8| {
            let mut entry = [0u8; 16];
            entry[..4].copy_from_slice(&index.to_le_bytes());
            entry[4..8].copy_from_slice(&offset.to_le_bytes());
            entry[8..10].copy_from_slice(&count.to_le_bytes());
            entry[12] = class;
            entry
        };
        let mut device = [0u8; PMGR_DEVICE];
        device[0] = 0x20;
        device[8] = 9;
        device[9] = 0;
        let source = |bytes: &[u8]| {
            let mut entry = [0u8; 24];
            entry[..bytes.len()].copy_from_slice(bytes);
            entry
        };
        let groups = [
            group(1, 0x34000, 256, 3),
            group(0, 0x58000, 256, 0),
            group(0, 0x78000, 12, 0),
        ]
        .concat();
        let clocks = [source(&[24, 0, 1]), source(&[25, 0, 0])].concat();
        let domains = [source(&[0, 31, 0]), source(&[0, 0, 0])].concat();
        let events = [
            source(&[0, 0, 1, 80, 41, 0, 40, 0]),
            source(&[15, 0, 5, 52, 1, 2, 0, 2]),
            source(&[0, 0, 0, 1, 0, 0, 120, 1]),
            source(&[0, 0, 2, 96, 0, 0, 0, 0]),
            source(&[0, 0, 7, 101, 0, 0, 12, 0]),
            source(&[0, 1, 0, 128, 0, 0, 50, 1]),
        ]
        .concat();
        let tree = |groups: &[u8], clocks: &[u8]| {
            encode(
                &[
                    ("perf-regs", groups),
                    ("devices", &device),
                    ("clocks", clocks),
                    ("power-domains", &domains),
                    ("events", &events),
                ],
                &[],
            )
        };
        let reg = [
            Some((0x2_3b70_0000, 0xcc000)),
            Some((0x2_3d28_0000, 0x7c000)),
        ];
        let data = tree(&groups, &clocks);
        let node = Node::root(&data).unwrap();
        assert_eq!(
            performance_banks(&node, &reg).unwrap(),
            vec![
                PerfBank {
                    physical: 0x2_3d2b_4000,
                    selectors: vec![9, 24, 31, 40, 41]
                },
                PerfBank {
                    physical: 0x2_3b75_8000,
                    selectors: vec![120]
                },
                PerfBank {
                    physical: 0x2_3b77_8000,
                    selectors: vec![0, 1]
                },
            ]
        );
        for invalid in [
            groups[..47].to_vec(),
            {
                let mut bad = groups.clone();
                bad[13] = 2;
                bad
            },
            {
                let mut bad = groups.clone();
                bad[15] = 2;
                bad
            },
            {
                let mut bad = groups.clone();
                bad[12] = 1;
                bad
            },
            {
                let mut bad = groups.clone();
                bad[..4].copy_from_slice(&3u32.to_le_bytes());
                bad
            },
        ] {
            let data = tree(&invalid, &clocks);
            assert!(performance_banks(&Node::root(&data).unwrap(), &reg).is_err());
        }
        for invalid in [
            clocks[..47].to_vec(),
            source(&[12, 2, 1]).to_vec(),
            source(&[0, 3, 1]).to_vec(),
        ] {
            let data = tree(&groups, &invalid);
            assert!(performance_banks(&Node::root(&data).unwrap(), &reg).is_err());
        }
        assert!(performance_banks(&node, &[Some((0, 0x100)), reg[1]]).is_err());
        assert!(performance_banks(&node, &[Some((u64::MAX - 0x58000, 0xcc000)), reg[1]]).is_err());
        let relocated = [
            Some((0x5_0000_0000, 0xcc000)),
            Some((0x6_0000_0000, 0x7c000)),
        ];
        let placed = performance_banks(&node, &relocated).unwrap();
        assert_eq!(placed[0].physical, 0x6_0003_4000);
        assert_eq!(placed[1].physical, 0x5_0005_8000);
    }

    /// The J473AP's `/arm-io/mcc` and `/arm-io/pmp` registers behind its one
    /// AMCC aperture.
    #[test]
    fn an_mcc_places_its_cache_channels_and_ptd_bank() {
        use crate::machine::adt::encode;
        const MODELED: [&str; 3] = ["uart-1,samsung", "wdt,s5l8960x", "aic,2"];
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let u32s = |cells: &[u32]| {
            cells
                .iter()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let u64s = |cells: &[u64]| {
            cells
                .iter()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let mcc = |ptd_offset: u32| {
            encode(
                &[
                    ("name", &z("mcc")),
                    ("compatible", &z(MCC)),
                    (
                        "reg",
                        &u64s(&[
                            0x10_0000,
                            0x8_0000,
                            0,
                            0x10_0000,
                            0x100_0000,
                            0x200_0000,
                            0xf0_0000,
                            0x10_0000,
                            0x3b3c_0000,
                            0x2_0000,
                        ]),
                    ),
                    ("dcs_num_channels", &u32s(&[8])),
                    ("pmp_ptd_reg_idx", &u32s(&[4])),
                    ("pmp_ptd_update_space_offset", &u32s(&[ptd_offset])),
                ],
                &[],
            )
        };
        // Two J473AP `ptd-range` records.
        let record = |id: u32, start: u32, count: u32, name: &str| {
            let mut record = [0u8; PTD_RANGE];
            for (at, word) in [id, start, count, 0].into_iter().enumerate() {
                record[4 * at..4 * at + 4].copy_from_slice(&word.to_le_bytes());
            }
            record[16..16 + name.len()].copy_from_slice(name.as_bytes());
            record
        };
        let records = [record(1, 0, 1, "NULL"), record(2, 1, 1, "PMP-STATUS")].concat();
        let nub = encode(&[("name", &z("iop-pmp-nub")), ("ptd-range", &records)], &[]);
        let pmp = encode(
            &[
                ("name", &z("pmp")),
                ("reg", &u64s(&[0x3bc0_0000, 0x6_c000, 0x3b3d_0000, 0x4000])),
                ("ptd-update-reg-index", &u32s(&[1])),
            ],
            &[nub],
        );
        let controller = MemoryController {
            apertures: vec![0x2_0000_0000],
            layout: amcc::Layout {
                aperture_bytes: 0xf4_0000,
                planes: 4,
                stride: 0x4_0000,
                cache_status: Some(amcc::Register {
                    offset: 0x424,
                    mask: 1,
                    value: 1,
                }),
                group: amcc::LockGroup {
                    page_size_shift: 14,
                    lower_limit: amcc::Register {
                        offset: 0x680,
                        mask: u32::MAX,
                        value: 0,
                    },
                    upper_limit: amcc::Register {
                        offset: 0x684,
                        mask: u32::MAX,
                        value: 0,
                    },
                    enable: Some(amcc::Register {
                        offset: 0x688,
                        mask: 1,
                        value: 1,
                    }),
                    write_disable: Some(amcc::Register {
                        offset: 0x7f0,
                        mask: 1,
                        value: 1,
                    }),
                    lock: Some(amcc::Register {
                        offset: 0x68c,
                        mask: 1,
                        value: 1,
                    }),
                },
                dram_base: 0x8_0000_0000,
            },
        };
        let found = |ptd_offset: u32, controller: Option<&MemoryController>| {
            let tree = tree_with_io(
                0x8112,
                "Apple M2",
                MODELED,
                &[],
                &[mcc(ptd_offset), pmp.clone()],
            );
            let io = Node::root(&tree).unwrap().child("arm-io").unwrap();
            memory_cache(
                &io,
                &|offset| Some(0x2_0000_0000 + offset),
                0x8112,
                controller,
            )
        };
        assert_eq!(
            found(0x1_0000, Some(&controller)),
            Ok(Some(MemoryCache {
                cache: amcc::Cache {
                    shared: (0x10_0000, 0x8_0000),
                    broadcast: 0xf0_0000,
                    bytes: 8 << 20,
                    ways: 16,
                },
                channels: (0x2_0100_0000, 0x200_0000, 8),
                ptd: PtdBank {
                    physical: 0x2_3b3c_0000,
                    interrupts: vec![0, 0],
                    ranges: vec![
                        ptd::Range {
                            id: 1,
                            start: 0,
                            count: 1,
                            name: "NULL".into(),
                        },
                        ptd::Range {
                            id: 2,
                            start: 1,
                            count: 1,
                            name: "PMP-STATUS".into(),
                        },
                    ],
                },
            }))
        );
        // The PTD updates must be the bank's, and the planes need the
        // lock-regs aperture.
        assert!(found(0x2_0000, Some(&controller)).is_err());
        assert!(found(0x1_0000, None).is_err());
    }

    #[test]
    fn an_aic3_board_states_the_modeled_offsets() {
        const M3: [&str; 3] = ["uart-1,samsung", "wdt,s5l8960x", "aic,3"];
        let found = board(&tree_with(0x8122, "Apple M3", M3, &AIC3_OFFSETS)).unwrap();
        assert_eq!(
            (found.cpus.chip, found.aic.layout),
            (Chip::AppleM3, AicLayout::aic3(0x40000))
        );
        assert_eq!(
            board(&tree_with(0x8122, "Apple M3", M3, &AIC3_OFFSETS[1..])),
            Err("/arm-io/aic has no rev-offset".into())
        );
        let mut moved = AIC3_OFFSETS;
        moved[4].1 = 0x20000;
        assert_eq!(
            board(&tree_with(0x8122, "Apple M3", M3, &moved)),
            Err("/arm-io/aic extint-baseaddress is 0x20000, not the modeled 0x10000".into())
        );
        // The M4's AICv3 event register has no public placement.
        assert_eq!(
            board(&tree_with(0x8132, "Apple M4", M3, &AIC3_OFFSETS)),
            Err("the SoC's AIC event register offset is unknown".into())
        );
    }
    #[test]
    fn sep_placement_uses_the_native_nub_and_is_admitted_by_its_sep_role() {
        use crate::machine::adt::encode;
        const MODELED: [&str; 3] = [UART, WATCHDOG, "aic,2"];
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let words = |cells: &[u32]| {
            cells
                .iter()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let pairs = |cells: &[u64]| {
            cells
                .iter()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let tree = |nub: &str, irqs: &[u32], parent: u32, stream: u32| {
            let mapper = encode(
                &[
                    ("name", &z("mapper-sep")),
                    ("compatible", &z(IOMMU_MAPPER)),
                    ("reg", &words(&[stream])),
                    ("AAPL,phandle", &words(&[0x84])),
                ],
                &[],
            );
            let dart = encode(
                &[
                    ("name", &z("dart-sep")),
                    ("compatible", &z(DART)),
                    ("reg", &pairs(&[0x5d2c0000, 0x4000])),
                    ("sid-count", &words(&[1])),
                    ("instance", b"TRAD\0\0\0\0DART\0\0\0\0"),
                    ("interrupts", &words(&[0x11a])),
                ],
                &[mapper],
            );
            let nub = encode(&[("name", &z("iop-sep-nub")), ("compatible", &z(nub))], &[]);
            let sep = encode(
                &[
                    ("name", &z("sep")),
                    ("compatible", &z(SEP)),
                    ("aarch64", &[]),
                    ("iop-version", &words(&[1])),
                    ("iommu-parent", &words(&[parent])),
                    ("interrupts", &words(irqs)),
                    ("reg", &pairs(&[0x5e400000, 0x6c000, 0x5e050000, 0x60000])),
                ],
                &[nub],
            );
            tree_with_io(0x8112, "Apple M2", MODELED, &[], &[dart, sep])
        };
        let irqs = [0x115, 0x114, 0x117, 0x116];
        let bytes = tree(SEP_NUB, &irqs, 0x84, 0);
        let found = board(&bytes).unwrap();
        assert_eq!(
            found.sep,
            Some(SepDevice {
                ranges: [(0x25e400000, 0x6c000), (0x25e050000, 0x60000)],
                irqs,
                iommu: 0,
                instance: 0,
                mapper: 0x84,
                mapper_context: 0,
                stream: 0,
                firmware: None,
                security: None,
                ecid: None,
            })
        );
        assert_eq!(found.darts[0].instances[0].physical, 0x25d2c0000);
        // A sole TRAD's SID capacity is independent of the selected context.
        // Incoming source5 -> context4 remains an explicit native route.
        let root = Node::root(&bytes).unwrap();
        let io = root.child("arm-io").unwrap();
        let place = |darts: &[Iommu]| {
            sep_device(&root, &io, &|v| Some(v + 0x200000000), darts).map(|sep| sep.unwrap())
        };
        let mut routed = found.darts.clone();
        routed[0].profile = dart::Profile::T6000;
        routed[0].streams = 16;
        routed[0].sids = alloc::vec![0, 4, 15];
        routed[0].mappers = alloc::vec![(0x84, 4)];
        routed[0].remap = alloc::vec![(5, 4)];
        let route = place(&routed).unwrap();
        assert_eq!(
            (
                route.instance,
                route.mapper,
                route.mapper_context,
                route.stream
            ),
            (0, 0x84, 4, 5)
        );
        let good = routed[0].clone();
        routed[0].remap.clear();
        assert_eq!(
            (
                place(&routed).unwrap().mapper_context,
                place(&routed).unwrap().stream
            ),
            (4, 4)
        );
        routed[0] = good.clone();
        routed[0].mappers.push((0x84, 0));
        assert!(place(&routed).unwrap_err().contains("ambiguous"));
        routed[0] = good.clone();
        routed.push(good.clone());
        assert!(place(&routed).unwrap_err().contains("ambiguous"));
        routed.pop();
        routed[0] = good.clone();
        routed[0].instances.push(good.instances[0].clone());
        assert!(place(&routed).unwrap_err().contains("multiple-TRAD"));
        routed[0].instances.clear();
        assert!(place(&routed).unwrap_err().contains("multiple-TRAD"));
        routed[0] = good.clone();
        routed[0].sids = alloc::vec![0, 15];
        assert!(place(&routed).unwrap_err().contains("SID set"));
        routed[0] = good.clone();
        routed[0].mappers[0].1 = 16;
        routed[0].sids.push(16);
        assert!(
            place(&routed)
                .unwrap_err()
                .contains("outside the native profile")
        );
        routed[0] = good.clone();
        routed[0].mappers[0].1 = 5;
        routed[0].sids.push(5);
        assert!(
            place(&routed)
                .unwrap_err()
                .contains("incoming remapped source")
        );
        routed[0] = good;
        routed[0].profile = dart::Profile::T8110;
        assert!(
            place(&routed)
                .unwrap_err()
                .contains("unqualified for this generation")
        );
        // Admitted only with its distinguishing `role = SEP`; the nub is kept
        // as a modeled child, and neither is a bare flat-list compatible.
        let sep_role = |key: &str| (key == "role").then_some(b"SEP\0".as_slice());
        assert!(models(SEP, sep_role));
        assert!(!models(SEP, |_| None));
        assert!(!models(SEP_NUB, |_| None));
        assert_eq!(
            model_children(SEP, sep_role)
                .iter()
                .map(|child| child.compatible)
                .collect::<Vec<_>>(),
            [SEP_NUB]
        );
        assert!(board(&tree("iop-nub,rtbuddy-v2", &irqs, 0x84, 0)).is_err());
        assert!(board(&tree(SEP_NUB, &irqs[..3], 0x84, 0)).is_err());
        assert!(board(&tree(SEP_NUB, &irqs, 0x85, 0)).is_err());
        assert!(
            board(&tree(SEP_NUB, &irqs, 0, 0))
                .unwrap_err()
                .contains("iommu-parent is zero")
        );
        assert!(board(&tree(SEP_NUB, &irqs, 0x84, 1)).is_err());
        let root = Node::root(&bytes).unwrap();
        let io = root.child("arm-io").unwrap();
        let memory_map =
            |cells: &[u64]| encode(&[("name", &z("memory-map")), ("SEPFW", &pairs(cells))], &[]);
        let root_with_region = |cells: &[u64]| {
            encode(
                &[("name", &z("device-tree"))],
                &[encode(&[("name", &z("chosen"))], &[memory_map(cells)])],
            )
        };
        let region = root_with_region(&[0x81fd54000, 0x5dc000]);
        let placed = sep_device(
            &Node::root(&region).unwrap(),
            &io,
            &|v| Some(v + 0x200000000),
            &found.darts,
        )
        .unwrap()
        .unwrap();
        assert_eq!(placed.firmware, Some((0x81fd54000, 0x5dc000)));
        for cells in [&[0x81fd54000][..], &[0x81fd54000, 0], &[u64::MAX, 2]] {
            let region = root_with_region(cells);
            assert!(
                sep_device(
                    &Node::root(&region).unwrap(),
                    &io,
                    &|v| Some(v + 0x200000000),
                    &found.darts
                )
                .is_err()
            );
        }
    }
    #[test]
    #[ignore = "requires original 26A434 J314s DT through STELA_TEST_DART_DT"]
    fn original_j314s_sep_preserves_sole_trad_with_sixteen_sid_capacity() {
        let data = std::fs::read(std::env::var("STELA_TEST_DART_DT").unwrap()).unwrap();
        assert_eq!(
            crate::sha256(&data),
            "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
        );
        let root = Node::root(&data).unwrap();
        let io = root.child("arm-io").unwrap();
        let ranges = io.ranges().unwrap();
        let translate = |offset: u64| {
            ranges.iter().find_map(|&(child, parent, bytes)| {
                offset
                    .checked_sub(child)
                    .filter(|&delta| delta < bytes)
                    .and_then(|delta| parent.checked_add(delta))
            })
        };
        let node = io.child("dart-sep").unwrap();
        assert_eq!(node.first_u32("sids"), Some(0x8001));
        let darts = [iommu(&node, &translate).unwrap()];
        let dart = &darts[0];
        assert_eq!(dart.profile, dart::Profile::T6000);
        assert_eq!(dart.streams, 16);
        assert_eq!(dart.sids, [0, 15]);
        assert_eq!(dart.instances.len(), 1);
        assert!(dart.remap.is_empty());
        let sep = sep_device(&root, &io, &translate, &darts).unwrap().unwrap();
        assert_eq!(
            (sep.iommu, sep.instance, sep.mapper_context, sep.stream),
            (0, 0, 0, 0)
        );
        assert_eq!(dart.mappers, [(sep.mapper, 0)]);
        println!("source-qualified SEP route: {sep:?}; dart={dart:?}");
    }

    #[test]
    #[ignore = "requires original 26A434 J314s DT through STELA_TEST_DART_DT"]
    fn original_j314s_external_output_preserves_native_routes_and_identity() {
        let data = std::fs::read(std::env::var("STELA_TEST_DART_DT").unwrap()).unwrap();
        assert_eq!(
            crate::sha256(&data),
            "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
        );
        let root = Node::root(&data).unwrap();
        let io = root.child("arm-io").unwrap();
        let ranges = io.ranges().unwrap();
        let translate = |offset| {
            ranges
                .iter()
                .find(|(child, _, bytes)| (*child..child + bytes).contains(&offset))
                .map(|(child, parent, _)| parent + (offset - child))
        };
        let darts = ["dart-dispext0", "dart-dcpext0"]
            .map(|name| iommu(&io.child(name).unwrap(), &translate).unwrap());
        assert_eq!(darts[0].instances.len(), 1);
        assert_eq!(darts[0].smmu, Some((0x2_8930_0000, 0x4000)));
        assert_eq!(darts[0].instances[0].physical, 0x2_8930_4000);
        assert_eq!(darts[1].instances[0].physical, 0x2_8930_c000);
        assert_eq!(darts[0].irq, 873);
        assert_eq!(darts[1].irq, 873);
        assert_eq!(darts[1].remap, [(5, 0)]);
        let dcp = dcp_device(&io, &translate, &darts).unwrap().unwrap();
        assert_eq!(dcp.role, "DCPEXT0");
        assert_eq!(dcp.identity, dcp::ExternalIdentity::Numbered(0));
        assert_eq!(
            (dcp.iommu, dcp.instance, dcp.mapper_context, dcp.stream),
            (1, 0, 0, 5)
        );
        assert_eq!((dcp.surface, dcp.surface_instance), (Some((0, 0)), Some(0)));
        assert_eq!(dcp.mapper, 0x109);
        assert_eq!(
            dcp.surface_routes,
            [
                DcpMapperRoute {
                    mapper: 0x103,
                    iommu: 0,
                    instance: 0,
                    mapper_context: 0,
                    stream: 0
                },
                DcpMapperRoute {
                    mapper: 0x104,
                    iommu: 0,
                    instance: 0,
                    mapper_context: 4,
                    stream: 4
                },
            ]
        );
        println!(
            "original DCP owner metadata: firmware={:?}/{:#x}, pipe={:?}, routes={:?}",
            dcp.phandle, dcp.mapper, dcp.surface_phandle, dcp.surface_routes
        );
        assert_eq!(dcp.wrapper, (0x2_89c0_0000, 0x6c000));
        assert_eq!(
            dcp.regions,
            [
                ("dispext0", (0x2_8800_0000, 0x3000000)),
                ("dispext0", (0x2_8932_0000, 0x4000)),
                ("dispext0", (0x2_8934_4000, 0x4000)),
                ("dispext0", (0x2_8980_0000, 0x800000)),
                ("dispext0", (0x2_8e3d_0000, 0x4000)),
            ]
        );
        let mut devices = crate::machine::apple::AppleDevices::new();
        let mut owners = Vec::new();
        for dart in darts {
            let native = dart
                .instances
                .iter()
                .map(|i| crate::machine::apple::Range {
                    physical: i.physical,
                    bytes: i.bytes,
                })
                .collect::<Vec<_>>();
            let ids = devices
                .add_dart_group_for_profile(
                    dart.profile,
                    &native,
                    usize::from(dart.streams),
                    Some(crate::platform::apple::interrupt::AicInput::new(
                        0,
                        dart.irq as u16,
                    )),
                    None,
                )
                .unwrap();
            if let Some((physical, bytes)) = dart.smmu {
                devices
                    .add_dart_smmu(ids[0], crate::machine::apple::Range { physical, bytes })
                    .unwrap();
            }
            owners.extend(ids);
        }
        use crate::machine::apple::{Range, Scanout, ScanoutFormat, ScanoutMode};
        struct Screen;
        impl Scanout for Screen {
            fn mode(&self) -> ScanoutMode {
                ScanoutMode {
                    width: 1,
                    height: 1,
                    format: ScanoutFormat::Bgra8888,
                }
            }
            fn present(&mut self, _: &[u8]) -> Result<(), &'static str> {
                panic!("mount is not a frame")
            }
        }
        devices
            .add_dcpext(
                Range {
                    physical: dcp.wrapper.0,
                    bytes: dcp.wrapper.1,
                },
                dcp.interrupts,
                dcp.quiesced,
                dcp.role,
                dcp.identity,
                alloc::boxed::Box::new(Screen),
                (owners[1], dcp.stream as usize),
                dcp.window,
                Some((owners[0], dcp.surface.unwrap().1 as usize)),
            )
            .unwrap();
        let regions = dcp
            .regions
            .iter()
            .map(|&(name, (physical, bytes))| (name, Range { physical, bytes }))
            .collect::<Vec<_>>();
        devices
            .add_display_with_darts(&regions, dcp.role, &owners)
            .unwrap();
        // Full original views and their actual nested owners mount together;
        // this is not evidence of original firmware execution or a frame.
    }

    #[test]
    fn dcp_placement_reads_the_wrapper_irqs_nub_and_display_apertures_without_admitting_it() {
        use crate::machine::adt::encode;
        const MODELED: [&str; 3] = [UART, WATCHDOG, "aic,2"];
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let words = |cells: &[u32]| {
            cells
                .iter()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let pairs = |cells: &[u64]| {
            cells
                .iter()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let irqs = [0x242, 0x242, 0x245, 0x244];
        let build = |role: &[u8], quiesced: bool, with_regions: bool| {
            let mut nub_props: Vec<(&str, &[u8])> = if quiesced {
                vec![("name", b"iop-dcpext-nub\0"), ("quiesced", &[])]
            } else {
                vec![("name", b"iop-dcpext-nub\0")]
            };
            nub_props.push(("compatible", b"iop-nub,rtbuddy-v2\0"));
            let nub = encode(&nub_props, &[]);
            let mapper = encode(
                &[
                    ("name", &z("mapper-dcpext")),
                    ("compatible", &z(IOMMU_MAPPER)),
                    ("reg", &words(&[5])),
                    ("AAPL,phandle", &words(&[0xc8])),
                ],
                &[],
            );
            let dart = encode(
                &[
                    ("name", &z("dart-dcpext")),
                    ("compatible", &z(DART)),
                    ("reg", &pairs(&[0x7130_c000, 0x4000])),
                    ("sid-count", &words(&[16])),
                    ("instance", b"TRAD\0\0\0\0DARTASC\0"),
                    ("interrupts", &words(&[0x251])),
                    ("vm-base", &words(&[0, 8])),
                ],
                &[mapper],
            );
            let dcpext = encode(
                &[
                    ("name", &z("dcpext")),
                    ("compatible", &z(ASC)),
                    ("role", role),
                    ("interrupts", &words(&irqs)),
                    ("iommu-parent", &words(&[0xc8])),
                    ("truncate-dvas", &[]),
                    ("reg", &pairs(&[0x71c0_0000, 0x6c000, 0x7185_0000, 0x4000])),
                ],
                &[nub],
            );
            let surface_mappers = [
                encode(
                    &[
                        ("name", &z("mapper-dispext0")),
                        ("compatible", &z(IOMMU_MAPPER)),
                        ("reg", &words(&[0])),
                        ("AAPL,phandle", &words(&[0xca])),
                    ],
                    &[],
                ),
                encode(
                    &[
                        ("name", &z("mapper-dispext0-piodma")),
                        ("compatible", &z(IOMMU_MAPPER)),
                        ("reg", &words(&[4])),
                        ("AAPL,phandle", &words(&[0xcb])),
                    ],
                    &[],
                ),
            ];
            let pipe_dart = encode(
                &[
                    ("name", &z("dart-dispext0")),
                    ("compatible", &z(DART)),
                    ("reg", &pairs(&[0x7130_4000, 0x4000, 0x7130_0000, 0x4000])),
                    ("sid-count", &words(&[16])),
                    (
                        "instance",
                        b"TRAD\0\0\0\0DART\0\0\0\0UMMS\0\0\0\0SMMU\0\0\0\0",
                    ),
                    ("interrupts", &words(&[0x251])),
                ],
                &surface_mappers,
            );
            let expert = encode(
                &[
                    ("name", &z("dcpext-expert")),
                    ("compatible", &z(DCP_EXPERT)),
                    ("role", DCPEXT_ROLE),
                    ("join-power-plane", &words(&[1])),
                ],
                &[],
            );
            let mut children = alloc::vec![dart, dcpext, expert];
            if with_regions {
                children.push(pipe_dart);
                children.push(encode(
                    &[
                        ("name", &z("dispext0")),
                        ("compatible", &z(DISPEXT)),
                        ("reg", &pairs(&[0x7000_0000, 0x61c000])),
                        ("iommu-parent", &words(&[0xca, 0xcb])),
                    ],
                    &[],
                ));
                children.push(encode(
                    &[
                        ("name", &z("dptx-phy")),
                        ("compatible", &z(DPTX_PHY)),
                        ("reg", &pairs(&[0x3c54_0000, 0xc000])),
                    ],
                    &[],
                ));
                children.push(encode(
                    &[
                        ("name", &z("display-crossbar0")),
                        ("compatible", &z(DISPLAY_CROSSBAR)),
                        ("reg", &pairs(&[0x3c00_0000, 0x4000])),
                    ],
                    &[],
                ));
            }
            tree_with_io(0x8112, "Apple M2", MODELED, &[], &children)
        };
        let found = board(&build(DCPEXT_ROLE, true, true)).unwrap();
        let dcp = found.dcp.expect("dcpext is parsed");
        // /arm-io ranges translate the low window by +0x2_0000_0000.
        assert_eq!(dcp.wrapper, (0x2_71c0_0000, 0x6c000));
        assert_eq!(dcp.interrupts, irqs);
        assert!(dcp.quiesced);
        assert_eq!((dcp.iommu, dcp.stream), (0, 5));
        assert_eq!(found.darts[0].vm_base, 0x8_0000_0000);
        assert_eq!(dcp.window, Some(0x8_0000_0000));
        // The surfaces translate through dart-dispext0 stream 0; its SMMU
        // block is the second reg entry.
        assert_eq!(dcp.surface, Some((1, 0)));
        assert_eq!(dcp.mapper, 0xc8);
        assert_eq!(
            dcp.surface_routes
                .iter()
                .map(|r| (r.mapper, r.mapper_context, r.stream))
                .collect::<Vec<_>>(),
            [(0xca, 0, 0), (0xcb, 4, 4)]
        );
        assert_eq!(found.darts[1].instances[0].physical, 0x2_7130_4000);
        assert_eq!(found.darts[1].smmu, Some((0x2_7130_0000, 0x4000)));
        assert_eq!(found.darts[0].smmu, None);
        assert_eq!(
            dcp.regions,
            alloc::vec![
                ("dispext0", (0x2_7000_0000, 0x61c000)),
                ("dptx-phy", (0x2_3c54_0000, 0xc000)),
                ("display-crossbar0", (0x2_3c00_0000, 0x4000)),
            ]
        );
        // A native controller cannot be exposed without its actual pipe.
        assert!(board(&build(DCPEXT_ROLE, false, false)).is_err());
        // DCPEXT and its pipe are admitted with a native nub; the PHY and
        // crossbar stay hidden, and a wrong role is not a DCP.
        let role = |key: &str| (key == "role").then_some(DCPEXT_ROLE);
        assert!(models(ASC, role));
        assert_eq!(model_children(ASC, role)[0].compatible, RTBUDDY);
        assert!(models(DISPEXT, |_| None));
        let t6000_role = |key: &str| (key == "role").then_some(b"DCPEXT0\0".as_slice());
        assert_eq!(models(ASC, t6000_role), T6000_EXTERNAL_OUTPUT_ADMITTED);
        assert_eq!(
            models(DISPEXT_T6000, |_| None),
            T6000_EXTERNAL_OUTPUT_ADMITTED
        );
        assert!(external_output(b"DCPEXT1\0").is_none());

        assert!(!models(DPTX_PHY, |_| None) && !models(DISPLAY_CROSSBAR, |_| None));
        // Its power expert binds; the internal display's expert does not.
        assert!(models(DCP_EXPERT, role));
        assert!(model_children(DCP_EXPERT, role).is_empty());
        assert!(!models(DCP_EXPERT, |key| (key == "role")
            .then_some(b"DCP\0".as_slice())));
        assert!(board(&build(b"DCP\0", true, false)).unwrap().dcp.is_none());
    }

    #[test]
    fn usb_placement_uses_identity_ranges_mapper_and_all_interrupts() {
        use crate::machine::adt::encode;
        let words = |cells: &[u32]| {
            cells
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let pairs = |cells: &[(u64, u64)]| {
            cells
                .iter()
                .flat_map(|&(a, b)| [a, b])
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let ranges = [
            (0x382280000, 0x11800),
            (0x382200000, 0x4000),
            (0x38228c000, 0x5800),
            (0x382a84000, 0x4000),
            (0x382800000, 0x4000),
            (0x382a80000, 0x4000),
            (0x382000000, 0x4000),
            (0x382080000, 0x4000),
            (0x38228d000, 0x4000),
        ];
        let mapper = encode(
            &[
                ("name", b"mapper-usb0\0"),
                ("compatible", b"iommu-mapper\0"),
                ("reg", &words(&[1])),
                ("AAPL,phandle", &words(&[0xa4])),
            ],
            &[],
        );
        // One-instance fixture: the independent Type-C worker owns the
        // production two-instance USB DART layout and SID remap.
        let dart = encode(
            &[
                ("name", b"dart-usb0\0"),
                ("compatible", b"dart,t8110\0"),
                ("reg", &pairs(&[(0x382f00000, 0x4000)])),
                ("instance", b"TRAD\0\0\0\0DART\0\0\0\0"),
                ("sid-count", &words(&[16])),
                ("interrupts", &words(&[1035])),
            ],
            &[mapper],
        );
        let usb = |ranges: &[(u64, u64)], parent: u32, irqs: &[u32]| {
            encode(
                &[
                    ("name", b"usb-drd0\0"),
                    ("compatible", b"usb-drd,t8112\0"),
                    ("reg", &pairs(ranges)),
                    ("iommu-parent", &words(&[parent])),
                    ("interrupts", &words(irqs)),
                    ("port-number", &words(&[1])),
                    ("atc-phy-parent", &words(&[0xa2])),
                ],
                &[],
            )
        };
        let irqs = [1031, 1032, 1033, 1034, 990];
        let tree = |usb| {
            tree_with_io(
                0x8112,
                "Apple M2",
                [UART, WATCHDOG, "aic,2"],
                &[],
                &[dart.clone(), usb],
            )
        };
        let found = board(&tree(usb(&ranges, 0xa4, &irqs))).unwrap();
        assert_eq!(
            found.usbs,
            [UsbController {
                ranges,
                irqs,
                iommu: 0,
                phandle: None,
                mapper: 0xa4,
                mapper_context: 1,
                stream: 1,
                port: 1,
                retention: false,
                phy: 0xa2,
            }]
        );
        assert_eq!(found.darts[0].instances[0].physical, 0x382f00000);
        let bytes = usb(&ranges, 0xa4, &irqs);
        let node = Node::root(&bytes).unwrap();
        let mut routes = found.darts.clone();
        routes[0].profile = dart::Profile::T6000;
        routes[0].remap = vec![(0, 1)];
        routes[0].sids = vec![1, 3];
        let routed = usb_controller(&node, &Some, &routes).unwrap();
        assert_eq!(
            (routed.mapper, routed.mapper_context, routed.stream),
            (0xa4, 1, 0)
        );
        routes[0].sids = vec![0, 3];
        assert!(
            usb_controller(&node, &Some, &routes)
                .unwrap_err()
                .contains("SID set")
        );
        routes[0].sids = vec![1, 3];
        routes[0].mappers.push((0xa4, 3));
        assert!(
            usb_controller(&node, &Some, &routes)
                .unwrap_err()
                .contains("ambiguous")
        );
        // Every controller is placed, in DeviceTree order; a malformed
        // second one names itself.
        let second = encode(
            &[
                ("name", b"usb-drd1\0"),
                ("compatible", b"usb-drd,t8112\0"),
                ("reg", &pairs(&ranges)),
                ("iommu-parent", &words(&[0xa4])),
                ("interrupts", &words(&irqs)),
                ("port-number", &words(&[2])),
                ("atc-phy-parent", &words(&[0xa3])),
            ],
            &[],
        );
        let pair = |second| {
            tree_with_io(
                0x8112,
                "Apple M2",
                [UART, WATCHDOG, "aic,2"],
                &[],
                &[dart.clone(), usb(&ranges, 0xa4, &irqs), second],
            )
        };
        let ports: Vec<_> = board(&pair(second))
            .unwrap()
            .usbs
            .iter()
            .map(|u| u.port)
            .collect();
        assert_eq!(ports, [1, 2]);
        let unnumbered = encode(
            &[
                ("name", b"usb-drd1\0"),
                ("compatible", b"usb-drd,t8112\0"),
                ("reg", &pairs(&ranges)),
                ("iommu-parent", &words(&[0xa4])),
                ("interrupts", &words(&irqs)),
            ],
            &[],
        );
        assert_eq!(
            board(&pair(unnumbered)).unwrap_err(),
            "usb-drd1 has no Type-C port number"
        );
        assert!(models(USB_DRD, |_| None));
        assert!(board(&tree(usb(&ranges, 0xff, &irqs))).is_err());
        assert!(board(&tree(usb(&ranges, 0xa4, &irqs[..4]))).is_err());
        let mut bad = ranges;
        bad[2].0 += 4;
        assert!(board(&tree(usb(&bad, 0xa4, &irqs))).is_err());
        let mut bad = ranges;
        bad[0].1 = u64::MAX;
        assert!(board(&tree(usb(&bad, 0xa4, &irqs))).is_err());
    }
    #[test]
    fn native_dma_owner_properties_keep_complete_lists_and_refuse_truncation() {
        use crate::machine::adt::encode;
        for bytes in [&[][..], &[1, 0, 0][..], &[0, 0, 0, 0][..], &[1; 8][..]] {
            let tree = encode(&[("AAPL,phandle", bytes)], &[]);
            assert!(native_dma_phandle(&Node::root(&tree).unwrap(), "AAPL,phandle").is_err());
        }
        let tree = encode(&[("iommu-parent", &[3, 0, 0, 0, 4, 0, 0, 0])], &[]);
        let node = Node::root(&tree).unwrap();
        assert_eq!(
            native_dma_mapper_list(&node, "iommu-parent").unwrap(),
            [3, 4]
        );
        assert!(native_dma_phandle(&node, "iommu-parent").is_err());
        for bytes in [
            &[][..],
            &[1, 0, 0][..],
            &[1, 0, 0, 0, 0, 0, 0, 0][..],
            &[1, 0, 0, 0, 1, 0, 0, 0][..],
        ] {
            let tree = encode(&[("iommu-parent", bytes)], &[]);
            assert!(native_dma_mapper_list(&Node::root(&tree).unwrap(), "iommu-parent").is_err());
        }
    }

    #[test]
    fn mpidr_composition_preserves_ep_identities_and_rejects_unknown_coordinates() {
        for soc in SOCS {
            for (kind, aff2) in [(b'E', 0u64), (b'P', 1)] {
                let core = soc
                    .cores
                    .iter()
                    .find(|core| core.cluster_type == kind)
                    .unwrap();
                // Include both dies, sparse cores and the upper declared
                // affinity boundary; this field does not define core count.
                for reg in [0, 3, 0x100, 0x105, 0x800, 0x905, 0xfff] {
                    assert_eq!(
                        core.mpidr(reg),
                        Some(0x8000_0000 | aff2 << 16 | u64::from(reg))
                    );
                }
            }
        }
        let m_core = *core_types(0x8152)
            .unwrap()
            .iter()
            .find(|core| core.cluster_type == b'M')
            .unwrap();
        for bit in 12..32 {
            assert_eq!(m_core.mpidr(0x102 | 1 << bit), None);
        }
        assert_eq!(
            CoreType {
                mpidr_aff2: None,
                ..m_core
            }
            .mpidr(0x102),
            None
        );
        for aff2 in [8, 0x80, 0xff] {
            assert_eq!(
                CoreType {
                    mpidr_aff2: Some(aff2),
                    ..m_core
                }
                .mpidr(0x102),
                None
            );
        }
    }

    #[test]
    fn core_requirements_keep_unknown_m6_capabilities_explicit() {
        let soc = SOCS.iter().find(|soc| soc.chip_id == 0x8152).unwrap();
        assert_eq!(soc.cpu_start, None);
        let cores = core_types(0x8152).unwrap();
        assert_eq!(
            cores
                .iter()
                .map(|core| core.cluster_type)
                .collect::<Vec<_>>(),
            b"EPM"
        );
        let m_core = cores.iter().find(|core| core.cluster_type == b'M').unwrap();
        assert_eq!(m_core.midr_part, None);
        assert_eq!(m_core.mpidr_aff2, Some(4));
        assert_eq!(m_core.mpidr(0x102), Some(0x8004_0102));
        assert_eq!(m_core.operating_points, None);
        assert!(m_core.caches.is_none());
        assert_eq!(midr_part(0x8152, b'M'), None);
        assert_eq!(level1_caches(0x8152, b'M'), None);
        assert_eq!(operating_points(0x8152), None);
        // Three core types describe two physical clusters; there is no
        // synthetic extra cluster or E/P fallback for an M PE.
        let processors = [
            Processor {
                cluster_type: b'E',
                reg: 0,
                l2_bytes: Some(8 << 20),
            },
            Processor {
                cluster_type: b'P',
                reg: 0x100,
                l2_bytes: Some(20 << 20),
            },
            Processor {
                cluster_type: b'M',
                reg: 0x102,
                l2_bytes: Some(20 << 20),
            },
        ];
        assert!(topology::validate(&processors).is_ok());
        assert_eq!(
            cpus(0x8152, "Apple M6", &processors),
            Err("Apple M6 cluster type M has no public MIDR part".into())
        );
    }

    #[test]
    fn cpu_binding_rejects_aliasing_affinities_before_synthetic_type_bits() {
        let processors = [
            Processor {
                cluster_type: b'E',
                reg: 0,
                l2_bytes: Some(4 << 20),
            },
            Processor {
                cluster_type: b'P',
                reg: 0,
                l2_bytes: Some(4 << 20),
            },
        ];
        assert_eq!(
            cpus(0x8112, "Apple M2", &processors),
            Err("duplicate CPU affinity reg 0x0".into())
        );
    }
    #[test]
    #[ignore = "requires original 26A434 J314s DT through STELA_TEST_ANS_DT"]
    fn original_j314s_ans_geometry_and_handoff_qualify_independently_of_whole_board() {
        let data = std::fs::read(std::env::var("STELA_TEST_ANS_DT").unwrap()).unwrap();
        assert_eq!(
            crate::sha256(&data),
            "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
        );
        let root = Node::root(&data).unwrap();
        let io = root.child("arm-io").unwrap();
        let ranges = io.ranges().unwrap();
        let translate = |offset| {
            ranges
                .iter()
                .find(|(child, _, size)| (*child..child + size).contains(&offset))
                .map(|(child, parent, _)| parent + (offset - child))
        };
        let security = root
            .child("defaults")
            .unwrap()
            .property("nvme-iboot-sptm-security")
            .is_some();
        let placement = ans_controller(&io, &translate, security).unwrap().unwrap();
        assert_eq!(placement.geometry.handoff_entries(), 253);
        assert_eq!(placement.geometry.ring_entries(), 254);
        assert_eq!(placement.geometry.tag_slots(), 253);
        assert_eq!(placement.interrupts, [1070, 1069, 1072, 1071]);
        assert_eq!(placement.completion_irq, 1613);
        assert_eq!(placement.clock_gates, [481]);
        assert_eq!(placement.power_gates, [71]);
        assert!(placement.sart_exclusive_bounds);
        assert_eq!(placement.vdma, None);
        assert_eq!(placement.sart_idle, placement.nvme.0 + 0x13e8);
        assert_eq!(placement.namespaces.len(), 3);
        assert_eq!(placement.namespaces[2].blocks, 32768);
        assert!(!models(ASC, |_| None)); // No whole-board/other ASC admission.
    }
}
