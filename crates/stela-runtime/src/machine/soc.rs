//! Apple SoCs: a board's chip and PEs from its DeviceTree.
//!
//! The board's DeviceTree gives the SoC: `/chosen` `chip-id` (the identity's
//! ApChipID, which the boot bundle writes there as iBoot does), `/product`
//! `product-soc-name`, and one `/cpus` node per PE with `reg` and
//! `cluster-type`. Each SoC row pairs an ApChipID with the
//! `product-soc-name` its boards' DeviceTrees give in UniversalMac 26A434 and
//! the MIDR_EL1 part number of each cluster type (m1n1 `src/midr.h`
//! `MIDR_PART_<soc>_<core>`). A SoC, cluster type or affinity without that
//! evidence refuses: the M1, M2 and M3 Ultra, the second M3 Max (ApChipID
//! 0x6034), the A18 Pro and the M5 Pro and Max (no `product-soc-name`), and
//! the M6's M cores.
use super::{
    Chip,
    adt::Node,
    caches::{Cache, Caches},
    registers::Identity,
};
use crate::platform::apple::{
    aic::{AIC3_IRQ_CFG, AicLayout},
    aic1::AIC1_EVENT,
    amcc, ans, asc, atc_phy, bridge, cluster, coresight, cpm, cpustart, dart, dpe, energy, fuse,
    i2c, nor, pmu, power, ptd, sart, smc, spi, spmi, wake,
};
use alloc::{format, string::String, vec::Vec};

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
/// `lockdown` is the CONTROL offset of the lockdown registers in each PE's
/// `cpu-impl-reg` and each cluster's `cpm-impl-reg` (`platform::apple::
/// lockdown`), on the SoCs whose SPTM shows them: the T8112's 26A434 SPTM.
/// `operating_points` is each cluster type's core clocks in MHz, lowest
/// first, in `parts` order: the `ecluster_opp` and `pcluster_opp` tables of
/// Linux `arch/arm64/boot/dts/apple/t8112.dtsi`, including the three P
/// states it leaves disabled until CPU deep sleep. The highest paces the
/// cycle counter of Apple's performance monitor (`machine::pmu`), and the
/// bundle publishes them as iBoot's `voltage-states` tables, which the IPSW
/// DeviceTree leaves to it; the SoCs without that evidence have none. `memory_cache` is the memory
/// cache's bytes and ways: the defaults the T8112's 26A434
/// `AppleT8112MemCacheController` driver starts from (`start` assumes 8 MiB
/// before `readCacheSize`; `mccEnableCacheMode` powers at most 16 ways).
/// `clusters` is each cluster type's PMGR registers
/// (`platform::apple::cluster`), in `parts` order, where known, and
/// `aon_fuses` the `/arm-io/pmgr` `reg` index of the always-on eFuses
/// (`platform::apple::fuse`): the T8112's 26A434 `ApplePMGR::
/// readPMGRAONFuseReg` reads `reg[36]`. `cpu_start` is the offset of the
/// CPU start registers (`platform::apple::cpustart`) from `/arm-io/pmgr`
/// `reg[0]`: m1n1 `src/smp.c` `CPU_START_OFF_T8112`. `caches` is each
/// cluster type's caches ([`CoreCaches`]), in `parts` order, where known.
struct Soc {
    chip_id: u32,
    name: &'static str,
    chip: Chip,
    parts: [(u8, u16); 2],
    aic: Option<(&'static str, u64)>,
    dram_base: Option<u64>,
    lockdown: Option<[u64; 2]>,
    operating_points: Option<[&'static [u32]; 2]>,
    memory_cache: Option<(u64, u32)>,
    clusters: Option<[CpuCluster; 2]>,
    aon_fuses: Option<usize>,
    cpu_start: Option<u64>,
    caches: Option<[CoreCaches; 2]>,
    wake_masks: Option<WakeLayout>,
    power_banks: &'static [(usize, power::Kind)],
    dpe_reg: Option<usize>,
    bridge_fields: Option<&'static [&'static [(u64, u32)]]>,
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

/// The T8112's Blizzard and Avalanche cores.
const T8112_CACHES: [CoreCaches; 2] = [
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

const SOCS: [Soc; 14] = [
    Soc {
        chip_id: 0x8103,
        name: "Apple M1",
        chip: Chip::AppleM1,
        parts: [(b'E', 0x022), (b'P', 0x023)],
        aic: Some(("aic,1", AIC1_EVENT)),
        dram_base: Some(0x8_0000_0000),
        lockdown: None,
        operating_points: None,
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: None,
        caches: None,
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    Soc {
        chip_id: 0x6000,
        name: "Apple M1 Pro",
        chip: Chip::AppleM1,
        parts: [(b'E', 0x024), (b'P', 0x025)],
        aic: Some(("aic,2", 0xc000)),
        dram_base: Some(0x100_0000_0000),
        lockdown: None,
        operating_points: None,
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: None,
        caches: None,
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    Soc {
        chip_id: 0x6001,
        name: "Apple M1 Max",
        chip: Chip::AppleM1,
        parts: [(b'E', 0x028), (b'P', 0x029)],
        aic: Some(("aic,2", 0xc000)),
        dram_base: Some(0x100_0000_0000),
        lockdown: None,
        operating_points: None,
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: None,
        caches: None,
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    Soc {
        chip_id: 0x8112,
        name: "Apple M2",
        chip: Chip::AppleM2,
        parts: [(b'E', 0x032), (b'P', 0x033)],
        aic: Some(("aic,2", 0x8000)),
        dram_base: Some(0x8_0000_0000),
        lockdown: Some([0x5000, 0x9000]),
        operating_points: Some([
            &[600, 912, 1284, 1752, 2004, 2256, 2424],
            &[
                660, 924, 1188, 1452, 1704, 1968, 2208, 2400, 2568, 2724, 2868, 2988, 3096, 3204,
                3324, 3408, 3504,
            ],
        ]),
        memory_cache: Some((8 << 20, 16)),
        clusters: Some(T8112_CLUSTERS),
        aon_fuses: Some(36),
        cpu_start: Some(0x34000),
        caches: Some(T8112_CACHES),
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
        chip: Chip::AppleM2,
        parts: [(b'E', 0x034), (b'P', 0x035)],
        aic: Some(("aic,2", 0xc000)),
        dram_base: Some(0x100_0000_0000),
        lockdown: None,
        operating_points: None,
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: None,
        caches: None,
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    Soc {
        chip_id: 0x6021,
        name: "Apple M2 Max",
        chip: Chip::AppleM2,
        parts: [(b'E', 0x038), (b'P', 0x039)],
        aic: Some(("aic,2", 0xc000)),
        dram_base: Some(0x100_0000_0000),
        lockdown: None,
        operating_points: None,
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: None,
        caches: None,
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    Soc {
        chip_id: 0x8122,
        name: "Apple M3",
        chip: Chip::AppleM3,
        parts: [(b'E', 0x042), (b'P', 0x043)],
        aic: Some(("aic,3", 0x40000)),
        dram_base: None,
        lockdown: None,
        operating_points: None,
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: None,
        caches: None,
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    Soc {
        chip_id: 0x6030,
        name: "Apple M3 Pro",
        chip: Chip::AppleM3,
        parts: [(b'E', 0x044), (b'P', 0x045)],
        aic: None,
        dram_base: None,
        lockdown: None,
        operating_points: None,
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: None,
        caches: None,
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    Soc {
        chip_id: 0x6031,
        name: "Apple M3 Max",
        chip: Chip::AppleM3,
        parts: [(b'E', 0x048), (b'P', 0x049)],
        aic: None,
        dram_base: None,
        lockdown: None,
        operating_points: None,
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: None,
        caches: None,
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    Soc {
        chip_id: 0x8132,
        name: "Apple M4",
        chip: Chip::AppleM4,
        parts: [(b'E', 0x052), (b'P', 0x053)],
        aic: None,
        dram_base: None,
        lockdown: None,
        operating_points: None,
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: None,
        caches: None,
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    Soc {
        chip_id: 0x6040,
        name: "Apple M4 Pro",
        chip: Chip::AppleM4,
        parts: [(b'E', 0x054), (b'P', 0x055)],
        aic: None,
        dram_base: None,
        lockdown: None,
        operating_points: None,
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: None,
        caches: None,
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    Soc {
        chip_id: 0x6041,
        name: "Apple M4 Max",
        chip: Chip::AppleM4,
        parts: [(b'E', 0x058), (b'P', 0x059)],
        aic: None,
        dram_base: None,
        lockdown: None,
        operating_points: None,
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: None,
        caches: None,
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    Soc {
        chip_id: 0x8142,
        name: "Apple M5",
        chip: Chip::AppleM5,
        parts: [(b'E', 0x062), (b'P', 0x063)],
        aic: None,
        dram_base: None,
        lockdown: None,
        operating_points: None,
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: None,
        caches: None,
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    Soc {
        chip_id: 0x8152,
        name: "Apple M6",
        chip: Chip::AppleM6,
        parts: [(b'E', 0x072), (b'P', 0x073)],
        aic: None,
        dram_base: None,
        lockdown: None,
        operating_points: None,
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: None,
        caches: None,
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
pub fn operating_points(chip_id: u32) -> Option<[(u8, &'static [u32]); 2]> {
    let soc = SOCS.iter().find(|soc| soc.chip_id == chip_id)?;
    let points = soc.operating_points?;
    Some([(soc.parts[0].0, points[0]), (soc.parts[1].0, points[1])])
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
/// supplies them. MPIDR_EL1 is `reg` with bit 31 RES1 and Aff2 1 on a P core:
/// `reg` is Aff1 (cluster) and Aff0 (core) on every single-die board (the
/// J473AP's cpu0-3 are 0-3 and cpu4-7 0x100-0x103), the cores of P clusters
/// have Aff2 1 (the `cpu@` `reg` of Linux `t8103.dtsi`, `t8112.dtsi`,
/// `t600x-common.dtsi` and `t602x-common.dtsi` and `t8122.dtsi`, which XNU
/// masks off in `ml_get_cpu_number`; inferred for the later SoCs), and U and
/// MT are 0 for a multiprocessor without multithreading (inferred). A `reg`
/// beyond Aff1's first eight clusters, as the multi-die boards use, has no
/// public MPIDR mapping and refuses.
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
    let processors = processors
        .iter()
        .map(|processor| {
            let index = soc
                .parts
                .iter()
                .position(|(cluster_type, _)| *cluster_type == processor.cluster_type);
            let part = index
                .map(|index| u64::from(soc.parts[index].1))
                .ok_or_else(|| {
                    format!(
                        "{} cluster type {} has no public MIDR part",
                        soc.name,
                        char::from(processor.cluster_type)
                    )
                })?;
            if processor.reg & !0x7ff != 0 {
                return Err(format!(
                    "{} cpu reg {:#x} has no public MPIDR mapping",
                    soc.name, processor.reg
                ));
            }
            Ok(Identity {
                midr: 0x61 << 24 | 1 << 20 | 0xf << 16 | part << 4,
                mpidr: 0x8000_0000
                    | u64::from(processor.cluster_type == b'P') << 16
                    | u64::from(processor.reg),
                clock: soc
                    .operating_points
                    .zip(index)
                    .and_then(|(points, index)| points[index].last())
                    .map(|&mhz| u64::from(mhz) * 1_000_000),
                caches: soc
                    .caches
                    .zip(index)
                    .map(|(caches, index)| core_caches(caches[index], processor))
                    .transpose()?,
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
/// The `compatible` of the DART the engine models (`platform::apple::dart`).
pub const DART: &str = "dart,t8110";
/// The `compatible` of a DART child naming one client's stream (its `reg`),
/// which XNU's IODARTMapper binds and clients name as `iommu-parent`.
pub const IOMMU_MAPPER: &str = "iommu-mapper";
/// The `compatible` of the PMGR whose registers `platform::apple::pmgr` and
/// the PMGR family models place (power states, clusters, CPU start, energy,
/// performance counters, wake masks, voltage, DPE, fabric bridges).
pub const PMGR: &str = "pmgr1,t8112";
/// The `compatible` of the AES engine the engine models
/// (`platform::apple::aes`).
pub const AES: &str = "aes,s8000";
/// The `compatible` of the memory cache controller whose registers
/// `platform::apple::amcc`, `dcs` and `ptd` model.
pub const MCC: &str = "mcc,t8112";
/// ASC wrapper and nub shared by multiple coprocessor roles.
pub const ASC: &str = "iop,ascwrap-v4";
pub const RTBUDDY: &str = "iop-nub,rtbuddy-v2";
pub const SART: &str = "sart,coastguard";

/// SPI controller compatible, byte-PIO version 1.
pub const SPI: &str = "spi-1,spimc";
/// Single-wire SPI NOR compatible.
pub const NOR: &str = "nor-flash,spi";
/// Apple CHRP NVRAM service compatible.
pub const NVRAM: &str = "nvram,chrp";
/// GPIO output provider compatible.
pub const GPIO: &str = "gpio,t8101";
/// The Type-C I2C bus: controller, HPM bus manager and CD321x dies.
pub const I2C: &str = "i2c,t8101";
pub const HPM_MANAGER: &str = "usbc,manager";
pub const HPM: &str = "usbc,cd3217";
pub const RETIMER: &str = "atcrt";
pub const ATC_PHY: &str = "atc-phy,t8112";
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
}
/// A child owned by a native coprocessor model and its boot-chain facts.
/// Properties describe model state, never a guest image or a driver patch.
pub struct ChildModel {
    pub compatible: &'static str,
    pub boot_properties: &'static [(&'static str, &'static [u8])],
}
/// Native RTKit is already running before SPTM and uses no ARM firmware
/// memory. RTBuddy::_initConfigEDT (0x4661408..14b4) reads
/// pre-loaded/running/no-firmware-service; getSegmentMap (0x4661d68/1df8)
/// accepts empty segment-ranges/segment-names. _handlePreloadFirmware
/// (0x465a488) consumes that segment map.
const NATIVE_RTKIT: ChildModel = ChildModel {
    compatible: RTBUDDY,
    boot_properties: &[
        ("pre-loaded", b""),
        ("running", b""),
        ("no-firmware-service", b""),
        ("segment-ranges", b""),
        ("segment-names", b""),
    ],
};
/// The SEP's native nub (`iop-nub,sep`, kept so `AppleSEPManager`'s
/// `A7IOPNub` personality binds). Unlike RTBuddy coprocessors, the SEP is not
/// an RTKit preload: it boots through its SEPROM mailbox handshake, so no
/// pre-loaded/running firmware-segment markers are injected.
const SEP_NUB_MODEL: ChildModel = ChildModel {
    compatible: SEP_NUB,
    boot_properties: &[],
};
const ROLE_MODELS: &[ModelClaim] = &[
    ModelClaim {
        compatible: ASC,
        property: ("role", b"ANS2\0"),
        children: &[NATIVE_RTKIT],
    },
    ModelClaim {
        compatible: ASC,
        property: ("role", b"SMC\0"),
        children: &[NATIVE_RTKIT],
    },
    // The SEP: a native model whose ASC wrapper uses `iop-sep,ascwrap-v4` and
    // whose nub is `iop-nub,sep`. Distinguished by its `role = SEP`, so it
    // never collides with the ANS2/SMC `iop,ascwrap-v4` coprocessors.
    ModelClaim {
        compatible: SEP,
        property: ("role", b"SEP\0"),
        children: &[SEP_NUB_MODEL],
    },
    ModelClaim {
        compatible: ASC,
        property: ("role", b"PMP\0"),
        children: &[NATIVE_RTKIT],
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
            claim.compatible == name && property(claim.property.0) == Some(claim.property.1)
        })
        .map_or(&[], |claim| claim.children)
}

/// Whether a compatible and its distinguishing properties name a modeled
/// device. The loader also checks provider and parent/child relationships.
pub fn models<'a>(name: &str, property: impl Fn(&str) -> Option<&'a [u8]>) -> bool {
    [
        UART,
        WATCHDOG,
        DART,
        IOMMU_MAPPER,
        AES,
        MCC,
        PMGR,
        SPI,
        NOR,
        NVRAM,
        SYSCFG,
        GPIO,
        I2C,
        HPM_MANAGER,
        HPM,
        ATC_PHY,
        DOCK_PORT,
        USB_DRD,
        SPMI,
        PMU,
    ]
    .contains(&name)
        || AICS.contains(&name)
        || ROLE_MODELS.iter().any(|claim| {
            claim.compatible == name && property(claim.property.0) == Some(claim.property.1)
        })
}

/// SEP's wrapper and native nub, from the J473AP IPSW DeviceTree. Admitted
/// through [`ROLE_MODELS`] (matched by `role = SEP`), so the loader keeps the
/// sep node and its nub and `AppleSEPManager` binds and boots the native SEP.
pub const SEP: &str = "iop-sep,ascwrap-v4";
pub const SEP_NUB: &str = "iop-nub,sep";

/// The J473AP HDMI display pipeline compatibles the engine models at the
/// AP-facing protocols (`platform::apple::dcp`, `display`): the `dcpext`
/// coprocessor (the shared ASC [`ASC`] with `role` `DCPEXT`), and the
/// register apertures around it. Like [`SEP`], they are deliberately absent
/// from `models()`: the IOMFB RPC shared-region exchange that carries the
/// host-call payloads is recovered but not yet validated against a boot, so
/// admitting DCPEXT would stop the guest at that boundary. The `add_dcpext`
/// and `add_display` placements and this model exist and are tested so the
/// path can be closed and admitted once the exchange is confirmed.
pub const DCPEXT_ROLE: &[u8] = b"DCPEXT\0";
pub const DISPEXT: &str = "dispext0,t8112";
pub const DPTX_PHY: &str = "dptx-phy,t8112";
pub const DISPLAY_CROSSBAR: &str = "display-crossbar,t8112";

/// SEP's DT-placed register banks, four mailbox IRQs, DART stream and optional
/// iBoot SEPFW source extent. The extent is not proof of firmware acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SepDevice {
    pub ranges: [(u64, u64); 2],
    pub irqs: [u32; 4],
    pub iommu: usize,
    pub stream: u32,
    pub firmware: Option<(u64, u64)>,
}

/// The `dcpext` display coprocessor and the register apertures around it,
/// from the J473AP DeviceTree: the ASC wrapper `reg[0]` and four mailbox IRQs,
/// whether the nub is `quiesced`, and each present display aperture's primary
/// `reg[0]` with a stable model name. Admission stays closed (see
/// [`DISPEXT`]); `board` parses it so `add_dcpext`/`add_display` can place the
/// inert model, exactly as SEP is placed while hidden.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DcpController {
    pub wrapper: (u64, u64),
    pub interrupts: [u32; 4],
    pub quiesced: bool,
    pub regions: Vec<(&'static str, (u64, u64))>,
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
    pub stream: u32,
    /// The Type-C connector's `port-number`, shared with its HPM die.
    pub port: u32,
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
    /// CPU CoreSight component bases, for their architectural Software Locks.
    pub coresight: Vec<u64>,
    /// The AMCC lock registers of `/chosen/lock-regs/amcc`, when iBoot
    /// described them.
    pub memory_controller: Option<MemoryController>,
    /// Every `/arm-io` `dart,t8110`.
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
    /// SEP placement if the input tree explicitly keeps it. Production
    /// `models()` admission remains closed while sepOS boot services refuse.
    pub sep: Option<SepDevice>,
    /// DWC3 placements of the visible `usb-drd,t8112` nodes, in DeviceTree order.
    pub usbs: Vec<UsbController>,
    /// `/arm-io/pmgr`'s power-state registers, when the DeviceTree shows a
    /// `pmgr1,t8112`.
    pub power_states: Option<PowerStates>,
    /// `/arm-io/mcc`, when the DeviceTree shows an `mcc,t8112`.
    pub memory_cache: Option<MemoryCache>,
    /// The CPU clusters' PMGR registers, when the DeviceTree shows a
    /// `pmgr1,t8112` and the SoC's are known.
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
    pub windows: Vec<pmu::Window>,
    pub rtc: Option<pmu::Rtc>,
}

/// An SPMI Gen2 controller: bank A (`reg[0]`), bank B (`reg[1]`), its AIC
/// line and its visible PMUs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpmiController {
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

/// Digital PHY placement preserves all ADT views for evidence, but maps the
/// canonical USB2/core regions once. The pipehandler belongs to the same PHY
/// via `usb-drd*/atc-phy-parent`, whose `reg[3]` supplies its aperture; its
/// `reg[4]` is the PHY's own view 1, the core event block
/// (`AppleT8103TypeCPhy::initRegisterSpaces` keeps view n at +0x158 + 16n).
/// Unqualified shared fuse, AXI and analog-only views are not claimed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypecPhy {
    pub views: Vec<(u64, u64)>,
    pub usb2: (u64, u64),
    pub core: (u64, u64),
    pub pipe: (u64, u64),
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
            if node.compatible(ATC_PHY) {
                let reg = node.pairs("reg").ok_or("ATC PHY has no reg pairs")?;
                if reg.len() != 29 {
                    return Err("T8112 ATC PHY requires its 29 register views".into());
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
                    return Err("ATC USB2/core views disagree with the T8112 layout".into());
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
                let (pipe, events) =
                    controller_views.ok_or("ATC PHY has no controller pipehandler view")?;
                let (pipe, events) = (place(pipe)?, place(events)?);
                if duplicate
                    || pipe.1 != atc_phy::WINDOW_BYTES
                    || events != views[1]
                    || events.1 != atc_phy::WINDOW_BYTES
                {
                    return Err("ambiguous or incomplete ATC pipehandler or event view".into());
                }
                phys.push(TypecPhy {
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
    pub physical: u64,
    pub bytes: u64,
    pub pins: u32,
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
    let Some(node) = io.child("gpio").filter(|n| n.compatible(GPIO)) else {
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
        if name == "gpio" || !node.compatible(GPIO) {
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

/// A `gpio,t8101` node's registers, pins, groups and AIC lines.
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
        || pins > 512
        || !(1..=7).contains(&groups)
        || lines.len() != groups as usize
        || node.first_u32("interrupt-parent") != Some(aic)
        || bytes < 0x800 + u64::from(groups) * 0x40
    {
        return Err("unsupported GPIO geometry or interrupt parent".into());
    }
    Ok(GpioBank {
        physical,
        bytes,
        pins,
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
}

/// A `ptd-range` record's bytes: id, first entry, entries, interrupt and a
/// 16-byte name.
const PTD_RANGE: usize = 32;

/// The PMGR power-state registers `/arm-io/pmgr` `ps-regs` and `devices`
/// place (m1n1 `src/pmgr.c`): each block, the span from a `ps-regs` entry's
/// base to its last device's register, and each device's register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerStates {
    pub blocks: Vec<(u64, u64)>,
    pub registers: Vec<u64>,
    /// Device IDs and their physical supply addresses, resolving virtual
    /// devices through both parent IDs without using their names.
    pub devices: Vec<(u16, Vec<u64>)>,
}

/// One numbered TRAD instance. Owners are retained as the DT's eight bytes,
/// not used as application or stream-selection keys. `AppleT8110DART::
/// _dartSetupInstance` (26A434 KC file 0x2f12884..0x2f12918) checks the
/// instance number and maps that numbered `reg` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DartInstance {
    pub physical: u64,
    pub bytes: u64,
    pub number: u32,
    pub owner: [u8; 8],
}

/// A DT DART group, its independently programmed TRAD windows, mapper stream
/// IDs and optional APF. `sid` is a list of u32 SIDs, not one stream per
/// instance or a bitmap (`_dartSetup`, KC 0x2f11e20..0x2f11e38). `remap`
/// contains byte source/destination pairs, with 0/0 padding ignored
/// (0x2f11864..0x2f11938). They describe routing, not permission to bypass
/// the DART. Per-instance DMA selection remains the bus master's contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iommu {
    pub instances: Vec<DartInstance>,
    pub streams: u16,
    pub irq: u32,
    pub mappers: Vec<(u32, u32)>,
    pub apf: Option<(u64, usize)>,
    /// PMGR supply IDs from the DT, resolved through `PowerStates::devices`.
    pub power_gates: Vec<u16>,
    /// A retained DART preserves ordinary state while its supply is gated.
    pub retention: bool,
    pub sids: Vec<u32>,
    pub remap: Vec<(u8, u8)>,
}

/// The AES engine: its block and key-disable register ranges, its
/// `aes-version`, its AIC input, and the [`Board::darts`] index and stream
/// of its `iommu-parent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AesEngine {
    pub ranges: [(u64, u64); 2],
    pub version: u32,
    pub irq: u32,
    pub iommu: usize,
    pub stream: u32,
}

/// ANS2's DT placement. `reg[0]` is the ASC wrapper; `reg[3]` is the
/// NVMe aperture. `iommu-parent` names SART itself, not a DART stream.
/// J473AP: `IOCoastGuardSARTMapper::start` (kernel file 0x2ccada8),
/// `AppleANS2NVMeController::start` (0x3dbb040); neither map is guessed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnsController {
    pub wrapper: (u64, u64),
    pub nvme: (u64, u64),
    pub sart: (u64, u64),
    pub sart_idle: u64,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmcController {
    pub wrapper: (u64, u64),
    pub interrupts: [u16; 4],
    pub watchdog: Option<(u64, u64)>,
    pub region: (u64, u64),
    pub gpio_keys: Vec<u32>,
    pub quiesced: bool,
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
    let nub = node
        .child("iop-pmp-nub")
        .filter(|nub| nub.compatible(RTBUDDY))
        .ok_or("PMP has no RTBuddy v2 nub")?;
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
    let nub = node
        .child("iop-smc-nub")
        .filter(|nub| nub.compatible(RTBUDDY))
        .ok_or("SMC has no RTBuddy v2 nub")?;
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
    // By name: the loader removes a hidden `smc-pmu`'s compatible, but the
    // keys its functions name are the SMC's whatever the AP binds.
    if let Some(pmu) = nub.child("smc-pmu") {
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
        if node.first_u32("gen") != Some(2) {
            return Err("SPMI controller generation other than 2".into());
        }
        let regs = node.pairs("reg").ok_or("SPMI controller has no reg")?;
        let bank = |index: usize| -> Result<(u64, u64), String> {
            let &(offset, bytes) = regs
                .get(index)
                .filter(|(_, bytes)| *bytes == spmi::BANK_BYTES)
                .ok_or("SPMI controller needs two 16 KiB banks")?;
            Ok((
                translate(offset).ok_or("SPMI bank outside arm-io ranges")?,
                bytes,
            ))
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
        let mut pmus = Vec::new();
        for child in node.children().ok_or("SPMI children are malformed")? {
            if child.compatible(PMU) {
                pmus.push(spmi_pmu(&child)?);
            }
        }
        controllers.push(SpmiController {
            banks: [bank(0)?, bank(1)?],
            irq,
            pmus,
        });
    }
    Ok(controllers)
}

/// A PMU's slave ID (`reg` cell 0) and its `info-*` windows: pairs are
/// `<base bytes>`, single cells one byte, except the legacy scratchpad.
fn spmi_pmu(node: &Node<'_>) -> Result<SpmiPmu, String> {
    let sid = node
        .first_u32("reg")
        .and_then(|sid| u8::try_from(sid).ok())
        .filter(|&sid| sid <= 0xf)
        .ok_or("PMU has no four-bit SPMI slave ID")?;
    let address = |value: u32| u16::try_from(value).map_err(|_| "PMU address above 16 bits");
    let pair = |name: &str| -> Result<Option<pmu::Window>, String> {
        match node.cells32(name).as_deref() {
            None => Ok(None),
            Some(&[base, bytes]) => Ok(Some(pmu::Window {
                base: address(base)?,
                bytes: address(bytes)?,
            })),
            Some(_) => Err(format!("PMU {name} is not <base bytes>")),
        }
    };
    let single = |name: &str| node.first_u32(name).map(address).transpose();
    let mut windows = Vec::new();
    for name in ["info-scrpad", "info-fault_log", "info-fault_shadow"] {
        windows.extend(pair(name)?);
    }
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
            let alarm_enable = node
                .first_u32("info-rtc_alarm_ctrl_en_mask")
                .and_then(|mask| u8::try_from(mask).ok())
                .ok_or("PMU RTC has no alarm enable mask")?;
            Some(pmu::Rtc {
                upcount,
                clock_offset: clock_offset.base,
                alarm_control: need("info-rtc_alarm_ctrl")?,
                alarm_enable,
                alarm_offset: need("info-rtc_alarm_offset")?,
                alarm_event: need("info-rtc_alarm_event")?,
                irq_mask: need("info-rtc_irq_mask_offset")?,
            })
        }
    };
    Ok(SpmiPmu { sid, windows, rtc })
}

fn cells_of(value: &[u8]) -> Option<[u32; 4]> {
    let cells = value.as_chunks::<4>().0;
    let cell = |i: usize| cells.get(i).map(|c| u32::from_le_bytes(*c));
    Some([cell(0)?, cell(1)?, cell(2)?, cell(3)?])
}

/// Only explicitly visible ANS2 hardware is placed. Do not preserve all
/// ASC compatibles in the loader: SIO, AOP and others need their own
/// native application protocols before they can be exposed.
fn ans_controller(
    io: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
) -> Result<Option<AnsController>, String> {
    let Some(node) = io.child("ans").filter(|n| n.compatible(ASC)) else {
        return Ok(None);
    };
    if node.property("role") != Some(b"ANS2\0".as_slice()) {
        return Err("/arm-io/ans role is not the modeled ANS2".into());
    }
    if node.property("nvme-linear-sq").is_none()
        || node.first_u32("nvme-queue-entries") != Some(u32::from(ans::TAGS))
    {
        return Err("ANS2 requires linear submission queues with 64 entries".into());
    }
    if !node
        .child("iop-ans-nub")
        .is_some_and(|nub| nub.compatible(RTBUDDY))
    {
        return Err("ANS2 has no RTBuddy v2 nub".into());
    }
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
        wrapper,
        nvme,
        sart,
        sart_idle,
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

const LOCK_GROUP: &str = "amcc-ctrr-a";
/// Lock groups iBoot's map names but leaves empty; one with registers is
/// refused, as the model implements CTRR-A alone.
const EMPTY_GROUPS: [&str; 3] = ["amcc-ctrr-b", "amcc-ctrr-c", "amcc-ctrr-d"];

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

/// The AMCC map of `/chosen/lock-regs/amcc`, or `None` without one.
fn memory_controller(chosen: &Node<'_>) -> Result<Option<MemoryController>, String> {
    let Some(node) = chosen
        .child("lock-regs")
        .and_then(|regs| regs.child("amcc"))
    else {
        return Ok(None);
    };
    const PATH: &str = "/chosen/lock-regs/amcc";
    let number = |name: &str| {
        node.first_u32(name)
            .ok_or_else(|| format!("{PATH} has no {name}"))
    };
    let count = number("aperture-count")? as usize;
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
    if count == 0 || apertures.len() != count {
        return Err(format!(
            "{PATH} aperture-phys-addr does not list aperture-count apertures"
        ));
    }
    let group_path = format!("{PATH}/{LOCK_GROUP}");
    let group = node
        .child(LOCK_GROUP)
        .ok_or_else(|| format!("{PATH} has no {LOCK_GROUP}"))?;
    for name in EMPTY_GROUPS {
        if node
            .child(name)
            .is_some_and(|empty| empty.property("page-size-shift").is_some())
        {
            return Err(format!(
                "{PATH}/{name} is a lock group the AMCC model does not implement"
            ));
        }
    }
    let register = |name: &str, bit: bool| lock_register(&group, &group_path, name, bit);
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
        cache_status: lock_register(&node, PATH, "cache-status", true)?,
        group: amcc::LockGroup {
            page_size_shift: group
                .first_u32("page-size-shift")
                .ok_or_else(|| format!("{group_path} has no page-size-shift"))?,
            lower_limit: register("lower-limit", false)?,
            upper_limit: register("upper-limit", false)?,
            enable: register("enable", true)?,
            write_disable: register("write-disable", true)?,
            lock: register("lock", true)?,
        },
        dram_base,
    };
    if layout.aperture_bytes == 0 || layout.stride == 0 {
        return Err(format!("{PATH} has an empty aperture or plane stride"));
    }
    Ok(Some(MemoryController { apertures, layout }))
}

/// The `name` of an `/arm-io` child, for messages.
fn name_of(node: &Node<'_>) -> String {
    node.property("name")
        .and_then(|name| core::str::from_utf8(name).ok())
        .map_or_else(|| "?".into(), |name| name.trim_end_matches('\0').into())
}

/// Every visible DART group. Multiple numbered TRAD ranges retain separate
/// register state; SMMU and mixed multi-TRAD/APF layouts remain unsupported.
fn iommus(io: &Node<'_>, translate: &dyn Fn(u64) -> Option<u64>) -> Result<Vec<Iommu>, String> {
    let mut found = Vec::new();
    let mut failure = None;
    io.visit(&mut |node| {
        if failure.is_some() || !node.compatible(DART) {
            return;
        }
        match iommu(node, translate) {
            Ok(iommu) => found.push(iommu),
            Err(error) => failure = Some(error),
        }
    })
    .ok_or("DeviceTree walk failed")?;
    match failure {
        Some(error) => Err(error),
        None => Ok(found),
    }
}

fn iommu(node: &Node<'_>, translate: &dyn Fn(u64) -> Option<u64>) -> Result<Iommu, String> {
    let path = format!("/arm-io/{}", name_of(node));
    let reg = node.pairs("reg").unwrap_or_default();
    if node
        .property("reg")
        .is_none_or(|bytes| bytes.len() != reg.len() * 16)
    {
        return Err(format!("{path} has incomplete reg pairs"));
    }
    let descriptors = node.property("instance").unwrap_or_default();
    if descriptors.is_empty()
        || !descriptors.len().is_multiple_of(16)
        || descriptors.len() / 16 != reg.len()
    {
        return Err(format!(
            "{path} instance descriptors do not match its reg entries"
        ));
    }
    let mut instances = Vec::new();
    let mut apf = None;
    for (descriptor, &(offset, bytes)) in descriptors.as_chunks::<16>().0.iter().zip(&reg) {
        let number = u32::from_le_bytes(descriptor[4..8].try_into().expect("instance number"));
        match &descriptor[..4] {
            b"TRAD" if apf.is_none() && number as usize == instances.len() => {
                let physical = translate(offset)
                    .filter(|at| {
                        at.is_multiple_of(dart::DAPF_BYTES)
                            && bytes == dart::DAPF_BYTES
                            && offset.checked_add(bytes - 1).and_then(translate)
                                == at.checked_add(bytes - 1)
                    })
                    .ok_or_else(|| {
                        format!("{path} DART instance is not one translated aligned 16 KiB block")
                    })?;
                if instances
                    .iter()
                    .any(|i: &DartInstance| i.physical == physical)
                {
                    return Err(format!("{path} has duplicate DART register windows"));
                }
                instances.push(DartInstance {
                    physical,
                    bytes,
                    number,
                    owner: descriptor[8..16].try_into().expect("eight-byte owner"),
                });
            }
            b"FPAD" if instances.len() == 1 && number == 0 && apf.is_none() => {
                apf = Some((offset, bytes))
            }
            _ => {
                return Err(format!(
                    "{path} has unsupported instance kinds, numbering or APF topology"
                ));
            }
        }
    }
    if instances.is_empty() {
        return Err(format!("{path} has no TRAD instance"));
    }
    let apf = match apf {
        None => None,
        Some((filter, filter_bytes)) => {
            let at = translate(filter)
                .filter(|at| {
                    at.is_multiple_of(dart::DAPF_BYTES) && filter_bytes == dart::DAPF_BYTES
                })
                .ok_or_else(|| format!("{path} APF is not one aligned 16 KiB block"))?;
            let slices = node
                .first_u32("n-apfs-instance-0")
                .and_then(|count| usize::try_from(count).ok())
                .filter(|&count| count > 0 && count as u64 * 0x40 <= dart::DAPF_BYTES)
                .ok_or_else(|| format!("{path} has no n-apfs-instance-0 slice count"))?;
            Some((at, slices))
        }
    };
    let streams = node
        .first_u32("sid-count")
        .and_then(|count| u16::try_from(count).ok())
        .filter(|&count| count > 0 && count <= 256)
        .ok_or_else(|| format!("{path} has no sid-count of at most 256"))?;
    let irq = node
        .first_u32("interrupts")
        .ok_or_else(|| format!("{path} has no interrupts"))?;
    let power_gates = node.property("power-gates").unwrap_or_default();
    if !power_gates.len().is_multiple_of(4) {
        return Err(format!("{path} power-gates contains a partial device ID"));
    }
    let power_gates = power_gates
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| {
            u16::try_from(u32::from_le_bytes(*word))
                .map_err(|_| format!("{path} power gate exceeds PMGR device ID width"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let retention = node.property("retention").is_some();
    if retention && node.property("no-sleep").is_some() {
        return Err(format!(
            "{path} retention and no-sleep are mutually exclusive"
        ));
    }
    let mut mappers = Vec::new();
    node.visit(&mut |child| {
        if child.compatible(IOMMU_MAPPER)
            && let (Some(phandle), Some(stream)) =
                (child.first_u32("AAPL,phandle"), child.first_u32("reg"))
        {
            mappers.push((phandle, stream));
        }
    })
    .ok_or("DeviceTree walk failed")?;
    let sids = match node.property("sid") {
        None => Vec::new(),
        Some(bytes) if bytes.len().is_multiple_of(4) => node
            .cells32("sid")
            .filter(|sids| sids.iter().all(|sid| *sid < u32::from(streams)))
            .ok_or_else(|| format!("{path} has malformed or out-of-range sid entries"))?,
        Some(_) => return Err(format!("{path} has incomplete sid cells")),
    };
    if sids
        .iter()
        .enumerate()
        .any(|(index, sid)| sids[..index].contains(sid))
    {
        return Err(format!("{path} has duplicate sid entries"));
    }
    let remap_bytes = node.property("remap").unwrap_or_default();
    if !remap_bytes.len().is_multiple_of(4) {
        return Err(format!("{path} remap is not padded byte pairs"));
    }
    let mut remap = Vec::new();
    for pair in remap_bytes.as_chunks::<2>().0 {
        let (source, target) = (pair[0], pair[1]);
        if source == 0 && target == 0 {
            continue;
        }
        if u16::from(source) >= streams
            || u16::from(target) >= streams
            || source == target
            || remap
                .iter()
                .any(|&(s, t)| [source, target].contains(&s) || [source, target].contains(&t))
        {
            return Err(format!(
                "{path} has overlapping or out-of-range remap entries"
            ));
        }
        remap.push((source, target));
    }
    Ok(Iommu {
        instances,
        sids,
        remap,
        streams,
        irq,
        mappers,
        apf,
        power_gates,
        retention,
    })
}

/// Bytes of one `/arm-io/pmgr` `devices` entry: flags, parents, the
/// register index in its `ps-regs` block [10], the block [11], the device
/// id [26..28] and the name [32..48] (m1n1 `struct pmgr_device`).
const PMGR_DEVICE: usize = 48;
/// A `devices` entry with no power-state register (m1n1
/// `PMGR_FLAG_VIRTUAL`).
const PMGR_VIRTUAL: u32 = 0x10;

/// The power-state registers of `/arm-io/pmgr`, if it is a modeled PMGR.
fn power_states(
    io: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
) -> Result<Option<PowerStates>, String> {
    let Some(node) = io.child("pmgr").filter(|node| node.compatible(PMGR)) else {
        return Ok(None);
    };
    const PATH: &str = "/arm-io/pmgr";
    let reg = node.pairs("reg").unwrap_or_default();
    let blocks = node.cells32("ps-regs").unwrap_or_default();
    let devices = node.property("devices").unwrap_or_default();
    if blocks.len() % 3 != 0 || devices.len() % PMGR_DEVICE != 0 {
        return Err(format!("{PATH} ps-regs or devices is not whole entries"));
    }
    let mut spans: Vec<Option<(u64, u64)>> = alloc::vec![None; blocks.len() / 3];
    let mut registers = Vec::new();
    let mut ids = Vec::new();
    for entry in devices.as_chunks::<PMGR_DEVICE>().0 {
        let flags = u32::from_le_bytes(entry[..4].try_into().expect("4 bytes"));
        let id = u16::from_le_bytes(entry[26..28].try_into().expect("device ID"));
        let parents = [
            u16::from_le_bytes(entry[4..6].try_into().expect("parent ID")),
            u16::from_le_bytes(entry[6..8].try_into().expect("parent ID")),
        ];
        if ids.iter().any(|&(old, _, _)| old == id) {
            return Err("PMGR has duplicate device IDs".into());
        }
        if flags & PMGR_VIRTUAL != 0 {
            ids.push((id, None, parents));
            continue;
        }
        let (index, block) = (u64::from(entry[10]), usize::from(entry[11]));
        let base = blocks
            .get(block * 3..block * 3 + 2)
            .and_then(|cells| {
                let (range, _) = reg.get(cells[0] as usize)?;
                Some(translate(*range)? + u64::from(cells[1]))
            })
            .ok_or_else(|| format!("{PATH} device names ps-regs block {block} outside reg"))?;
        let address = base + index * 8;
        ids.push((id, Some(address), parents));
        let span = spans[block].get_or_insert((base, 0));
        span.1 = span.1.max(address + 4 - base);
        if !registers.contains(&address) {
            registers.push(address);
        }
    }
    registers.sort_unstable();
    Ok(Some(PowerStates {
        blocks: spans.into_iter().flatten().collect(),
        registers,
        devices: ids
            .iter()
            .map(|&(id, _, _)| Ok((id, resolve_supplies(id, &ids, &mut Vec::new())?)))
            .collect::<Result<Vec<_>, String>>()?,
    }))
}

/// Virtual PMGR devices have no register; their nonzero parent IDs select
/// the physical supplies (`devices` parents at bytes 4..8, m1n1 pmgr_device).
/// Reject cycles/missing parents instead of silently dropping a dependency.
fn resolve_supplies(
    id: u16,
    devices: &[(u16, Option<u64>, [u16; 2])],
    visiting: &mut Vec<u16>,
) -> Result<Vec<u64>, String> {
    if visiting.contains(&id) {
        return Err("PMGR virtual supply graph contains a cycle".into());
    }
    let (_, address, parents) = devices
        .iter()
        .find(|(device, _, _)| *device == id)
        .ok_or("PMGR virtual supply has an absent parent")?;
    if let Some(address) = address {
        return Ok(alloc::vec![*address]);
    }
    visiting.push(id);
    let mut supplies = Vec::new();
    for &parent in parents.iter().filter(|&&parent| parent != 0) {
        for address in resolve_supplies(parent, devices, visiting)? {
            if !supplies.contains(&address) {
                supplies.push(address);
            }
        }
    }
    visiting.pop();
    Ok(supplies)
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

/// The DT region can contain several components. This model places only
/// the first component's described management pair, within that region.
fn place_coresight(pairs: &[(u64, u64)]) -> Result<u64, String> {
    let [(physical, bytes)] = pairs else {
        return Err("CPU CoreSight map must describe one component".into());
    };
    if *bytes < coresight::STATUS + 4
        || !physical.is_multiple_of(coresight::BYTES)
        || physical.checked_add(*bytes).is_none()
    {
        return Err("CPU CoreSight component is empty, unaligned or overflows its page".into());
    }
    Ok(*physical)
}

/// The SoC's CPU clusters and always-on eFuses, when the DeviceTree shows a
/// `pmgr1,t8112` whose `reg` places each cluster's register window and
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
    let Some(node) = io.child("pmgr").filter(|node| node.compatible(PMGR)) else {
        return Ok(none);
    };
    let Some(soc) = SOCS.iter().find(|soc| soc.chip_id == chip_id) else {
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
    for entry in data.as_chunks::<RECORD>().0 {
        let source = u32::from_le_bytes(entry[..4].try_into().expect("4 bytes"));
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
    })
}

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
    let ranges = records
        .as_chunks::<PTD_RANGE>()
        .0
        .iter()
        .map(|record| {
            let word = |at: usize| u32::from_le_bytes(record[at..at + 4].try_into().expect("4"));
            let name = record[16..]
                .split(|&byte| byte == 0)
                .next()
                .unwrap_or_default();
            ptd::Range {
                id: word(0),
                start: word(4),
                count: word(8),
                name: String::from_utf8_lossy(name).into_owned(),
            }
        })
        .collect();
    let ptd = PtdBank {
        physical: bank.0,
        ranges,
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
    let parent = number("iommu-parent")?;
    let (iommu, stream) = darts
        .iter()
        .enumerate()
        .find_map(|(index, dart)| {
            dart.mappers
                .iter()
                .find(|(phandle, _)| *phandle == parent)
                .map(|&(_, stream)| (index, stream))
        })
        .ok_or_else(|| format!("{PATH} iommu-parent {parent:#x} is no modeled DART's mapper"))?;
    if darts[iommu].instances.len() != 1 {
        return Err(format!(
            "{PATH} DMA instance routing is undetermined for a multi-instance DART"
        ));
    }
    Ok(Some(AesEngine {
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
    let parent = node
        .first_u32("iommu-parent")
        .ok_or_else(|| err("has no iommu-parent"))?;
    let mut matching = darts.iter().enumerate().flat_map(|(index, dart)| {
        dart.mappers
            .iter()
            .filter(move |(phandle, _)| *phandle == parent)
            .map(move |&(_, stream)| (index, stream))
    });
    let (iommu, stream) = matching
        .next()
        .ok_or_else(|| err("iommu-parent is no modeled DART mapper"))?;
    if matching.next().is_some() {
        return Err(err("iommu-parent is ambiguous"));
    }
    if stream >= u32::from(darts[iommu].streams) {
        return Err(err("mapper stream exceeds DART capacity"));
    }
    let port = node
        .first_u32("port-number")
        .filter(|&port| port != 0)
        .ok_or_else(|| err("has no Type-C port number"))?;
    Ok(UsbController {
        ranges,
        irqs,
        iommu,
        stream,
        port,
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
        .first_u32("iommu-parent")
        .ok_or_else(|| format!("{PATH} has no iommu-parent"))?;
    let (iommu, stream) = darts
        .iter()
        .enumerate()
        .find_map(|(index, dart)| {
            dart.mappers
                .iter()
                .find(|(phandle, _)| *phandle == parent)
                .map(|&(_, stream)| (index, stream))
        })
        .ok_or_else(|| format!("{PATH} iommu-parent is no modeled DART's mapper"))?;
    if stream != 0 || darts[iommu].streams != 1 || darts[iommu].instances.len() != 1 {
        return Err(format!("{PATH} requires dart-sep's single stream 0"));
    }
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
    Ok(Some(SepDevice {
        ranges: [place(first)?, place(second)?],
        irqs,
        iommu,
        stream,
        firmware,
    }))
}

/// The `dcpext` coprocessor and the display apertures around it, when the
/// DeviceTree shows a `dcpext` with `role` `DCPEXT`. Admission is closed, so
/// this is placed hidden (like SEP); the parse validates the shape the model
/// needs and refuses a tree that does not match rather than guessing.
fn dcp_device(
    io: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
) -> Result<Option<DcpController>, String> {
    let Some(node) = io
        .child("dcpext")
        .filter(|n| n.compatible(ASC) && n.property("role") == Some(DCPEXT_ROLE))
    else {
        return Ok(None);
    };
    const PATH: &str = "/arm-io/dcpext";
    let place = |offset: u64, bytes: u64| -> Result<(u64, u64), String> {
        if bytes == 0 {
            return Err(format!("{PATH} aperture is empty"));
        }
        let physical =
            translate(offset).ok_or_else(|| format!("{PATH} lies outside /arm-io ranges"))?;
        let last = offset.checked_add(bytes - 1).and_then(translate);
        if last != physical.checked_add(bytes - 1) {
            return Err(format!(
                "{PATH} register extent lies outside /arm-io ranges"
            ));
        }
        Ok((physical, bytes))
    };
    let reg = node.pairs("reg").unwrap_or_default();
    let &(wrapper_off, wrapper_bytes) = reg
        .first()
        .ok_or_else(|| format!("{PATH} has no register range"))?;
    if wrapper_bytes < crate::platform::apple::asc::WRAPPER_BYTES {
        return Err(format!("{PATH} has an incomplete ASC aperture"));
    }
    let quiesced = node
        .child("iop-dcpext-nub")
        .is_some_and(|nub| nub.property("quiesced").is_some());
    let irqs: [u32; 4] = node
        .cells32("interrupts")
        .unwrap_or_default()
        .get(..4)
        .and_then(|cells| cells.try_into().ok())
        .ok_or_else(|| format!("{PATH} requires four mailbox interrupts"))?;
    if irqs.iter().any(|&irq| u16::try_from(irq).is_err()) {
        return Err(format!(
            "{PATH} mailbox interrupt is outside the AIC encoding"
        ));
    }
    // Each present display aperture's primary reg[0], by DeviceTree node name
    // and the compatible the model keys on.
    let mut regions = Vec::new();
    for (name, model, model_name) in [
        ("dispext0", DISPEXT, "dispext0"),
        ("dptx-phy", DPTX_PHY, "dptx-phy"),
        ("display-crossbar0", DISPLAY_CROSSBAR, "display-crossbar0"),
    ] {
        if let Some(child) = io.child(name).filter(|n| n.compatible(model)) {
            let &(offset, bytes) = child
                .pairs("reg")
                .unwrap_or_default()
                .first()
                .ok_or_else(|| format!("/arm-io/{name} has no register range"))?;
            regions.push((model_name, place(offset, bytes)?));
        }
    }
    Ok(Some(DcpController {
        wrapper: place(wrapper_off, wrapper_bytes)?,
        interrupts: irqs,
        quiesced,
        regions,
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
                    debug_components.push(node.pairs("coresight-reg"));
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
        .map(|pairs| place_coresight(&pairs.ok_or("CPU CoreSight reg contains partial records")?))
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
    let memory_controller =
        memory_controller(&root.child("chosen").ok_or("DeviceTree has no /chosen")?)?;
    let gpio = gpio_bank(&io, &translate, phandle)?;
    let aux_gpios = aux_gpio_banks(&root, &io, &translate, phandle)?;
    let (i2cs, typec_phys) = typec_devices(&io, &translate, phandle, gpio.as_ref())?;
    let darts = iommus(&io, &translate)?;
    let aes = aes_engine(&io, &translate, &darts)?;
    let ans = ans_controller(&io, &translate)?;
    let smc = smc_controller(&root, &io, &translate)?;
    let pmp = pmp_controller(&io, &translate)?;
    let sep = sep_device(&root, &io, &translate, &darts)?;
    let usbs = usb_controllers(&io, &translate, &darts)?;
    let power_states = power_states(&io, &translate)?;
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
    let spi_nor = spi_nor(&root, &io, &translate, phandle, gpio.as_ref())?;
    let spmis = spmi_controllers(&io, &translate, phandle)?;
    let dcp = dcp_device(&io, &translate)?;
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
        coresight,
        memory_controller,
        darts,
        aes,
        ans,
        smc,
        pmp,
        sep,
        usbs,
        power_states,
        memory_cache,
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
    fn coresight_lock_uses_the_dt_component_base_and_stays_inside_its_region() {
        assert_eq!(
            place_coresight(&[(0x2_1001_0000, 0x300c8)]).unwrap(),
            0x2_1001_0000
        );
        for pairs in [
            vec![],
            vec![(0x2_1001_0001, 0x3c8)],
            vec![(0, 0)],
            vec![(0, 0x3c8)],
            vec![(u64::MAX - 0xfff, 4)],
        ] {
            assert!(place_coresight(&pairs).is_err());
        }
    }

    #[test]
    fn virtual_supply_graph_expands_both_parents_and_rejects_missing_nodes_and_cycles() {
        let physical = 0x2_3b70_0100;
        let graph = [
            (1, Some(physical), [0, 0]),
            (2, Some(physical + 8), [0, 0]),
            (0x212, None, [1, 2]),
            (4, None, [0x212, 1]),
        ];
        assert_eq!(
            resolve_supplies(4, &graph, &mut Vec::new()).unwrap(),
            vec![physical, physical + 8]
        );
        assert!(resolve_supplies(9, &graph, &mut Vec::new()).is_err());
        assert!(
            resolve_supplies(1, &[(1, None, [2, 0]), (2, None, [1, 0])], &mut Vec::new()).is_err()
        );
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
        let tree = |version: u32, parent: u32, interrupt_index: u32| {
            let nub = encode(
                &[("name", &z("iop-ans-nub")), ("compatible", &z(RTBUDDY))],
                &[],
            );
            let ans = encode(
                &[
                    ("name", &z("ans")),
                    ("compatible", &z(ASC)),
                    ("role", &z("ANS2")),
                    (
                        "reg",
                        &pairs(&[
                            (0x7740_0000, 0x6c000),
                            (0x7705_0000, 0x4000),
                            (0, 0),
                            (0x7bcc_0000, 0x60000),
                        ]),
                    ),
                    ("nvme-linear-sq", &[]),
                    ("nvme-queue-entries", &cells(&[64])),
                    ("nvme-interrupt-idx", &cells(&[interrupt_index])),
                    ("interrupts", &cells(&[718, 717, 720, 719, 724])),
                    ("iommu-parent", &cells(&[parent])),
                    ("namespaces", &cells(&[1, 1, 0, 2, 8, 768, 3, 13, 32768])),
                    ("clock-gates", &cells(&[125])),
                    ("power-gates", &cells(&[125])),
                ],
                &[nub],
            );
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
        let bytes = tree(3, 0x8e, 4);
        let io = Node::root(&bytes).unwrap();
        let placed = ans_controller(&io, &|offset| Some(0x2_0000_0000 + offset))
            .unwrap()
            .unwrap();
        assert_eq!(placed.wrapper, (0x2_7740_0000, 0x6c000));
        assert_eq!(placed.nvme, (0x2_7bcc_0000, 0x60000));
        assert_eq!(placed.sart, (0x2_7bc5_0000, 0xc000));
        assert_eq!(placed.sart_idle, 0x2_7bcc_13e8);
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
        for bytes in [
            tree(2, 0x8e, 4),
            tree(3, 0x99, 4),
            tree(3, 0x8e, 3),
            tree(3, 0x8e, 5),
        ] {
            assert!(ans_controller(&Node::root(&bytes).unwrap(), &|a| Some(a)).is_err());
        }
        assert!(ans_controller(&io, &|_| None).is_err());
        // These compatibles are shared by other hardware. The partial ANS
        // controller cannot authorize advertising every ASC/RTBuddy/SART.
        assert!(!models(ASC, |_| None));
        assert!(!models(RTBUDDY, |_| None));
        assert!(!models(SART, |_| None));
    }

    /// The J473AP SMC subtree: its wrapper and watchdog banks, the nub's
    /// shared-page region and the `pKW4` functions other nodes route
    /// through `smc-pmu`.
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
                &[("name", &z("smc-pmu")), ("AAPL,phandle", &cells(&[0x91]))],
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
        // Sorted; `keyW` is not a GPIO write.
        assert_eq!(
            placed.gpio_keys,
            [smc::code(b"gP09"), smc::code(b"gP0d"), smc::code(b"gP16")]
        );
        let small = tree(0x1000);
        let root = Node::root(&small).unwrap();
        let io = root.child("arm-io").unwrap();
        assert!(smc_controller(&root, &io, &translate).is_err());
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
                    ("info-rtc_alarm_offset", &cells(&[0xf808])),
                    ("info-rtc_alarm_event", &cells(&[0xf80c])),
                    ("info-rtc_irq_mask_offset", &cells(&[0xf80e])),
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
        let window = |base, bytes| pmu::Window { base, bytes };
        assert_eq!(
            pmu.windows,
            [
                window(0x8000, 0x2800),
                window(0xfa00, 5),
                window(0xf700, pmu::LEGACY_SCRATCH_BYTES),
                window(0xf801, 1),
            ]
        );
        let rtc = pmu.rtc.unwrap();
        assert_eq!(
            (rtc.upcount, rtc.clock_offset, rtc.alarm_enable),
            (0xf802, 0xf900, 0x40)
        );
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
                caches: None,
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
        // M2 Ultra: two dies, no public part numbers.
        assert_eq!(
            cpus(0x6022, "Apple M2 Ultra", &one),
            Err("ApChipID 0x6022 (Apple M2 Ultra) has no public MIDR part".into())
        );
        assert!(cpus(0x8112, "Apple M2 Pro", &one).is_err());
        assert!(cpus(0x8112, "Apple M2", &[]).is_err());
        // The M6's M cores and a second die's affinity.
        assert_eq!(
            cpus(0x8152, "Apple M6", &layout_of(&[(b'M', 0)])),
            Err("Apple M6 cluster type M has no public MIDR part".into())
        );
        assert!(cpus(0x6031, "Apple M3 Max", &layout_of(&[(b'P', 0x800)])).is_err());
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
        assert_eq!(found.coresight, vec![0x2_1001_0000, 0x2_1101_0000]);
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
        // No SPTM shows the M1's lockdown registers.
        assert!(m1.lockdown.is_empty());
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
                instances: vec![DartInstance {
                    physical: 0x2_3500_4000,
                    bytes: 0x4000,
                    number: 0,
                    owner: *b"DART\0\0\0\0"
                }],
                sids: vec![],
                remap: vec![],
                streams: 16,
                irq: 0x301,
                mappers: vec![(0x89, 0), (0x8a, 1)],
                apf: None,
                power_gates: Vec::new(),
                retention: false,
            }]
        );
        assert_eq!(
            found.aes,
            Some(AesEngine {
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
            physical: 0x23c100000,
            bytes: 0x100000,
            pins: 213,
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
        let phy = |compatible: &[u8]| {
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
        // The manager's line must be a visible AP GPIO pin.
        assert!(place(&io, 0x63, None).is_err());
        assert_eq!(phys[0].usb2, (0x382a90000, 0x4000));
        assert_eq!(phys[0].core, (0x383000000, atc_phy::CORE_BYTES));
        assert_eq!(phys[0].pipe, (0x382a84000, 0x4000));
        assert_eq!(phys[0].events, (0x382800000, 0x4000));
        assert_eq!(phys[0].views, views);
        assert!(place(&io, 0x99, Some(&gpio)).is_err());
        assert!(typec_devices(&Node::root(&io).unwrap(), &|_| None, 0x63, Some(&gpio)).is_err());
        let io = encode(&[("name", b"arm-io\0")], &[phy(b"atc-phy,t8112\0")]);
        assert!(place(&io, 0x63, Some(&gpio)).is_err());
        for compatible in [I2C, HPM_MANAGER, HPM, ATC_PHY] {
            assert!(models(compatible, |_| None));
        }
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
                    owner: *b"DARTLLT\0"
                },
                DartInstance {
                    physical: 0x382f80000,
                    bytes: 0x4000,
                    number: 1,
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
        let found = power_states(&Node::root(&bytes).unwrap(), &|a| Some(a + 0x2_0000_0000))
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
        assert_eq!(
            found.power_states,
            Some(PowerStates {
                blocks: vec![(0x2_3d28_4000, 0x14), (0x2_3b70_0000, 0x1c)],
                registers: vec![0x2_3b70_0000, 0x2_3b70_0018, 0x2_3d28_4010],
                devices: vec![
                    (1, vec![0x2_3b70_0000]),
                    (4, vec![0x2_3b70_0018]),
                    (8, vec![0x2_3b70_0000]),
                    (3, vec![0x2_3d28_4010])
                ],
            })
        );
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
        let source = |id: u32| {
            let mut entry = [0u8; 36];
            entry[..4].copy_from_slice(&id.to_le_bytes());
            entry
        };
        let records = [source(14), source(157)].concat();
        let tree = encode(&[("ap-wake-sources", &records)], &[]);
        let found = wake_bank(&Node::root(&tree).unwrap(), &reg, layout).unwrap();
        assert_eq!(
            found,
            WakeBank {
                physical: 0x2_3d00_4008,
                valid: layout.valid,
                sources: vec![14, 157]
            }
        );
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
                cache_status: amcc::Register {
                    offset: 0x424,
                    mask: 1,
                    value: 1,
                },
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
                    enable: amcc::Register {
                        offset: 0x688,
                        mask: 1,
                        value: 1,
                    },
                    write_disable: amcc::Register {
                        offset: 0x7f0,
                        mask: 1,
                        value: 1,
                    },
                    lock: amcc::Register {
                        offset: 0x68c,
                        mask: 1,
                        value: 1,
                    },
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
                stream: 0,
                firmware: None,
            })
        );
        assert_eq!(found.darts[0].instances[0].physical, 0x25d2c0000);
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
            let nub_props: Vec<(&str, &[u8])> = if quiesced {
                vec![("name", b"iop-dcpext-nub\0"), ("quiesced", &[])]
            } else {
                vec![("name", b"iop-dcpext-nub\0")]
            };
            let nub = encode(&nub_props, &[]);
            let dcpext = encode(
                &[
                    ("name", &z("dcpext")),
                    ("compatible", &z(ASC)),
                    ("role", role),
                    ("interrupts", &words(&irqs)),
                    ("reg", &pairs(&[0x71c0_0000, 0x6c000, 0x7185_0000, 0x4000])),
                ],
                &[nub],
            );
            let mut children = alloc::vec![dcpext];
            if with_regions {
                children.push(encode(
                    &[
                        ("name", &z("dispext0")),
                        ("compatible", &z(DISPEXT)),
                        ("reg", &pairs(&[0x7000_0000, 0x61c000])),
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
        assert_eq!(
            dcp.regions,
            alloc::vec![
                ("dispext0", (0x2_7000_0000, 0x61c000)),
                ("dptx-phy", (0x2_3c54_0000, 0xc000)),
                ("display-crossbar0", (0x2_3c00_0000, 0x4000)),
            ]
        );
        // A non-quiesced nub and an absent set of apertures still parse.
        let bare = board(&build(DCPEXT_ROLE, false, false))
            .unwrap()
            .dcp
            .unwrap();
        assert!(!bare.quiesced);
        assert!(bare.regions.is_empty());
        // Admission stays closed, and a wrong role is not a DCP.
        assert!(!models(ASC, |key| (key == "role").then_some(DCPEXT_ROLE)));
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
                stream: 1,
                port: 1,
            }]
        );
        assert_eq!(found.darts[0].instances[0].physical, 0x382f00000);
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
}
