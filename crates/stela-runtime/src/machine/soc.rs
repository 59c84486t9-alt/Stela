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
    amcc, cluster, cpustart, dart, fuse, ptd,
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
/// The `compatible` of the PMGR whose power-state registers
/// `platform::apple::pmgr` models. The engine places them when a tree shows
/// it; until the rest of the PMGR is modeled, bundles hide it.
pub const PMGR: &str = "pmgr1,t8112";
/// The `compatible` of the AES engine the engine models
/// (`platform::apple::aes`).
pub const AES: &str = "aes,s8000";
/// The `compatible` of the memory cache controller whose registers
/// `platform::apple::amcc`, `dcs` and `ptd` model.
pub const MCC: &str = "mcc,t8112";

/// Whether the engine models a device `compatible` with `name`: the devices a
/// [`Board`] places. A boot bundle presents no other device to the guest.
pub fn models(name: &str) -> bool {
    [UART, WATCHDOG, DART, IOMMU_MAPPER, AES, MCC].contains(&name) || AICS.contains(&name)
}

/// Everything the engine models of a board, from its DeviceTree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Board {
    pub cpus: Cpus,
    /// `/arm-io/uart0`, a `uart-1,samsung`.
    pub uart: Device,
    /// `/arm-io/wdt`, a `wdt,s5l8960x`.
    pub watchdog: Device,
    /// `/arm-io/aic`, an `aic,1`, `aic,2` or `aic,3`.
    pub aic: InterruptController,
    /// Every PE's `cpu-impl-reg` and every cluster's `cpm-impl-reg`, once
    /// each, on a SoC whose lockdown offsets are known; none otherwise.
    pub lockdown: Vec<LockdownBlock>,
    /// The AMCC lock registers of `/chosen/lock-regs/amcc`, when iBoot
    /// described them.
    pub memory_controller: Option<MemoryController>,
    /// Every `/arm-io` `dart,t8110`.
    pub darts: Vec<Iommu>,
    /// `/arm-io/aes`, an `aes,s8000`, when the DeviceTree keeps it.
    pub aes: Option<AesEngine>,
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
    /// The CPU start registers' guest PA and the clusters they start, under
    /// the same conditions.
    pub cpu_start: Option<(u64, u8)>,
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
}

/// A `dart,t8110`: its one DART register range (ADT `instance` `TRAD`), its
/// `sid-count`, its AIC input, the `AAPL,phandle` and stream (`reg`) of
/// each `iommu-mapper` child, and its address permission filter (`instance`
/// `FPAD`, the second range) with `n-apfs-instance-0` slices, if it has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iommu {
    pub physical: u64,
    pub bytes: u64,
    pub streams: u16,
    pub irq: u32,
    pub mappers: Vec<(u32, u32)>,
    pub apf: Option<(u64, usize)>,
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

/// Every `/arm-io` child that is a modeled DART. Each must have exactly one
/// register range, a DART (`instance` `TRAD`): DAPF and SMMU ranges are not
/// modeled.
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
    let instances = node.property("instance").unwrap_or_default();
    // One 16-byte descriptor per range: its kind, instance number and owner.
    let kinds: Vec<&[u8]> = instances.chunks(16).map(|d| &d[..8]).collect();
    let (&(offset, bytes), apf) = match (reg.as_slice(), kinds.as_slice()) {
        ([dart], [b"TRAD\0\0\0\0"]) => (dart, None),
        ([dart, filter], [b"TRAD\0\0\0\0", b"FPAD\0\0\0\0"]) => (dart, Some(*filter)),
        _ => {
            return Err(format!(
                "{path} is not one DART instance, alone or with its APF"
            ));
        }
    };
    let physical =
        translate(offset).ok_or_else(|| format!("{path} lies outside /arm-io ranges"))?;
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
        .filter(|&count| count <= 256)
        .ok_or_else(|| format!("{path} has no sid-count of at most 256"))?;
    let irq = node
        .first_u32("interrupts")
        .ok_or_else(|| format!("{path} has no interrupts"))?;
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
    Ok(Iommu {
        physical,
        bytes,
        streams,
        irq,
        mappers,
        apf,
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
    for entry in devices.as_chunks::<PMGR_DEVICE>().0 {
        let flags = u32::from_le_bytes(entry[..4].try_into().expect("4 bytes"));
        if flags & PMGR_VIRTUAL != 0 {
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
    }))
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
    Ok(PmgrRegisters {
        clusters,
        aon_fuses: fuses,
        cpu_start,
    })
}

/// The PMGR registers the machine models besides its power states.
struct PmgrRegisters {
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
    Ok(Some(AesEngine {
        ranges: [place(block)?, place(key_disable)?],
        version: number("aes-version")?,
        irq: number("interrupts")?,
        iommu,
        stream,
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
    root.child("cpus")
        .ok_or("DeviceTree has no /cpus")?
        .visit(&mut |node| {
            if let Some(cluster_type) = node.property("cluster-type") {
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
    let darts = iommus(&io, &translate)?;
    let aes = aes_engine(&io, &translate, &darts)?;
    let power_states = power_states(&io, &translate)?;
    let PmgrRegisters {
        clusters,
        aon_fuses,
        cpu_start,
    } = pmgr_registers(&io, &translate, chip_id, &cpus.processors)?;
    let memory_cache = memory_cache(&io, &translate, chip_id, memory_controller.as_ref())?;
    Ok(Board {
        cpus,
        uart,
        watchdog,
        lockdown,
        memory_controller,
        darts,
        aes,
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
                ("ranges", &u64s(&[0, 0x2_0000_0000, 0x1_0000_0000])),
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
                physical: 0x2_3500_4000,
                bytes: 0x4000,
                streams: 16,
                irq: 0x301,
                mappers: vec![(0x89, 0), (0x8a, 1)],
                apf: None,
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
            Err("/arm-io/dart-sio is not one DART instance, alone or with its APF".into())
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
        reg[5] = [0x10e2_0000, 0x2000];
        reg[8] = [0x10e5_0000, 0xe8_1000];
        reg[14] = [0x11e2_0000, 0x2000];
        reg[17] = [0x11e5_0000, 0xe8_1000];
        reg[36] = [0x3d2c_8000, 0x4000];
        let reg = reg.concat();
        let pmgr_with = |reg: &[u64]| {
            encode(
                &[
                    ("name", &z("pmgr")),
                    ("compatible", &z(PMGR)),
                    ("reg", &u64s(reg)),
                    ("ps-regs", &u32s(&[1, 0x4000, 0x3ff, 0, 0, 0x3ff])),
                    ("devices", &devices),
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
        let pmgr = encode(
            &[
                ("name", &z("pmgr")),
                ("compatible", &z(PMGR)),
                ("reg", &u64s(&reg)),
                ("ps-regs", &u32s(&[1, 0x4000, 0x3ff, 0, 0, 0x3ff])),
                ("devices", &devices),
            ],
            &[],
        );
        let found = board(&tree_with_io(0x8112, "Apple M2", MODELED, &[], &[pmgr])).unwrap();
        assert_eq!(found.clusters, T8112_CLUSTERS.to_vec());
        assert_eq!(found.aon_fuses, Some((0x2_3d2c_8000, 0x4000)));
        assert_eq!(
            found.power_states,
            Some(PowerStates {
                blocks: vec![(0x2_3d28_4000, 0x14), (0x2_3b70_0000, 0x1c)],
                registers: vec![0x2_3b70_0000, 0x2_3b70_0018, 0x2_3d28_4010],
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
}
