//! Source-backed CPU identities, cache geometry, and DeviceTree CPU admission.
use super::{KernelLimits, topology};
use crate::wake;
use alloc::{format, string::String, vec::Vec};
use stela_contracts::{
    Chip,
    adt::Node,
    caches::{Cache, Caches},
    identity::Identity,
};
pub(super) mod rows;
use rows::SOCS;

/// One SoC row: ApChipID, `product-soc-name`, chip, the MIDR_EL1 part
/// number of each `cluster-type`, and the `aic` node's `compatible` with the
/// offset of its event register from its `reg`: for the M1's `aic,1` the
/// event register in its core block (Linux `AIC_EVENT`, 0x2004), and for an
/// `aic,2` or `aic,3` the separate block whose offset iBoot writes to the
/// ADT's `aic-iack-offset`, as Linux `arch/arm64/boot/dts/apple` places it
/// (0x8000 in `t8112.dtsi`, 0xc000 in `t600x-die0.dtsi` and
/// `t602x-die0.dtsi`, 0x40000 in `t8122.dtsi`, `t6030.dtsi`,
/// `t6031-die0.dtsi` and `t8132.dtsi`) and [`rows::AIC3_EVENT`] states for the
/// later SoCs. `dram_base` is where the SoC places DRAM: the constant every
/// 26A434 iBoot of the SoC writes to `/chosen dram-base` (payload file
/// offsets: T8103 J274 0x15950 and T8112 J473 0x23904, 0x8_0000_0000; T6000
/// J314s 0x23e78, T8122 J433 0x2479c, A18 Pro J700 0x20d60, M5 J704 0x24168
/// and M6 J873g 0x22e38, 0x100_0000_0000, as on every other SoC;
/// `docs/research/apple-socs.md#dram-base`). It is also the base of carveout
/// 1 in each iBoot's carveout table, the `memory@` node of Linux
/// `t8103-jxxx.dtsi`, `t8112-jxxx.dtsi`, `t600x-j314-j316.dtsi` and
/// `t600x-j375.dtsi`, and the M3 and later boards' `/arm-io/mcc dram-base`
/// ([`board_dram_base`]).
/// `pmgr` is the `compatible` of the SoC's `/arm-io/pmgr` in its boards'
/// 26A434 DeviceTrees. Power-state
/// ownership and optional register-family validation are independent.
/// `lockdown` is
/// the CONTROL offset of the lockdown registers in each PE's `cpu-impl-reg`
/// and each cluster's `cpm-impl-reg` (`platform::apple::lockdown`), on the
/// SoCs whose SPTM writes them ([`rows::LOCKDOWN`]); the M4 and later SPTMs write
/// none, so their boards map no lockdown block.
/// `operating_points` is each cluster type's core clocks in MHz, lowest
/// first, in each [`CoreType`]: the opp tables of Linux
/// `arch/arm64/boot/dts/apple/t8112.dtsi` (`ecluster_opp`, `pcluster_opp`)
/// and the other files [`rows::M1_POINTS`] names, including the P states they
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
/// CPU start registers (`platform::apple::cpustart`) from the PMGR node's
/// `reg[0]` ([`rows::CPU_START_T8112`] and its siblings). Each [`CoreType`] also
/// holds its cache geometry ([`CoreCaches`]), where known.
pub(super) struct Soc {
    pub(super) chip_id: u32,
    pub(super) name: &'static str,
    pub(super) pmgr: &'static str,
    pub(super) chip: Chip,
    pub(super) cores: &'static [CoreType],
    pub(super) aic: Option<(&'static str, u64)>,
    pub(super) dram_base: u64,
    pub(super) lockdown: Option<[u64; 2]>,
    pub(super) limits: Option<KernelLimits>,
    pub(super) memory_cache: Option<(u64, u32)>,
    pub(super) clusters: Option<[CpuCluster; 2]>,
    pub(super) aon_fuses: Option<usize>,
    pub(super) cpu_start: Option<u64>,
    pub(super) wake_masks: Option<WakeLayout>,
    pub(super) power_banks: &'static [(usize, crate::power::Kind)],
    pub(super) dpe_reg: Option<usize>,
    pub(super) bridge_fields: Option<&'static [&'static [(u64, u32)]]>,
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
    pub(super) caches: Option<CoreCaches>,
}

impl CoreType {
    /// Compose the established MPIDR identity independently of the MIDR,
    /// caches and clocks that a complete PE profile also requires. `reg`
    /// keeps the physical cluster/core coordinates; core type never
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
pub(super) struct WakeLayout {
    pub(super) reg: usize,
    pub(super) valid: [u32; wake::WORDS],
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
pub(super) struct CoreCaches {
    instruction: Cache,
    data: Cache,
    unified_ways: u32,
}

/// Apple's 128-byte cache lines.
const LINE: u32 = 128;

pub(super) const fn cache(bytes: u32, ways: u32) -> Cache {
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
///   chockenberry/1d08129bdf41bfb70e98c3a75ce74578): the M4 Max, the M5
///   and the M5 Pro and Max report these `l1icachesize` and `l1dcachesize`
///   values per core type, with the `l2cachesize` values their boards'
///   26A434 DeviceTrees state. The M5 Pro and Max M cores (`perflevel1`,
///   "Performance") report the E cores' 128 KiB and 64 KiB, with the 8 MiB
///   their `l2-cache-size` gives.
/// - Inferred: the M3 Pro and Max, the M4 and M4 Pro, the A18 Pro, the M5
///   Ultra and the M6, whose 26A434 DeviceTrees give their cores the same
///   `apple,sawtooth` and `apple,everest` compatibles as the M3, M4 Max and
///   M5 cores above. The M6 M type has no cache geometry.
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

/// The T6050's core types: M cores (`cluster-type` M, `apple,sawtooth`) and
/// P cores (`apple,everest`), no E cores (XNU `board_config.h` T6050
/// `HAS_MCORE`). XNU `osfmk/arm/cpuid.h` gives the Sotra S (H17S) parts,
/// M 0x64 and P 0x65, and the Sotra C (H17C) parts, 0x68 and 0x69 (m1n1
/// `src/midr.h` `MIDR_PART_T6050_SOTRA_*` and `MIDR_PART_T6051_SOTRAC_*`),
/// and `MPIDR_CORETYPE` M is 4. The M cores take the E geometry and
/// the P cores the P geometry ([`L1_CACHES`]); both types' clocks are not
/// established.
const fn sotra_cores(m_part: u16, p_part: u16) -> [CoreType; 2] {
    [
        CoreType {
            cluster_type: b'M',
            midr_part: Some(m_part),
            mpidr_aff2: Some(4),
            operating_points: None,
            caches: Some(L1_CACHES[0]),
        },
        CoreType {
            cluster_type: b'P',
            midr_part: Some(p_part),
            mpidr_aff2: Some(1),
            operating_points: None,
            caches: Some(L1_CACHES[1]),
        },
    ]
}

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

/// The chip and PEs a board's SoC row and `/cpus` select.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cpus {
    pub chip: Chip,
    /// The PEs in `/cpus` order.
    pub processors: Vec<Identity>,
    /// The `aic` node's `compatible` and its event register's offset from its
    /// `reg`, on a SoC whose event register offset is established.
    pub aic: Option<(&'static str, u64)>,
    /// The SoC's lockdown CONTROL offsets in `cpu-impl-reg` and
    /// `cpm-impl-reg`, where known.
    pub lockdown: Option<[u64; 2]>,
}

/// The `aic` node's `compatible` and its event register's offset from its
/// `reg` on the SoC with `chip_id`, where established.
pub fn aic(chip_id: u32) -> Option<(&'static str, u64)> {
    chip_row(chip_id)?.aic
}

/// A row of `chip_id`, for the facts every row of an ApChipID shares: all
/// but the `product-soc-name` and the core types.
pub(super) fn chip_row(chip_id: u32) -> Option<&'static Soc> {
    SOCS.iter().find(|soc| soc.chip_id == chip_id)
}

/// The row of `chip_id` when it is the ApChipID's only one. The T6050's
/// rows differ in name and parts, so its chip ID alone selects none; its
/// DeviceTree's `product-soc-name` does ([`cpus`]).
fn only_row(chip_id: u32) -> Option<&'static Soc> {
    let mut rows = SOCS.iter().filter(|soc| soc.chip_id == chip_id);
    let row = rows.next()?;
    rows.next().is_none().then_some(row)
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

/// The observed core types and their configured or unknown CPU requirements,
/// for an ApChipID with one row (`only_row`). The number of types does not
/// define the number of physical clusters.
pub fn core_types(chip_id: u32) -> Option<&'static [CoreType]> {
    Some(only_row(chip_id)?.cores)
}

/// The CPU of the SoC with `chip_id`, for the SoCs with a row.
pub fn chip(chip_id: u32) -> Option<Chip> {
    Some(chip_row(chip_id)?.chip)
}

/// The label of the SoC's own core variant in a DeviceTree template that
/// gives a value per variant instead of one: J700AP's P cores carry
/// `l2-cache-size-h17p` (16 MiB) and `l2-cache-size-h17a` (8 MiB) and no
/// `l2-cache-size`, which XNU's `ml_parse_cpu_topology` reads. XNU
/// `osfmk/arm/cpuid.h` names the A18 Pro's Tahiti cores H17P (the A18's
/// Tupai cores are H17A), so its value is the `-h17p` one.
pub fn template_variant(chip_id: u32) -> Option<&'static str> {
    match chip_id {
        0x8140 => Some("h17p"),
        _ => None,
    }
}

/// The `product-soc-name` of the SoC with `chip_id`, for an ApChipID with one
/// row (`only_row`).
pub fn name(chip_id: u32) -> Option<&'static str> {
    Some(only_row(chip_id)?.name)
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
    chip_row(chip_id)
        .map(|soc| soc.dram_base)
        .ok_or_else(|| format!("ApChipID {chip_id:#x} has no SoC row and no DRAM base"))
}

/// The guest DRAM base of a board whose SoC is `chip_id`: its DeviceTree's
/// `/arm-io/mcc` `dram-base`, which most M3 and later boards state, or else
/// the SoC's base ([`dram_base`]). Where both exist they must agree.
pub fn board_dram_base(tree: &[u8], chip_id: u32) -> Result<u64, String> {
    let root = Node::root_exact(tree).ok_or("DeviceTree has no root or is malformed")?;
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
/// `t6022.dtsi`: `cpu@800`, `cpu@10900`), and on the T6050 Aff1 16 to 18
/// (its template's `reg` 0x1000 to 0x1205; XNU's T6050
/// `MAX_CPU_CLUSTER_PHY_ID` is 18). Each chip's kernel limits bound the
/// cluster numbers further. A `reg` beyond Aff1 and Aff0 refuses.
/// The `reg` bits a `/cpus` node may set: Aff1 and Aff0.
const MPIDR_CLUSTER_CORE: u32 = 0xffff;

pub fn cpus(chip_id: u32, soc_name: &str, processors: &[Processor]) -> Result<Cpus, String> {
    let rows: Vec<&Soc> = SOCS.iter().filter(|soc| soc.chip_id == chip_id).collect();
    if rows.is_empty() {
        return Err(format!(
            "ApChipID {chip_id:#x} ({soc_name}) has no public MIDR part"
        ));
    }
    let Some(soc) = rows.iter().find(|soc| soc.name == soc_name) else {
        let names: Vec<&str> = rows.iter().map(|soc| soc.name).collect();
        return Err(format!(
            "ApChipID {chip_id:#x} is {}, but the DeviceTree names {soc_name}",
            names.join(" or ")
        ));
    };
    if processors.is_empty() {
        return Err("the DeviceTree has no /cpus nodes".into());
    }
    topology::validate(processors)?;
    if let Some(limits) = soc.limits {
        limits.check(processors)?;
    }
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
