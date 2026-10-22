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
//! their rows). ApChipID 0x6050 has three rows, the M5 Pro, Max and Ultra,
//! which its boards' DeviceTree template names per variant. A SoC row names
//! the `machine::Chip` whose CPU profile its cores take; the A18 Pro takes
//! the M4's (its row gives the evidence). A SoC, cluster type or affinity
//! without that evidence refuses: the T6050's M cores, whose caches no
//! source gives, the M6's M cores, and a T6050 template whose fused variant
//! is not merged yet (the boot bundle merges it, `stela_loader::soc_variant`).
use super::{
    Chip,
    adt::Node,
    caches::{Cache, Caches},
    registers::Identity,
};
use crate::platform::apple::{
    aes, agx,
    aic::{AIC2_DIE_STRIDE, AIC2_MAX_DIES, AIC3_IRQ_CFG, AIC3_TIMESTAMPS, AicLayout},
    aic1::AIC1_EVENT,
    amcc, ans, asc, atc_phy, bridge, cluster, core_counters, coresight, cpm, cpustart, dart, dcp,
    dpe, energy, fuse, gpio, i2c, nor,
    pmgr::coverage::DomainId,
    pmu, power, ptd, sart, smc, spi, spmi, wake,
};
use alloc::{collections::BTreeMap, format, string::String, vec::Vec};

pub mod t6000_pmgr;

mod apertures;
mod interrupts;
pub use interrupts::InterruptController;
use interrupts::{aic_inputs, aic_layout, aic_vectors};
mod gpio_topology;
pub use gpio_topology::{AuxGpioBank, GpioBank};
use gpio_topology::{aux_gpio_banks, gpio_bank, gpio_profile};
mod usb_topology;
use usb_topology::{ATC_PHY_LAYOUTS, typec_devices, usb_controllers};
pub use usb_topology::{I2cAddress, I2cController, TypecPhy, UsbController, hpm_firmware_file};
mod spmi_topology;
use spmi_topology::spmi_controllers;
pub use spmi_topology::{FirmwareMailbox, SpmiConfiguration, SpmiController, SpmiPmu};
mod storage_topology;
pub use storage_topology::{AesEngine, AnsController, AnsQueueGeometry, SpiNor};
use storage_topology::{aes_engine, ans_controller, spi_nor};
mod memory_topology;
pub use memory_topology::{MemoryCache, MemoryController, PtdBank};
use memory_topology::{PTD_RANGE, memory_cache, memory_controller, memory_controller_named};
mod power_registers;
pub use power_registers::{BridgeBank, EnergyBank, PerfBank, PowerBank, SocDpe, WakeBank};
use power_registers::{PmgrRegisters, cpu_start, pmgr_registers};
mod pmp_topology;
pub use pmp_topology::PmpController;
use pmp_topology::pmp_controller;
mod smc_topology;
pub use smc_topology::SmcController;
use smc_topology::smc_controller;
mod gfx_topology;
use gfx_topology::gfx_controller;
pub use gfx_topology::{GfxController, admitted_gpu};
mod sep_topology;
pub use sep_topology::SepDevice;
use sep_topology::sep_device;
mod display_topology;
use display_topology::dcp_device;
pub use display_topology::{DcpController, DcpMapperRoute};
mod dart_topology;
mod dma_routes;
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
use power_resources::power_states;
pub use power_resources::{
    ClockRole, PmgrClockProvider, PowerOwner, PowerResource, PowerStates, ProcessorAssociation,
};
pub use topology::{KernelLimits, assigned};

/// One SoC row: ApChipID, `product-soc-name`, chip, the MIDR_EL1 part
/// number of each `cluster-type`, and the `aic` node's `compatible` with the
/// offset of its event register from its `reg`: for the M1's `aic,1` the
/// event register in its core block (Linux `AIC_EVENT`, 0x2004), and for an
/// `aic,2` or `aic,3` the separate block whose offset iBoot writes to the
/// ADT's `aic-iack-offset`, as Linux `arch/arm64/boot/dts/apple` places it
/// (0x8000 in `t8112.dtsi`, 0xc000 in `t600x-die0.dtsi` and
/// `t602x-die0.dtsi`, 0x40000 in `t8122.dtsi`, `t6030.dtsi`,
/// `t6031-die0.dtsi` and `t8132.dtsi`) and [`AIC3_EVENT`] states for the
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
/// CPU start registers (`platform::apple::cpustart`) from the PMGR node's
/// `reg[0]` ([`CPU_START_T8112`] and its siblings). Each [`CoreType`] also
/// holds its cache geometry ([`CoreCaches`]), where known.
struct Soc {
    chip_id: u32,
    name: &'static str,
    pmgr: &'static str,
    chip: Chip,
    cores: &'static [CoreType],
    aic: Option<(&'static str, u64)>,
    dram_base: u64,
    lockdown: Option<[u64; 2]>,
    limits: Option<KernelLimits>,
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

/// XNU's per-board CPU limits (`xnu-12377.121.6`
/// `pexpert/pexpert/arm64/board_config.h` `MAX_CPUS`, `MAX_CPU_CLUSTERS`,
/// `MAX_CPU_CLUSTER_PHY_ID`, defaulting to the cluster count less one):
/// the T6000 configuration covers the M1 Pro, Max and Ultra, T6020 the M2
/// Pro, Max and Ultra, T6031 the M3 Max and Ultra, T6041 the M4 Pro and
/// Max, T6050 the M5 Pro, Max and Ultra. Each Ultra boots its Max's 26A434
/// kernel, and each of those kernels' `topology_info` arrays hold exactly
/// these CPUs and clusters (`docs/research/cpu-topology.md`). Every 26A434
/// board DeviceTree fits its chip's (`topology::KernelLimits`).
const T8103_LIMITS: KernelLimits = KernelLimits::new(8, 2, 1);
const T6000_LIMITS: KernelLimits = KernelLimits::new(20, 6, 10);
const T8112_LIMITS: KernelLimits = KernelLimits::new(8, 2, 1);
const T6020_LIMITS: KernelLimits = KernelLimits::new(24, 6, 10);
const T8122_LIMITS: KernelLimits = KernelLimits::new(8, 2, 1);
const T6030_LIMITS: KernelLimits = KernelLimits::new(12, 2, 1);
const T6031_LIMITS: KernelLimits = KernelLimits::new(32, 6, 10);
const T8132_LIMITS: KernelLimits = KernelLimits::new(10, 2, 1);
const T6041_LIMITS: KernelLimits = KernelLimits::new(16, 3, 2);
const T6050_LIMITS: KernelLimits = KernelLimits::new(36, 6, 18);
const T8142_LIMITS: KernelLimits = KernelLimits::new(10, 2, 1);
/// The T8140 has no public configuration; its 26A434 kernel's
/// (kernelcache.release.mac17p, SHA-256 `12ee4fc6...1d45`) compiles six CPUs,
/// two clusters and cluster 1: `ml_parse_cpu_topology` defaults its CPU
/// limit to 6 (`0xfffffe000ba88318`) and fills two `cluster_offsets`
/// entries (`0xfffffe000ba88408`), and `topology_info` (`0xfffffe0007e2c650`)
/// points at six 0x88-byte CPU records (`0x...e2c270`) followed by two
/// 0x58-byte cluster records (`0x...e2c5a0`) that end at it. The same reading
/// of the T8142's kernel (mac17g) gives XNU's 10/2/1.
const T8140_LIMITS: KernelLimits = KernelLimits::new(6, 2, 1);
/// The T8152 has no public configuration either; the same reading of its
/// 26A434 kernel (kernelcache.release.mac18g, SHA-256 `09746d1f...5b85`)
/// gives twelve CPUs, two clusters and cluster 1: the CPU limit defaults to
/// 12 (`0xfffffe000bdf1298`), two `cluster_offsets` entries are filled
/// (`0xfffffe000bdf1388`), and `topology_info` (`0xfffffe0007eb89a0`)
/// points at twelve CPU records (`0x...eb8290`) and two cluster records
/// (`0x...eb88f0`). J873gAP's six E, two P and four M cores fill it, the
/// M cores in the P cluster (Aff1 1).
const T8152_LIMITS: KernelLimits = KernelLimits::new(12, 2, 1);

/// The event register offset every 26A434 M3-to-M6 iBoot writes to an
/// `aic,3` node's `aic-iack-offset` (`mov w8, #0x40000` before the property
/// name): J613 0x3c0f8, J514s 0x3b800, J514c 0x3e2a4, J773g 0x3a610, J614s
/// 0x3c6e4, J614c 0x3c604, J700 0x3ce90, J813 0x3e79c, J714s 0x40f40 and
/// J873g 0x3cd14 in the decoded `iBoot.<board>.RELEASE.im4p` payloads, where J473's writes
/// the 0x8000 of `t8112.dtsi` (0x39a88).
const AIC3_EVENT: u64 = 0x40000;

/// The generic `/arm-io/pmgr` of the M6, whose SoC registers are in
/// `/arm-io/pmgr-child` (m1n1 `pmgr.c`).
const PMGR2_ARCH: &str = "pmgr2,arch";

/// The CPU start registers' offsets from the PMGR's `reg[0]` ([`cpu_start`]),
/// m1n1 `src/smp.c` `CPU_START_OFF_*` and the chips its `smp_init` gives
/// each. The M6's is also its `/arm-io/pmgr-child` `misc-cores-offset`,
/// which the 26A434 J873GAP `AppleT8152PMGR` `HAL::initRegGroups` reads as
/// the misc-cores register group at `reg[0]` plus that offset (kernelcache
/// 0xfffffe000a05521c).
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
    dram_base: 0x100_0000_0000,
    lockdown: Some(LOCKDOWN),
    limits: Some(T6000_LIMITS),
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
    dram_base: 0x100_0000_0000,
    lockdown: Some(LOCKDOWN),
    limits: Some(T6020_LIMITS),
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
    aic: Some(("aic,3", AIC3_EVENT)),
    dram_base: 0x100_0000_0000,
    lockdown: Some(LOCKDOWN),
    limits: Some(T6031_LIMITS),
    memory_cache: None,
    clusters: None,
    aon_fuses: None,
    cpu_start: Some(CPU_START_T6031),
    wake_masks: None,
    power_banks: &[],
    dpe_reg: None,
    bridge_fields: None,
};

/// The M5 Pro, Max and Ultra share ApChipID 0x6050: every 26A434 build
/// identity of their boards (J714s/c, J716s/c, J775c/d, J873s) names it, as
/// does one `sptm.t6050`, one kernel (`mac17j`) and one XNU configuration
/// (T6050). Their DeviceTrees are one template listing both dies' CPUs
/// (`reg` 0x0 to 0x1205, clusters 0, 1, 2 and 16, 17, 18), without
/// `product-soc-name`; iBoot picks a `/:sotra` variant (`h17s`, `h17c`,
/// `h17cr1`, `h17cr2` or `h17d`) from its fuses, as the boot bundle does
/// from the board's (`stela_loader::soc_variant`), and the
/// `/product/:sotra_<variant>_<n>` overlay names the SoC: Apple M5 Pro for `h17s`, Apple M5 Max for the
/// three `h17c` variants and Apple M5 Ultra for `h17d`. The Pro has the
/// Sotra S parts and the Max the Sotra C parts; the Ultra's two dies are
/// inferred to be Max dies, as on the earlier Ultras, since XNU gives the
/// Sotra C parts the subfamily it gives the Max and Ultra dies
/// (`osfmk/arm/cpuid.c` `CPUSUBFAMILY_ARM_HC_HD`) and names no other Sotra
/// part. m1n1's T6051 label for the Max (`src/soc.h`) matches no 26A434
/// ApChipID. m1n1 `smp.c` gives the T6050 the T6031's CPU start offset.
const M5_PRO: Soc = Soc {
    chip_id: 0x6050,
    name: "Apple M5 Pro",
    pmgr: "pmgr1,t6050",
    chip: Chip::AppleM5,
    cores: &sotra_cores(0x064, 0x065),
    aic: Some(("aic,3", AIC3_EVENT)),
    dram_base: 0x100_0000_0000,
    lockdown: None,
    limits: Some(T6050_LIMITS),
    memory_cache: None,
    clusters: None,
    aon_fuses: None,
    cpu_start: Some(CPU_START_T6031),
    wake_masks: None,
    power_banks: &[],
    dpe_reg: None,
    bridge_fields: None,
};

const SOCS: [Soc; 22] = [
    Soc {
        chip_id: 0x8103,
        name: "Apple M1",
        pmgr: "pmgr1,t8103",
        chip: Chip::AppleM1,
        cores: &ep_cores(0x022, 0x023, Some(M1_POINTS)),
        aic: Some(("aic,1", AIC1_EVENT)),
        dram_base: 0x8_0000_0000,
        lockdown: Some(LOCKDOWN),
        limits: Some(T8103_LIMITS),
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
        dram_base: 0x100_0000_0000,
        lockdown: Some(LOCKDOWN),
        limits: Some(T6000_LIMITS),
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
        dram_base: 0x8_0000_0000,
        lockdown: Some(LOCKDOWN),
        limits: Some(T8112_LIMITS),
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
        dram_base: 0x100_0000_0000,
        lockdown: Some(LOCKDOWN),
        limits: Some(T6020_LIMITS),
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
        aic: Some(("aic,3", AIC3_EVENT)),
        dram_base: 0x100_0000_0000,
        lockdown: Some(LOCKDOWN),
        limits: Some(T8122_LIMITS),
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
        aic: Some(("aic,3", AIC3_EVENT)),
        dram_base: 0x100_0000_0000,
        lockdown: Some(LOCKDOWN),
        limits: Some(T6030_LIMITS),
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
        aic: Some(("aic,3", AIC3_EVENT)),
        dram_base: 0x100_0000_0000,
        lockdown: None,
        limits: Some(T8132_LIMITS),
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
        aic: Some(("aic,3", AIC3_EVENT)),
        dram_base: 0x100_0000_0000,
        lockdown: None,
        limits: Some(T6041_LIMITS),
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
        aic: Some(("aic,3", AIC3_EVENT)),
        dram_base: 0x100_0000_0000,
        lockdown: None,
        limits: Some(T6041_LIMITS),
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: Some(CPU_START_T6031),
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    // The A18 Pro (J700AP) takes the M4's CPU profile. Apple clang's
    // `-mcpu=apple-a18` exports exactly the M4's FEAT set (clang-2100.1.1.101);
    // its 26A434 SPTM's IMPLEMENTATION DEFINED census equals the T8132's and
    // its kernel's is a subset of the T8132 kernel's (`isa/apple-soc-facts.json`);
    // the SPTM executes the M4's maintenance words and never reads
    // TAG_OFFSET_EL2; XNU builds memory tagging only for the T8142 and T6050
    // (`makedefs/MakeInc.def` `MTE_SUPPORTED_SOCS`); and m1n1 gives its Tahiti
    // cores `features_m4` (`src/chickens.c`). Its parts are XNU's H17P Tahiti
    // pair (`osfmk/arm/cpuid.h` `CPU_PART_ECORE_TAHITI` 0x60,
    // `CPU_PART_PCORE_TAHITI` 0x61; m1n1 `MIDR_PART_T8140_TAHITI_*`), and
    // m1n1 `smp.c` gives it the T8112's CPU start offset.
    Soc {
        chip_id: 0x8140,
        name: "Apple A18 Pro",
        pmgr: "pmgr1,t8140",
        chip: Chip::AppleM4,
        cores: &ep_cores(0x060, 0x061, None),
        aic: Some(("aic,3", AIC3_EVENT)),
        dram_base: 0x100_0000_0000,
        lockdown: None,
        limits: Some(T8140_LIMITS),
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
        chip_id: 0x8142,
        name: "Apple M5",
        pmgr: "pmgr1,t8142",
        chip: Chip::AppleM5,
        cores: &ep_cores(0x062, 0x063, None),
        aic: Some(("aic,3", AIC3_EVENT)),
        dram_base: 0x100_0000_0000,
        lockdown: None,
        limits: Some(T8142_LIMITS),
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        cpu_start: Some(CPU_START_T8112),
        wake_masks: None,
        power_banks: &[],
        dpe_reg: None,
        bridge_fields: None,
    },
    M5_PRO,
    Soc {
        name: "Apple M5 Max",
        cores: &sotra_cores(0x068, 0x069),
        ..M5_PRO
    },
    Soc {
        name: "Apple M5 Ultra",
        cores: &sotra_cores(0x068, 0x069),
        ..M5_PRO
    },
    Soc {
        chip_id: 0x8152,
        name: "Apple M6",
        pmgr: PMGR2_ARCH,
        chip: Chip::AppleM6,
        cores: &M6_CORES,
        aic: Some(("aic,3", AIC3_EVENT)),
        dram_base: 0x100_0000_0000,
        lockdown: None,
        limits: Some(T8152_LIMITS),
        memory_cache: None,
        clusters: None,
        aon_fuses: None,
        // In `/arm-io/pmgr-child` (`pmgr2,t8152`), whose
        // `misc-cores-offset` is 0x34000.
        cpu_start: Some(CPU_START_T8112),
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
fn chip_row(chip_id: u32) -> Option<&'static Soc> {
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
/// for an ApChipID with one row ([`only_row`]). The number of types does not
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
/// row ([`only_row`]).
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
    chip_row(chip_id)
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
/// The SPMI controllers and the Dialog PMUs on them (`spmi`, `pmu`).
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

/// T8112 device controller compatible; admission stays closed until the
/// unchanged Apple platform/PHY initialization has been observed.
pub const USB_DRD: &str = "usb-drd,t8112";

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
    /// The CPU start registers' guest PA and the clusters they start, where
    /// the SoC row places them ([`cpu_start`]).
    pub cpu_start: Option<(u64, u8)>,
    /// Visible SPMI controllers and the PMUs on them.
    pub spmis: Vec<SpmiController>,
    /// The `dcpext` display coprocessor and its register apertures, when the
    /// DeviceTree shows them (admission is closed; see [`DcpController`]).
    pub dcp: Option<DcpController>,
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

/// A node's one `reg` range, translated through contiguous `arm-io` ranges.
fn single_range(
    node: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
) -> Result<(u64, u64), &'static str> {
    let pairs = apertures::registers(node).ok_or("device reg missing")?;
    let [(offset, bytes)] = pairs[..] else {
        return Err("device requires one reg range");
    };
    let physical = translate(offset, bytes).ok_or("device range is not wholly translated")?;
    Ok((physical, bytes))
}

/// The opcode of a `function-*` property naming a GPIO pin: the FourCC
/// `GPIO`, first character in the high byte, as the ADT cells store it (the
/// J473AP `/arm-io/spi1` `function-spi_cs0` bytes `4f 49 50 47`).
pub const GPIO_FUNCTION: u32 = u32::from_be_bytes(*b"GPIO");

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
    /// Separate original die-qualified PMGR clock and power requirements.
    pub clock_gates: Vec<DomainId>,
    pub power_gates: Vec<DomainId>,
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

/// The GPU's firmware mapper's compatible.
pub const GFX_MAPPER: &str = "iommu-mapper,gfx";

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
    translate: &dyn Fn(u64, u64) -> Option<u64>,
) -> Result<Option<WatchdogSide>, String> {
    let reg = apertures::registers(node).ok_or("watchdog has no reg")?;
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
            translate(address, bytes).ok_or("watchdog side register is outside arm-io ranges")?;
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

/// The board a DeviceTree describes, or why the engine cannot model it: its
/// chip and PEs ([`cpus`], from `/chosen` `chip-id`, `/product`
/// `product-soc-name` and each `/cpus` node with a `cluster-type`) and the
/// devices the engine models, each of which must be `compatible` with its
/// model. An `/arm-io` child's `reg` is translated through `/arm-io`
/// `ranges`; the AIC's inputs and dies are those its vectors name
/// ([`aic_vectors`], [`aic_inputs`]).
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
    let translate = |offset: u64| io.translate_range(offset, 1);
    let extent = |offset: u64, bytes: u64| io.translate_range(offset, bytes);
    let place = |name: &str, model: Option<&str>| -> Result<(Node<'_>, u64, u64), String> {
        let node = io
            .child(name)
            .ok_or_else(|| format!("DeviceTree has no /arm-io/{name}"))?;
        if let Some(model) = model
            && !node.compatible(model)
        {
            return Err(format!("/arm-io/{name} is not {model}, the modeled device"));
        }
        let (offset, bytes) = apertures::registers(&node)
            .and_then(|reg| reg.first().copied())
            .ok_or_else(|| format!("/arm-io/{name} has no reg"))?;
        let physical = extent(offset, bytes)
            .ok_or_else(|| format!("/arm-io/{name} extent is outside /arm-io ranges"))?;
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
    let watchdog_side = watchdog_side(&io.child("wdt").expect("device was placed"), &extent)?;
    let (version, event) = cpus
        .aic
        .ok_or("the SoC's AIC event register offset is unknown")?;
    let (aic, physical, _) = place("aic", Some(version))?;
    let phandle = aic
        .first_u32("AAPL,phandle")
        .ok_or("/arm-io/aic has no phandle")?;
    let (inputs, layout) = aic_inputs(
        &aic,
        aic_layout(&aic, version, event)?,
        &aic_vectors(&root, phandle)?,
    )?;
    let chosen = root.child("chosen").ok_or("DeviceTree has no /chosen")?;
    let memory_controller = memory_controller(&chosen)?;
    let io_access_controller = memory_controller_named(&chosen, "ioa")?;
    let gpio = gpio_bank(&io, &extent, phandle)?;
    let aux_gpios = aux_gpio_banks(&root, &io, &extent, phandle)?;
    let (i2cs, typec_phys) = typec_devices(&io, &extent, phandle, gpio.as_ref())?;
    let darts = iommus(&io, &extent)?;
    let aes = aes_engine(&io, &extent, &darts)?;
    let iboot_security = root
        .child("defaults")
        .is_some_and(|defaults| defaults.property("nvme-iboot-sptm-security").is_some());
    let ans = ans_controller(&io, &extent, iboot_security)?;
    let smc = smc_controller(&root, &io, &extent)?;
    let pmp = pmp_controller(&io, &extent)?;
    let gfx = gfx_controller(&io, &extent, chip_id)?;
    let sep = sep_device(&root, &io, &extent, &darts)?;
    let usbs = usb_controllers(&io, &extent, &darts)?;
    let power_states = power_states(&root, &extent, chip_id)?;
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
    } = pmgr_registers(&io, &extent, chip_id)?;
    let cpu_start = cpu_start(&io, &extent, chip_id, &cpus.processors)?;
    let memory_cache = memory_cache(&io, &extent, chip_id, memory_controller.as_ref())?;
    let direct_memory_cache =
        memory_resources::direct_memory_cache(&io, &extent, memory_controller.as_ref())?;
    let spi_nor = spi_nor(&root, &io, &extent, phandle, gpio.as_ref())?;
    let spmis = spmi_controllers(&io, &extent, phandle)?;
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
    use super::power_resources::PMGR_DEVICE;
    /// Existing unit fixtures explicitly declare an affine synthetic map.
    /// Production callers supply Node::translate_range, never this adapter.
    pub(super) fn flat_fixture_extent(
        point: &dyn Fn(u64) -> Option<u64>,
    ) -> impl Fn(u64, u64) -> Option<u64> + '_ {
        move |address, bytes| {
            if bytes == 0 {
                return None;
            }
            address.checked_add(bytes)?;
            let physical = point(address)?;
            physical.checked_add(bytes)?;
            Some(physical)
        }
    }

    use super::*;

    /// The T8112 row's PMGR compatible.
    pub(super) const PMGR: &str = "pmgr1,t8112";

    pub(super) fn layout_of(layout: &[(u8, u32)]) -> Vec<Processor> {
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

    /// The M4 and later maps fill CTRR-A to D; a template group iBoot leaves
    /// empty describes none.

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
        // A second die's device carries its die in the word's top nibble.
        let gates = [0x212u32, 0x1000_0216]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let encoded = tree(&gates, true, false);
        let node = Node::root(&encoded).unwrap();
        let dart = iommu(&node, &flat_fixture_extent(&|a| Some(a + 0x2_0000_0000))).unwrap();
        assert_eq!(
            dart.power_gates,
            [
                DomainId {
                    die: 0,
                    device: 0x212
                },
                DomainId {
                    die: 1,
                    device: 0x216
                }
            ]
        );
        assert!(dart.retention);
        for encoded in [
            tree(&gates[..3], false, false),
            tree(&u32::MAX.to_le_bytes(), false, false),
            tree(&0x0001_0212u32.to_le_bytes(), false, false),
            tree(&gates, true, true),
        ] {
            assert!(iommu(&Node::root(&encoded).unwrap(), &flat_fixture_extent(&Some)).is_err());
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
            watchdog_side(&n, &flat_fixture_extent(&|a| Some(a + 0x2_0000_0000))).unwrap(),
            Some(WatchdogSide {
                words: vec![0x2_0000_c218, 0x2_0000_8008, 0x2_0000_800c, 0x2_0000_8020],
                // Trigger words are absolute physical addresses.
                triggers: vec![(0x2_1002_0304, 0xf, 1), (0x2_1012_0304, 0xf, 1)],
            })
        );
        assert!(watchdog_side(&n, &flat_fixture_extent(&|_| None)).is_err());
        let tree = encode(&[("reg", &reg), ("panic-save-flag-bit", &zero)], &[]);
        // reg[4] needs its force-power-off flag bit.
        assert!(watchdog_side(&Node::root(&tree).unwrap(), &flat_fixture_extent(&Some)).is_err());
        let tree = encode(
            &[
                ("reg", &reg[..48]),
                ("panic-save-flag-bit", &32u32.to_le_bytes()),
            ],
            &[],
        );
        assert!(watchdog_side(&Node::root(&tree).unwrap(), &flat_fixture_extent(&Some)).is_err());
        let tree = encode(&[("reg", &reg[..48]), ("panic-save-flag-bit", &zero)], &[]);
        assert_eq!(
            watchdog_side(&Node::root(&tree).unwrap(), &flat_fixture_extent(&Some))
                .unwrap()
                .unwrap()
                .words,
            [0xc218, 0x8008]
        );
        let tree = encode(&[("reg", &reg[..16])], &[]);
        assert_eq!(
            watchdog_side(&Node::root(&tree).unwrap(), &flat_fixture_extent(&Some)).unwrap(),
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
        let side = watchdog_side(&node, &|address, bytes| io.translate_range(address, bytes))
            .unwrap()
            .unwrap();
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
    #[ignore = "requires original26A434J314sDT throughSTELA_TEST_GPIO_DT"]
    fn original_j314s_ap_gpio_qualifies_without_auxiliary_or_lifecycle_claims() {
        let data = std::fs::read(std::env::var("STELA_TEST_GPIO_DT").unwrap()).unwrap();
        assert_eq!(
            crate::sha256(&data),
            "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
        );
        let root = Node::root(&data).unwrap();
        let io = root.child("arm-io").unwrap();
        let bank = gpio_bank(
            &io,
            &|address, bytes| io.translate_range(address, bytes),
            130,
        )
        .unwrap()
        .unwrap();
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
        let controllers = spmi_controllers(
            &io,
            &|address, bytes| io.translate_range(address, bytes),
            130,
        )
        .unwrap();
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
        let smc = smc_controller(&root, &io, &|address, bytes| {
            io.translate_range(address, bytes)
        })
        .unwrap()
        .unwrap();
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
                .flat_map(|pmu| {
                    pmu.retained()
                        .map(|(kind, window)| (pmu.sid, kind, vec![0; usize::from(window.bytes)]))
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
            let (base, bytes) = controller.bank_c.unwrap();
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
        assert_eq!(
            (found.chip, found.aic),
            (Chip::AppleM4, Some(("aic,3", AIC3_EVENT)))
        );
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
        // The M3's AICv3 has it at +0x40000; J613AP has four E and four P
        // cores, within the M3's eight CPU slots (an M4's six E cores are
        // not).
        let j613 = [(b'E', 0), (b'E', 3), (b'P', 0x100), (b'P', 0x103)];
        assert_eq!(
            cpus(0x8122, "Apple M3", &layout_of(&j613)).unwrap().aic,
            Some(("aic,3", 0x40000))
        );
        assert!(
            cpus(0x8122, "Apple M3", &layout_of(&layout))
                .unwrap_err()
                .contains("CPU slots")
        );
        assert_eq!(dram_base(0x8112), Ok(0x8_0000_0000));
        assert_eq!(dram_base(0x6021), Ok(0x100_0000_0000));
        for chip_id in [0x8132, 0x8140, 0x8142, 0x8152] {
            assert_eq!(dram_base(chip_id), Ok(0x100_0000_0000));
        }
        assert!(dram_base(0x8101).is_err());
        // Every ApChipID and name pair appears once, and the rows of one
        // ApChipID share its chip-level facts.
        for (index, soc) in SOCS.iter().enumerate() {
            for other in SOCS[index + 1..]
                .iter()
                .filter(|o| o.chip_id == soc.chip_id)
            {
                assert_ne!(other.name, soc.name);
                assert_eq!(
                    (other.chip, other.pmgr, other.aic, other.dram_base),
                    (soc.chip, soc.pmgr, soc.aic, soc.dram_base)
                );
                assert_eq!(
                    (other.lockdown, other.limits, other.cpu_start),
                    (soc.lockdown, soc.limits, soc.cpu_start)
                );
                assert_eq!(
                    (other.memory_cache, other.clusters, other.aon_fuses),
                    (soc.memory_cache, soc.clusters, soc.aon_fuses)
                );
            }
        }
    }

    /// The A18 Pro takes the M4's CPU profile with its own parts, so every
    /// chip-keyed feature is the M4's: the Apple generic timer, CTRR-C/D and
    /// CTXR, no memory tagging and the M4's maintenance words (DC INCPA4K,
    /// operation 25 and `0x00201401`, not operation 26). J700AP's four E and
    /// two P cores fill its kernel's six CPU slots.
    #[test]
    fn the_a18_pro_takes_the_m4_cpu_profile() {
        use super::super::{ctrr, identification, timer::agt};
        assert_eq!(chip(0x8140), Some(Chip::AppleM4));
        assert_eq!(name(0x8140), Some("Apple A18 Pro"));
        assert_eq!(midr_part(0x8140, b'E'), Some(0x60));
        assert_eq!(midr_part(0x8140, b'P'), Some(0x61));
        assert!(agt::present(Chip::AppleM4));
        assert_eq!(ctrr::generation(Chip::AppleM4), ctrr::Generation::Ctrr3);
        assert!(!identification::memory_tagging(Chip::AppleM4));
        assert!(Chip::AppleM4 < Chip::AppleM5);
        assert_eq!(template_variant(0x8140), Some("h17p"));
        assert_eq!(template_variant(0x8132), None);
        let j700 = [
            (b'E', 0),
            (b'E', 1),
            (b'E', 2),
            (b'E', 3),
            (b'P', 0x100),
            (b'P', 0x101),
        ];
        let a18 = cpus(0x8140, "Apple A18 Pro", &layout_of(&j700)).unwrap();
        assert_eq!(a18.chip, Chip::AppleM4);
        assert_eq!(a18.lockdown, None);
        assert_eq!(a18.processors[0].midr, 0x611f_0600);
        assert_eq!(a18.processors[4].midr, 0x611f_0610);
        assert_eq!(a18.processors[5].mpidr, 0x8001_0101);
        let seventh = [j700.as_slice(), &[(b'P', 0x102)]].concat();
        assert!(
            cpus(0x8140, "Apple A18 Pro", &layout_of(&seventh))
                .unwrap_err()
                .contains("MAX_CPUS")
        );
    }

    /// ApChipID 0x6050's rows follow the `product-soc-name` its template
    /// gives each variant: the Pro's Sotra S parts, the Max's and the
    /// Ultra's Sotra C parts, the second die at Aff1 16 to 18. The M cores
    /// refuse for their unestablished caches; the chip ID alone names no row.
    #[test]
    fn the_t6050_rows_follow_the_template_soc_name() {
        use super::super::{identification, timer::agt};
        assert_eq!(chip(0x6050), Some(Chip::AppleM5));
        assert!(agt::present(Chip::AppleM5) && identification::memory_tagging(Chip::AppleM5));
        assert!(name(0x6050).is_none() && core_types(0x6050).is_none());
        assert_eq!(midr_part(0x6050, b'P'), None);
        let p_core = |soc: &str, reg: u32| {
            let cpus = cpus(0x6050, soc, &layout_of(&[(b'P', reg)])).unwrap();
            assert_eq!(cpus.chip, Chip::AppleM5);
            (cpus.processors[0].midr, cpus.processors[0].mpidr)
        };
        assert_eq!(p_core("Apple M5 Pro", 0x200), (0x611f_0650, 0x8001_0200));
        assert_eq!(p_core("Apple M5 Max", 0x205), (0x611f_0690, 0x8001_0205));
        assert_eq!(p_core("Apple M5 Ultra", 0x1205), (0x611f_0690, 0x8001_1205));
        // The M cores report the E cores' level 1 caches (`hw.perflevel1`).
        let m_core = cpus(0x6050, "Apple M5 Pro", &layout_of(&[(b'M', 0)])).unwrap();
        assert_eq!(
            m_core.processors[0],
            Identity {
                midr: 0x611f_0640,
                mpidr: 0x8004_0000,
                clock: None,
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
            cpus(0x6050, "Apple M5", &layout_of(&[(b'P', 0x200)])),
            Err(
                "ApChipID 0x6050 is Apple M5 Pro or Apple M5 Max or Apple M5 Ultra, but the \
                 DeviceTree names Apple M5"
                    .into()
            )
        );
        // The template's 36 PEs fill the kernel's slots; a 37th refuses.
        let mut template = Vec::new();
        for die in [0, 0x1000] {
            for (kind, cluster) in [(b'M', 0), (b'M', 0x100), (b'P', 0x200)] {
                template.extend((0..6).map(|core| (kind, die | cluster | core)));
            }
        }
        assert_eq!(T6050_LIMITS.check(&layout_of(&template)), Ok(()));
        template.push((b'P', 0x1206));
        assert!(
            T6050_LIMITS
                .check(&layout_of(&template))
                .unwrap_err()
                .contains("MAX_CPUS")
        );
    }

    #[test]
    fn the_m6_kernel_bounds_its_cpus() {
        // Twelve PEs at J873gAP's affinities (its 0x102..0x105 are M cores).
        let mut j873g: Vec<(u8, u32)> = (0..6).map(|core| (b'E', core)).collect();
        j873g.extend((0..6).map(|core| (b'P', 0x100 + core)));
        let m6 = cpus(0x8152, "Apple M6", &layout_of(&j873g)).unwrap();
        assert_eq!(m6.processors.len(), 12);
        assert_eq!(m6.processors[11].mpidr, 0x8001_0105);
        j873g.push((b'P', 0x106));
        assert!(
            cpus(0x8152, "Apple M6", &layout_of(&j873g))
                .unwrap_err()
                .contains("MAX_CPUS")
        );
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
            cpus(0x8101, "Apple A14", &one),
            Err("ApChipID 0x8101 (Apple A14) has no public MIDR part".into())
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
    pub(super) fn tree(chip_id: u32, soc: &str, compatibles: [&str; 3]) -> Vec<u8> {
        tree_with(chip_id, soc, compatibles, &[])
    }
    /// [`tree`] with more `/arm-io/aic` properties.
    pub(super) fn tree_with(
        chip_id: u32,
        soc: &str,
        compatibles: [&str; 3],
        aic_properties: &[(&str, u32)],
    ) -> Vec<u8> {
        tree_with_io(chip_id, soc, compatibles, aic_properties, &[])
    }
    /// [`tree_with`] with more `/arm-io` children.
    pub(super) fn tree_with_io(
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
        // An AICv1 states its 740 inputs (the UART's 739 is the highest) to
        // the word.
        let ipid_mask = vec![0xff; 24 * 4];
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
        .chain((compatibles[2] == "aic,1").then_some(("ipid-mask", ipid_mask.as_slice())))
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
        // An M3 board states its base; an M5 board states none and takes its
        // SoC's.
        assert_eq!(
            board_dram_base(&with_base(Some(&stated)), m3),
            Ok(0x100_0000_0000)
        );
        assert_eq!(
            board_dram_base(&with_base(None), 0x8142),
            Ok(0x100_0000_0000)
        );
        assert!(board_dram_base(&with_base(None), 0x8101).is_err());
        // The M2's board states none and takes its SoC's base; a stated base
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
                dkey: None,
                config: aes::Config {
                    version: 3,
                    address_width: aes::DEFAULT_ADDRESS_WIDTH,
                    key_disable: aes::KeyDisable {
                        bytes: 0x8000,
                        word: 0,
                        keys: [None; 3],
                    },
                },
                irq: 0x2f7,
                iommu: 0,
                stream: 1,
            })
        );
        // J773g: version 5 with its DKey range, 42-bit addresses and a
        // disable word per key.
        let m4 = |reg: &[u64], version: u32, gid1: &[u8]| {
            encode(
                &[
                    ("name", &z("aes")),
                    ("compatible", &z(AES)),
                    ("reg", &u64s(reg)),
                    ("interrupts", &u32s(&[0x425])),
                    ("iommu-parent", &u32s(&[0x8a])),
                    ("aes-version", &u32s(&[version])),
                    ("address-width", &u32s(&[42])),
                    ("sioaesdisable-offset", &u32s(&[0])),
                    ("sioaesdisableuid1-offset", &u32s(&[0x40])),
                    ("sioaesdisablegid0-offset", &u32s(&[0x44])),
                    ("sioaesdisablegid1-offset", gid1),
                ],
                &[],
            )
        };
        let three = [
            0x3500_c000,
            0x4000,
            0x3d2d_c000,
            0x8000,
            0x3d07_8000,
            0x4000,
        ];
        let parse = |node: Vec<u8>| {
            board(&tree_with_io(
                0x8112,
                "Apple M2",
                MODELED,
                &[],
                &[sio.clone(), node],
            ))
            .map(|board| board.aes.unwrap())
        };
        let wide = parse(m4(&three, 5, &u32s(&[0x48]))).unwrap();
        assert_eq!(wide.dkey, Some((0x2_3d07_8000, 0x4000)));
        assert_eq!(
            wide.config,
            aes::Config {
                version: 5,
                address_width: 42,
                key_disable: aes::KeyDisable {
                    bytes: 0x8000,
                    word: 0,
                    keys: [Some(0x40), Some(0x44), Some(0x48)],
                },
            }
        );
        assert_eq!(
            parse(m4(&three[..4], 5, &u32s(&[0x48]))),
            Err("/arm-io/aes aes-version 5 has 2 register ranges".into())
        );
        assert_eq!(
            parse(m4(&three, 3, &u32s(&[0x48]))),
            Err("/arm-io/aes aes-version 3 has 3 register ranges".into())
        );
        assert_eq!(
            parse(m4(&three, 5, &u32s(&[0x48, 0]))),
            Err("/arm-io/aes sioaesdisablegid1-offset is not one 32-bit cell".into())
        );
        assert_eq!(
            parse(m4(&three, 5, &u32s(&[0x44]))),
            Err("/arm-io/aes: AES key-disable words overlap".into())
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
        let routed = aes_engine(&io, &flat_fixture_extent(&Some), &routes)
            .unwrap()
            .unwrap();
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
            aes_engine(&io, &flat_fixture_extent(&Some), &routes)
                .unwrap_err()
                .contains("ambiguous")
        );
        routes[0] = good.clone();
        routes.push(good.clone());
        assert!(
            aes_engine(&io, &flat_fixture_extent(&Some), &routes)
                .unwrap_err()
                .contains("ambiguous")
        );
        routes.pop();
        routes[0] = good.clone();
        routes[0].sids = vec![0, 15];
        assert!(
            aes_engine(&io, &flat_fixture_extent(&Some), &routes)
                .unwrap_err()
                .contains("SID set")
        );
        routes[0] = good.clone();
        routes[0].streams = 1;
        assert!(
            aes_engine(&io, &flat_fixture_extent(&Some), &routes)
                .unwrap_err()
                .contains("outside the native profile")
        );
        routes[0] = good.clone();
        routes[0].instances.push(good.instances[0].clone());
        assert!(
            aes_engine(&io, &flat_fixture_extent(&Some), &routes)
                .unwrap_err()
                .contains("multi-instance")
        );
        routes[0].instances.clear();
        assert!(aes_engine(&io, &flat_fixture_extent(&Some), &routes).is_err());
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
        let found = iommu(
            &Node::root(&bytes).unwrap(),
            &flat_fixture_extent(&|a| Some(a)),
        )
        .unwrap();
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
            assert!(
                iommu(
                    &Node::root(&bad).unwrap(),
                    &flat_fixture_extent(&|a| Some(a))
                )
                .is_err()
            );
        }
        let mut bad = descriptors.clone();
        bad[20..24].copy_from_slice(&0u32.to_le_bytes());
        let bytes = build(&bad, &reg, &[1, 14], &[0, 1, 0, 0]);
        assert!(
            iommu(
                &Node::root(&bytes).unwrap(),
                &flat_fixture_extent(&|a| Some(a))
            )
            .is_err()
        );
        assert!(
            iommu(
                &Node::root(&build(&descriptors, &reg, &[1, 14], &[0, 1, 0, 0])).unwrap(),
                &flat_fixture_extent(&|_| None)
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
            &flat_fixture_extent(&|a| Some(a + 0x2_0000_0000)),
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

    /// `/arm-io` children shaped like J514cAP's: the always-on PTD
    /// (phandle 0x127, one cell per notification) and a CLPC (its
    /// `/arm-io/pmgr/clpc`) that names the AIC (0x63) for its first three
    /// specifiers and the PTD for the four FourCCs after them.
    pub(super) fn clpc_with_ptd() -> Vec<Vec<u8>> {
        use crate::machine::adt::encode;
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let words = |cells: &[u32]| {
            cells
                .iter()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let ptd = encode(
            &[
                ("name", &z("aon-ptd")),
                ("AAPL,phandle", &words(&[0x127])),
                ("#interrupt-cells", &words(&[1])),
                ("interrupt-controller", &z("master")),
            ],
            &[],
        );
        let clpc = encode(
            &[
                ("name", &z("clpc")),
                (
                    "interrupt-parent",
                    &words(&[0x63, 0x63, 0x63, 0x127, 0x127, 0x127, 0x127]),
                ),
                (
                    "interrupts",
                    &words(&[
                        0x5bf,
                        0,
                        0x5bd,
                        0x7030_5452,
                        0x7031_5452,
                        0x6130_5452,
                        0x6630_5452,
                    ]),
                ),
            ],
            &[],
        );
        vec![ptd, clpc]
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
        let node = io.child("dart-sep").unwrap();
        assert_eq!(node.first_u32("sids"), Some(0x8001));
        let darts = [iommu(&node, &|address, bytes| io.translate_range(address, bytes)).unwrap()];
        let dart = &darts[0];
        assert_eq!(dart.profile, dart::Profile::T6000);
        assert_eq!(dart.streams, 16);
        assert_eq!(dart.sids, [0, 15]);
        assert_eq!(dart.instances.len(), 1);
        assert!(dart.remap.is_empty());
        let sep = sep_device(
            &root,
            &io,
            &|address, bytes| io.translate_range(address, bytes),
            &darts,
        )
        .unwrap()
        .unwrap();
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
        let darts = ["dart-dispext0", "dart-dcpext0"].map(|name| {
            iommu(&io.child(name).unwrap(), &|address, bytes| {
                io.translate_range(address, bytes)
            })
            .unwrap()
        });
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
    fn mpidr_composition_preserves_ep_identities_and_rejects_unknown_coordinates() {
        for soc in SOCS {
            for (kind, aff2) in [(b'E', 0u64), (b'P', 1), (b'M', 4)] {
                // The T6050 has no E cores and the earlier SoCs no M cores.
                let Some(core) = soc.cores.iter().find(|core| core.cluster_type == kind) else {
                    continue;
                };
                // Include both dies, sparse cores and the upper declared
                // affinity boundary; this field does not define core count.
                for reg in [0, 3, 0x100, 0x105, 0x800, 0x905, 0x1205, 0xffff] {
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
        for bit in 16..32 {
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

    /// The CPU start registers sit in `/arm-io/pmgr` `reg[0]`, or in
    /// `/arm-io/pmgr-child` `reg[0]` under the M6's `pmgr2,arch`, with a
    /// start word for each cluster (J873GAP: `pmgr-child` `reg[0]` is
    /// 0x1_0070_0000 for 0xd0000 bytes, two clusters).

    #[test]
    fn core_requirements_keep_unknown_m6_capabilities_explicit() {
        let soc = SOCS.iter().find(|soc| soc.chip_id == 0x8152).unwrap();
        assert_eq!(soc.cpu_start, Some(CPU_START_T8112));
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
        let security = root
            .child("defaults")
            .unwrap()
            .property("nvme-iboot-sptm-security")
            .is_some();
        let placement = ans_controller(
            &io,
            &|address, bytes| io.translate_range(address, bytes),
            security,
        )
        .unwrap()
        .unwrap();
        assert_eq!(placement.geometry.handoff_entries(), 253);
        assert_eq!(placement.geometry.ring_entries(), 254);
        assert_eq!(placement.geometry.tag_slots(), 253);
        assert_eq!(placement.interrupts, [1070, 1069, 1072, 1071]);
        assert_eq!(placement.completion_irq, 1613);
        assert_eq!(
            placement.clock_gates,
            [DomainId {
                die: 0,
                device: 481
            }]
        );
        assert_eq!(placement.power_gates, [DomainId { die: 0, device: 71 }]);
        assert!(placement.sart_exclusive_bounds);
        assert_eq!(placement.vdma, None);
        assert_eq!(placement.sart_idle, placement.nvme.0 + 0x13e8);
        assert_eq!(placement.namespaces.len(), 3);
        assert_eq!(placement.namespaces[2].blocks, 32768);
        assert!(!models(ASC, |_| None)); // No whole-board/other ASC admission.
    }
}
