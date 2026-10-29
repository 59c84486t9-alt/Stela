//! SoC catalog values and the firmware/kernel evidence establishing each row.
use super::{CpuCluster, KernelLimits, M6_CORES, Soc, WakeLayout, ep_cores, sotra_cores};
use crate::aic::AIC1_EVENT;
use stela_contracts::Chip;

/// The T8112 clusters. The 26A434 J473AP iBoot's native register lists
/// program the DVMR tables: the E cluster's common list `0x17dd70`
/// (descriptors `0x17ce28`, `0x17ce48`, `0x17ce58` and `0x17ce68`), the P
/// cluster's common list `0x181f18` (`0x17f7f0`, `0x17f800`) and its
/// revision 0 list `0x1825d8` (`0x17f810` to `0x17f850`), revision 0 being
/// the `/arm-io` `chip-revision` the DeviceTree hands off. `0x206b8` keeps
/// only the bits its descriptor masks, `0x4000003700000fff` (E) and
/// `0x4000003780000fff` (P), with DVMR (bit 63) left for `enableDVMR` to
/// set. iBoot's state captures span 16 E and 18 P performance-state slots.
pub(in crate::board) const T8112_CLUSTERS: [CpuCluster; 2] = [
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
/// (the T8112's at `__text+0x1b0e4..0x1b14c`). The M4 and later SPTMs write none.
pub(in crate::board) const LOCKDOWN: [u64; 2] = [0x5000, 0x9000];

/// XNU's per-board CPU limits (`xnu-12377.121.6`
/// `pexpert/pexpert/arm64/board_config.h` `MAX_CPUS`, `MAX_CPU_CLUSTERS`,
/// `MAX_CPU_CLUSTER_PHY_ID`, defaulting to the cluster count less one):
/// the T6000 configuration covers the M1 Pro, Max and Ultra, T6020 the M2
/// Pro, Max and Ultra, T6031 the M3 Max and Ultra, T6041 the M4 Pro and
/// Max, T6050 the M5 Pro, Max and Ultra. Each Ultra boots its Max's 26A434
/// kernel, and each of those kernels' `topology_info` arrays hold exactly
/// these CPUs and clusters (`docs/research/cpu-topology.md`). Every 26A434
/// board DeviceTree fits its chip's (`topology::KernelLimits`).
pub(in crate::board) const T8103_LIMITS: KernelLimits = KernelLimits::new(8, 2, 1);
pub(in crate::board) const T6000_LIMITS: KernelLimits = KernelLimits::new(20, 6, 10);
pub(in crate::board) const T8112_LIMITS: KernelLimits = KernelLimits::new(8, 2, 1);
pub(in crate::board) const T6020_LIMITS: KernelLimits = KernelLimits::new(24, 6, 10);
pub(in crate::board) const T8122_LIMITS: KernelLimits = KernelLimits::new(8, 2, 1);
pub(in crate::board) const T6030_LIMITS: KernelLimits = KernelLimits::new(12, 2, 1);
pub(in crate::board) const T6031_LIMITS: KernelLimits = KernelLimits::new(32, 6, 10);
pub(in crate::board) const T8132_LIMITS: KernelLimits = KernelLimits::new(10, 2, 1);
pub(in crate::board) const T6041_LIMITS: KernelLimits = KernelLimits::new(16, 3, 2);
pub(in crate::board) const T6050_LIMITS: KernelLimits = KernelLimits::new(36, 6, 18);
pub(in crate::board) const T8142_LIMITS: KernelLimits = KernelLimits::new(10, 2, 1);
/// The T8140 has no public configuration; its 26A434 kernel's
/// (kernelcache.release.mac17p, SHA-256 `12ee4fc6...1d45`) compiles six CPUs,
/// two clusters and cluster 1: `ml_parse_cpu_topology` defaults its CPU
/// limit to 6 (`0xfffffe000ba88318`) and fills two `cluster_offsets`
/// entries (`0xfffffe000ba88408`), and `topology_info` (`0xfffffe0007e2c650`)
/// points at six 0x88-byte CPU records (`0x...e2c270`) followed by two
/// 0x58-byte cluster records (`0x...e2c5a0`) that end at it. The same reading
/// of the T8142's kernel (mac17g) gives XNU's 10/2/1.
pub(in crate::board) const T8140_LIMITS: KernelLimits = KernelLimits::new(6, 2, 1);
/// The T8152 has no public configuration either; the same reading of its
/// 26A434 kernel (kernelcache.release.mac18g, SHA-256 `09746d1f...5b85`)
/// gives twelve CPUs, two clusters and cluster 1: the CPU limit defaults to
/// 12 (`0xfffffe000bdf1298`), two `cluster_offsets` entries are filled
/// (`0xfffffe000bdf1388`), and `topology_info` (`0xfffffe0007eb89a0`)
/// points at twelve CPU records (`0x...eb8290`) and two cluster records
/// (`0x...eb88f0`). J873gAP's six E, two P and four M cores fill it, the
/// M cores in the P cluster (Aff1 1).
pub(in crate::board) const T8152_LIMITS: KernelLimits = KernelLimits::new(12, 2, 1);

/// The event register offset every 26A434 M3-to-M6 iBoot writes to an
/// `aic,3` node's `aic-iack-offset` (`mov w8, #0x40000` before the property
/// name): J613 0x3c0f8, J514s 0x3b800, J514c 0x3e2a4, J773g 0x3a610, J614s
/// 0x3c6e4, J614c 0x3c604, J700 0x3ce90, J813 0x3e79c, J714s 0x40f40 and
/// J873g 0x3cd14 in the decoded `iBoot.<board>.RELEASE.im4p` payloads, where J473's writes
/// the 0x8000 of `t8112.dtsi` (0x39a88).
pub(in crate::board) const AIC3_EVENT: u64 = 0x40000;

/// The generic `/arm-io/pmgr` of the M6, whose SoC registers are in
/// `/arm-io/pmgr-child` (m1n1 `pmgr.c`).
pub(in crate::board) const PMGR2_ARCH: &str = "pmgr2,arch";
/// T8152 physical groups below the generic PMGRv2 interface (original J873g ADT).
pub(in crate::board) const PMGR2_IMPLEMENTATION: &str = "pmgr2,t8152";

/// The CPU start registers' offsets from the PMGR's `reg[0]` ([`cpu_start`]),
/// m1n1 `src/smp.c` `CPU_START_OFF_*` and the chips its `smp_init` gives
/// each. The M6's is also its `/arm-io/pmgr-child` `misc-cores-offset`,
/// which the 26A434 J873GAP `AppleT8152PMGR` `HAL::initRegGroups` reads as
/// the misc-cores register group at `reg[0]` plus that offset (kernelcache
/// 0xfffffe000a05521c).
pub(in crate::board) const CPU_START_T8103: u64 = 0x54000;
pub(in crate::board) const CPU_START_T8112: u64 = 0x34000;
pub(in crate::board) const CPU_START_T6020: u64 = 0x28000;
pub(in crate::board) const CPU_START_T6031: u64 = 0x88000;

/// Operating points in MHz from Linux `arch/arm64/boot/dts/apple`, each
/// cluster type lowest first with the P states the files leave disabled
/// until CPU deep sleep: `t8103.dtsi` (`ecluster_opp`, `pcluster_opp`),
/// `t600x-common.dtsi` (`icestorm_opp`, `firestorm_opp`) and
/// `t602x-common.dtsi` (`blizzard_opp`, whose "pstate #1 is a dummy clone of
/// #2", and `avalanche_opp`).
pub(in crate::board) const M1_POINTS: [&[u32]; 2] = [
    &[600, 972, 1332, 1704, 2064],
    &[
        600, 828, 1056, 1284, 1500, 1728, 1956, 2184, 2388, 2592, 2772, 2988, 3096, 3144, 3204,
    ],
];
pub(in crate::board) const M1_PRO_POINTS: [&[u32]; 2] = [
    &[600, 972, 1332, 1704, 2064],
    &[
        600, 828, 1056, 1296, 1524, 1752, 1980, 2208, 2448, 2676, 2904, 3036, 3132, 3168, 3228,
    ],
];
pub(in crate::board) const M2_PRO_POINTS: [&[u32]; 2] = [
    &[912, 1284, 1752, 2004, 2256, 2424],
    &[
        702, 948, 1188, 1452, 1704, 1968, 2208, 2400, 2568, 2724, 2868, 3000, 3132, 3264, 3360,
        3408, 3504,
    ],
];

pub(in crate::board) const M1_MAX: Soc = Soc {
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

pub(in crate::board) const M2_MAX: Soc = Soc {
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

pub(in crate::board) const M3_MAX: Soc = Soc {
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
pub(in crate::board) const M5_PRO: Soc = Soc {
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

pub(in crate::board) const SOCS: [Soc; 22] = [
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
            (31, crate::power::Kind::Volman),
            (30, crate::power::Kind::Marker),
            (34, crate::power::Kind::Gpce),
            (32, crate::power::Kind::Gating),
            (35, crate::power::Kind::Tvm),
        ],
        dpe_reg: Some(29),
        bridge_fields: Some(&crate::bridge::tunables::T8112),
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
    // its kernel's is a subset of the T8132 kernel's;
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
