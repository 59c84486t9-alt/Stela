//! Declared ARM board capabilities and the hosted process's resource plan.
//! Original DeviceTree geometry remains source evidence, not a CPU budget.
//! Actual runs observe native Darwin physical/logical availability once,
//! then configure one shared uniform group of their actual CPU0 ARM
//! semantics. Native SMT, cache sharing and exclusive bindings are not
//! inferred from Apple SKU counts.
//!
//! Board/CPU identities, architectural cache capabilities and memory
//! tagging use the shared `machine` tables. The DeviceTree facts are pinned
//! to the universal 26A434 IPSW. CPU family and
//! subfamily are XNU's for the selected MIDR part ([`FAMILIES`]).
mod availability;
pub use availability::DarwinAvailability;
use availability::SharedScheduler;

use anyhow::{Context, Result, bail, ensure};
use {crate::machine::identification, crate::machine::soc, stela_contracts::Chip};

pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;
pub const CPU_SUBTYPE_ARM64E: u32 = 2;
/// `CPU_SUBTYPE_MASK`: the capability bits above the subtype.
pub const CPU_SUBTYPE_MASK: u32 = 0xff00_0000;
/// `CPU_SUBTYPE_PTRAUTH_ABI`: an arm64e process using the stable PAC ABI.
pub const CPU_SUBTYPE_PTRAUTH_ABI: u32 = 0x8000_0000;

/// XNU `osfmk/mach/machine.h` CPU families of the Apple-silicon Macs
/// (xnu-12377.121.6), and the T8152's, which only 26A434 gives (below).
pub const CPUFAMILY_ARM_FIRESTORM_ICESTORM: u32 = 0x1b58_8bb3;
pub const CPUFAMILY_ARM_BLIZZARD_AVALANCHE: u32 = 0xda33_d83d;
pub const CPUFAMILY_ARM_IBIZA: u32 = 0xfa33_415e;
pub const CPUFAMILY_ARM_LOBOS: u32 = 0x5f4d_ea93;
pub const CPUFAMILY_ARM_PALMA: u32 = 0x7201_5832;
pub const CPUFAMILY_ARM_DONAN: u32 = 0x6f51_29ac;
pub const CPUFAMILY_ARM_BRAVA: u32 = 0x17d5_b93a;
pub const CPUFAMILY_ARM_TAHITI: u32 = 0x75d4_acb9;
pub const CPUFAMILY_ARM_HIDRA: u32 = 0x1d5a_87e8;
pub const CPUFAMILY_ARM_SOTRA: u32 = 0xf76c_5b1a;
/// The family of MIDR parts 0x72 and 0x73 (m1n1 `src/midr.h`
/// `MIDR_PART_T8152_KOMODO_*`), which xnu-12377.121.6 does not list: the
/// 26A434 kernels' MIDR-part-indexed family table (`cpuid_get_cpufamily`;
/// kernelcache.release.mac14g file 0xf5bc, entries 0x72 and 0x73) gives it.
pub const CPUFAMILY_ARM_KOMODO: u32 = 0x6d0c_cb0c;

/// XNU `machine.h` CPU subfamilies.
pub const CPUSUBFAMILY_ARM_HP: u32 = 1;
pub const CPUSUBFAMILY_ARM_HG: u32 = 2;
pub const CPUSUBFAMILY_ARM_HS: u32 = 4;
pub const CPUSUBFAMILY_ARM_HC_HD: u32 = 5;

/// The CPU family and subfamily of each MIDR_EL1 part an Apple-silicon Mac
/// SoC row has, as `(part, family, subfamily)`: XNU `osfmk/arm/cpuid.c`
/// `cpuid_get_cpufamily` and `cpuid_get_cpusubfamily` (xnu-12377.121.6),
/// which the 26A434 kernels' part-indexed tables match (kernelcache.release.
/// mac14g file 0xf5bc for families, 0xf7d0 for subfamilies), and those
/// tables for the T8152's parts.
const FAMILIES: &[(u16, u32, u32)] = &[
    (0x22, CPUFAMILY_ARM_FIRESTORM_ICESTORM, CPUSUBFAMILY_ARM_HG),
    (0x23, CPUFAMILY_ARM_FIRESTORM_ICESTORM, CPUSUBFAMILY_ARM_HG),
    (0x24, CPUFAMILY_ARM_FIRESTORM_ICESTORM, CPUSUBFAMILY_ARM_HS),
    (0x25, CPUFAMILY_ARM_FIRESTORM_ICESTORM, CPUSUBFAMILY_ARM_HS),
    (
        0x28,
        CPUFAMILY_ARM_FIRESTORM_ICESTORM,
        CPUSUBFAMILY_ARM_HC_HD,
    ),
    (
        0x29,
        CPUFAMILY_ARM_FIRESTORM_ICESTORM,
        CPUSUBFAMILY_ARM_HC_HD,
    ),
    (0x32, CPUFAMILY_ARM_BLIZZARD_AVALANCHE, CPUSUBFAMILY_ARM_HG),
    (0x33, CPUFAMILY_ARM_BLIZZARD_AVALANCHE, CPUSUBFAMILY_ARM_HG),
    (0x34, CPUFAMILY_ARM_BLIZZARD_AVALANCHE, CPUSUBFAMILY_ARM_HS),
    (0x35, CPUFAMILY_ARM_BLIZZARD_AVALANCHE, CPUSUBFAMILY_ARM_HS),
    (
        0x38,
        CPUFAMILY_ARM_BLIZZARD_AVALANCHE,
        CPUSUBFAMILY_ARM_HC_HD,
    ),
    (
        0x39,
        CPUFAMILY_ARM_BLIZZARD_AVALANCHE,
        CPUSUBFAMILY_ARM_HC_HD,
    ),
    (0x42, CPUFAMILY_ARM_IBIZA, CPUSUBFAMILY_ARM_HG),
    (0x43, CPUFAMILY_ARM_IBIZA, CPUSUBFAMILY_ARM_HG),
    (0x44, CPUFAMILY_ARM_LOBOS, CPUSUBFAMILY_ARM_HS),
    (0x45, CPUFAMILY_ARM_LOBOS, CPUSUBFAMILY_ARM_HS),
    (0x48, CPUFAMILY_ARM_PALMA, CPUSUBFAMILY_ARM_HC_HD),
    (0x49, CPUFAMILY_ARM_PALMA, CPUSUBFAMILY_ARM_HC_HD),
    (0x52, CPUFAMILY_ARM_DONAN, CPUSUBFAMILY_ARM_HG),
    (0x53, CPUFAMILY_ARM_DONAN, CPUSUBFAMILY_ARM_HG),
    (0x54, CPUFAMILY_ARM_BRAVA, CPUSUBFAMILY_ARM_HS),
    (0x55, CPUFAMILY_ARM_BRAVA, CPUSUBFAMILY_ARM_HS),
    (0x58, CPUFAMILY_ARM_BRAVA, CPUSUBFAMILY_ARM_HC_HD),
    (0x59, CPUFAMILY_ARM_BRAVA, CPUSUBFAMILY_ARM_HC_HD),
    (0x60, CPUFAMILY_ARM_TAHITI, CPUSUBFAMILY_ARM_HP),
    (0x61, CPUFAMILY_ARM_TAHITI, CPUSUBFAMILY_ARM_HP),
    (0x62, CPUFAMILY_ARM_HIDRA, CPUSUBFAMILY_ARM_HG),
    (0x63, CPUFAMILY_ARM_HIDRA, CPUSUBFAMILY_ARM_HG),
    (0x64, CPUFAMILY_ARM_SOTRA, CPUSUBFAMILY_ARM_HS),
    (0x65, CPUFAMILY_ARM_SOTRA, CPUSUBFAMILY_ARM_HS),
    (0x68, CPUFAMILY_ARM_SOTRA, CPUSUBFAMILY_ARM_HC_HD),
    (0x69, CPUFAMILY_ARM_SOTRA, CPUSUBFAMILY_ARM_HC_HD),
    (0x72, CPUFAMILY_ARM_KOMODO, CPUSUBFAMILY_ARM_HG),
    (0x73, CPUFAMILY_ARM_KOMODO, CPUSUBFAMILY_ARM_HG),
];

/// Apple's 128-byte cache lines: `hw.cachelinesize`, which XNU takes from
/// the level 1 data cache's CCSIDR_EL1 (`machine::caches`).
const CACHE_LINE: u32 = 128;

/// The DeviceTree `cluster-type` letters.
const EFFICIENCY: u8 = b'E';
const PERFORMANCE: u8 = b'P';

/// One cluster of a board's DeviceTree: its `cluster-type`, core count and
/// `l2-cache-size`.
#[derive(Debug, Clone, Copy)]
struct Layout {
    cluster_type: u8,
    cores: u8,
    l2_bytes: u32,
}

const fn layout(cluster_type: u8, cores: u8, l2_mib: u32) -> Layout {
    Layout {
        cluster_type,
        cores,
        l2_bytes: l2_mib << 20,
    }
}

/// One SoC's hosted board: its ApChipID, `hw.model` (the IPSW product type),
/// `hw.target` (`/product` `unique-model`) and clusters in `/cpus` order.
struct Board {
    chip_id: u32,
    model: &'static str,
    target: &'static str,
    clusters: &'static [Layout],
}

/// The hosted board of each SoC `machine::soc` has a row for: the Mac mini
/// or Mac Studio where one exists, else a MacBook Pro or the A18 Pro's
/// MacBook (and the Mac15,3 the M3 boot bundle uses), with its 26A434
/// DeviceTree's clusters. The first row
/// of each chip is its base SoC, the one [`Hardware::of`] selects.
const BOARDS: &[Board] = &[
    Board {
        chip_id: 0x8103,
        model: "Macmini9,1",
        target: "J274AP",
        clusters: &[layout(EFFICIENCY, 4, 4), layout(PERFORMANCE, 4, 8)],
    },
    Board {
        chip_id: 0x6000,
        model: "MacBookPro18,3",
        target: "J314sAP",
        clusters: &[
            layout(EFFICIENCY, 2, 4),
            layout(PERFORMANCE, 4, 8),
            layout(PERFORMANCE, 4, 8),
        ],
    },
    Board {
        chip_id: 0x6001,
        model: "Mac13,1",
        target: "J375cAP",
        clusters: &[
            layout(EFFICIENCY, 2, 4),
            layout(PERFORMANCE, 4, 8),
            layout(PERFORMANCE, 4, 8),
        ],
    },
    Board {
        chip_id: 0x6002,
        model: "Mac13,2",
        target: "J375dAP",
        clusters: &[
            layout(EFFICIENCY, 2, 4),
            layout(PERFORMANCE, 4, 8),
            layout(PERFORMANCE, 4, 8),
            layout(EFFICIENCY, 2, 4),
            layout(PERFORMANCE, 4, 8),
            layout(PERFORMANCE, 4, 8),
        ],
    },
    Board {
        chip_id: 0x8112,
        model: "Mac14,3",
        target: "J473AP",
        clusters: &[layout(EFFICIENCY, 4, 4), layout(PERFORMANCE, 4, 16)],
    },
    Board {
        chip_id: 0x6020,
        model: "Mac14,12",
        target: "J474sAP",
        clusters: &[
            layout(EFFICIENCY, 4, 4),
            layout(PERFORMANCE, 4, 8),
            layout(PERFORMANCE, 4, 8),
        ],
    },
    Board {
        chip_id: 0x6021,
        model: "Mac14,13",
        target: "J475cAP",
        clusters: &[
            layout(EFFICIENCY, 4, 4),
            layout(PERFORMANCE, 4, 8),
            layout(PERFORMANCE, 4, 8),
        ],
    },
    Board {
        chip_id: 0x6022,
        model: "Mac14,14",
        target: "J475dAP",
        clusters: &[
            layout(EFFICIENCY, 4, 4),
            layout(PERFORMANCE, 4, 8),
            layout(PERFORMANCE, 4, 8),
            layout(EFFICIENCY, 4, 4),
            layout(PERFORMANCE, 4, 8),
            layout(PERFORMANCE, 4, 8),
        ],
    },
    Board {
        chip_id: 0x8122,
        model: "Mac15,3",
        target: "J504AP",
        clusters: &[layout(EFFICIENCY, 4, 4), layout(PERFORMANCE, 4, 16)],
    },
    Board {
        chip_id: 0x6030,
        model: "Mac15,6",
        target: "J514sAP",
        clusters: &[layout(EFFICIENCY, 6, 4), layout(PERFORMANCE, 6, 16)],
    },
    Board {
        chip_id: 0x6031,
        model: "Mac15,8",
        target: "J514cAP",
        clusters: &[
            layout(EFFICIENCY, 4, 4),
            layout(PERFORMANCE, 6, 16),
            layout(PERFORMANCE, 6, 16),
        ],
    },
    Board {
        chip_id: 0x6034,
        model: "Mac15,10",
        target: "J514mAP",
        clusters: &[
            layout(EFFICIENCY, 4, 4),
            layout(PERFORMANCE, 6, 16),
            layout(PERFORMANCE, 6, 16),
        ],
    },
    Board {
        chip_id: 0x6032,
        model: "Mac15,14",
        target: "J575dAP",
        clusters: &[
            layout(EFFICIENCY, 4, 4),
            layout(PERFORMANCE, 6, 16),
            layout(PERFORMANCE, 6, 16),
            layout(EFFICIENCY, 4, 4),
            layout(PERFORMANCE, 6, 16),
            layout(PERFORMANCE, 6, 16),
        ],
    },
    Board {
        chip_id: 0x8132,
        model: "Mac16,10",
        target: "J773gAP",
        clusters: &[layout(EFFICIENCY, 6, 4), layout(PERFORMANCE, 4, 16)],
    },
    Board {
        chip_id: 0x6040,
        model: "Mac16,11",
        target: "J773sAP",
        clusters: &[
            layout(EFFICIENCY, 4, 4),
            layout(PERFORMANCE, 6, 16),
            layout(PERFORMANCE, 6, 16),
        ],
    },
    Board {
        chip_id: 0x6041,
        model: "Mac16,9",
        target: "J575cAP",
        clusters: &[
            layout(EFFICIENCY, 4, 4),
            layout(PERFORMANCE, 6, 16),
            layout(PERFORMANCE, 6, 16),
        ],
    },
    // J700AP's P cores carry the A18 Pro's 16 MiB L2 as `l2-cache-size-h17p`
    // (`machine::soc::template_variant`).
    Board {
        chip_id: 0x8140,
        model: "Mac17,5",
        target: "J700AP",
        clusters: &[layout(EFFICIENCY, 4, 4), layout(PERFORMANCE, 2, 16)],
    },
    Board {
        chip_id: 0x8142,
        model: "Mac17,2",
        target: "J704AP",
        clusters: &[layout(EFFICIENCY, 6, 6), layout(PERFORMANCE, 4, 16)],
    },
    Board {
        chip_id: 0x8152,
        model: "Mac18,5",
        target: "J873gAP",
        clusters: &[layout(EFFICIENCY, 6, 8), layout(PERFORMANCE, 6, 20)],
    },
];

/// One declared guest execution cluster of identical ARM core semantics.
/// Cache capacities describe the architectural profile; they do not
/// establish native cache sharing for a shared scheduler allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cluster {
    pub cores: u8,
    pub performance: bool,
    pub l1i_bytes: u32,
    pub l1d_bytes: u32,
    /// The cluster's shared L2.
    pub l2_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hardware {
    /// None for an unallocated source profile; actual hosted execution
    /// uses a single observed shared scheduler resource plan.
    shared: Option<SharedScheduler>,
    pub chip: Chip,
    /// The SoC's ApChipID.
    pub chip_id: u32,
    /// `hw.model` and `hw.product`.
    pub model: &'static str,
    /// `hw.target`: the board.
    pub target: &'static str,
    /// The device tree's `product-soc-name`: `machdep.cpu.brand_string`.
    pub brand: &'static str,
    /// `hw.cpufamily`.
    pub cpu_family: u32,
    /// `hw.cpusubfamily`.
    pub cpu_subfamily: u32,
    pub cache_line: u32,
    /// In logical guest CPU order. Source profiles retain DeviceTree
    /// order; shared execution has one actual uniform CPU0 group.
    pub clusters: Vec<Cluster>,
    /// `hw.memsize`: the host's physical memory.
    pub memory_bytes: u64,
    /// `kern.version`: the `version[]` of the kernelcache the board boots,
    /// which the installed guest system's receipt records; `None` when the
    /// guest system did not record it.
    pub kernel_version: Option<String>,
    /// `hw.optional.breakpoint` and `hw.optional.watchpoint`: the
    /// ID_AA64DFR0_EL1 BRPs and WRPs counts the system engine's
    /// identification of the same chip presents.
    pub breakpoints: u64,
    pub watchpoints: u64,
    /// The chip implements memory tagging (FEAT_MTE and later): the
    /// ID_AA64PFR1_EL1.MTE field the system engine's identification of the
    /// same chip presents (`machine::identification::memory_tagging`).
    pub memory_tagging: bool,
}

/// The board a hosted run models unless one is chosen (`stela run
/// --model`): the primary M1 Pro MacBook Pro reference profile.
pub const DEFAULT_MODEL: &str = "MacBookPro18,3";

/// The hosted boards' product types (`hw.model`), in table order.
pub fn models() -> impl Iterator<Item = &'static str> {
    BOARDS.iter().map(|board| board.model)
}

impl Hardware {
    /// An unallocated board capability/source profile. Actual process
    /// construction must use [`Self::for_host_model`].
    pub fn of_model(model: &str, memory_bytes: u64) -> Result<Self> {
        let board = BOARDS
            .iter()
            .find(|board| board.model == model)
            .with_context(|| {
                format!(
                    "Stela models no Mac {model:?}; the models are {}",
                    models().collect::<Vec<_>>().join(", ")
                )
            })?;
        Self::of_soc(board.chip_id, memory_bytes)
    }

    /// A hosted resource plan from one native availability snapshot.
    pub fn for_host_model(model: &str, memory_bytes: u64) -> Result<Self> {
        Self::of_model(model, memory_bytes)?.with_availability(DarwinAvailability::observe()?)
    }

    /// Configure the actual uniform CPU0 execution group of the shared
    /// scheduler. No SKU core distribution, native P/E or L2 mapping is
    /// inferred from the observed physical capacity.
    pub fn with_availability(mut self, observed: DarwinAvailability) -> Result<Self> {
        let plan = SharedScheduler::new(observed)?;
        let mut cluster = *self
            .clusters
            .first()
            .context("a hosted profile has no CPU0 semantics")?;
        cluster.cores = plan.maximum;
        self.clusters = vec![cluster];
        self.shared = Some(plan);
        Ok(self)
    }

    /// The shared scheduler's native observations, without any exclusive
    /// physical assignment or affinity guarantee.
    pub fn native_availability(&self) -> Option<&DarwinAvailability> {
        self.shared.as_ref().map(|plan| &plan.observed)
    }

    /// Whether the declared clusters also qualify service cache-sharing
    /// counts. Shared execution retains CPU0's virtual architectural cache
    /// capacities, but its physical CPU budget supplies no L2 sharing map.
    /// Neither profile capacities nor these counts measure native caches.
    pub fn has_cache_sharing(&self) -> bool {
        self.shared.is_none()
    }

    /// Online logical guest CPU capacity, separately from maximum slots.
    pub fn active_cpus(&self) -> u8 {
        self.shared.map_or_else(|| self.cpus(), |plan| plan.active)
    }

    /// The base SoC of `chip`: the M1, M2, M3, M4, M5 or M6.
    pub fn of(chip: Chip, memory_bytes: u64) -> Result<Self> {
        let board = BOARDS
            .iter()
            .find(|board| soc::chip(board.chip_id) == Some(chip))
            .with_context(|| format!("{} has no hosted board", chip.name()))?;
        Self::of_soc(board.chip_id, memory_bytes)
    }

    /// The SoC with ApChipID `chip_id`, such as an M2 Pro's 0x6020.
    pub fn of_soc(chip_id: u32, memory_bytes: u64) -> Result<Self> {
        let board = BOARDS
            .iter()
            .find(|board| board.chip_id == chip_id)
            .with_context(|| format!("ApChipID {chip_id:#x} has no hosted board"))?;
        let chip = soc::chip(chip_id).context("hosted board without a SoC row")?;
        let brand = soc::name(chip_id).context("hosted board without a SoC row")?;
        let mut family = None;
        let mut clusters = Vec::with_capacity(board.clusters.len());
        for layout in board.clusters {
            let kind = char::from(layout.cluster_type);
            let part = soc::midr_part(chip_id, layout.cluster_type)
                .with_context(|| format!("{brand} cluster type {kind} has no MIDR part"))?;
            let (_, cpu_family, cpu_subfamily) = FAMILIES
                .iter()
                .find(|(known, ..)| *known == part)
                .with_context(|| format!("{brand} MIDR part {part:#x} has no CPU family"))?;
            ensure!(
                *family.get_or_insert((*cpu_family, *cpu_subfamily))
                    == (*cpu_family, *cpu_subfamily),
                "{brand}'s core types are of different CPU families"
            );
            let Some((instruction, data)) = soc::level1_caches(chip_id, layout.cluster_type) else {
                bail!(
                    "the hosted machine profile of {brand} has no public level 1 cache sizes \
                     for its {kind} cores"
                );
            };
            ensure!(
                instruction.line == CACHE_LINE && data.line == CACHE_LINE,
                "{brand}'s level 1 caches do not have Apple's 128-byte lines"
            );
            clusters.push(Cluster {
                cores: layout.cores,
                performance: layout.cluster_type == PERFORMANCE,
                l1i_bytes: instruction.bytes,
                l1d_bytes: data.bytes,
                l2_bytes: layout.l2_bytes,
            });
        }
        let (cpu_family, cpu_subfamily) = family.context("hosted board without clusters")?;
        let (breakpoints, watchpoints) = identification::breakpoints_and_watchpoints(chip);
        Ok(Self {
            shared: None,
            chip,
            chip_id,
            model: board.model,
            target: board.target,
            brand,
            cpu_family,
            cpu_subfamily,
            cache_line: CACHE_LINE,
            clusters,
            memory_bytes,
            kernel_version: None,
            breakpoints,
            watchpoints,
            memory_tagging: identification::memory_tagging(chip),
        })
    }

    /// Logical CPU 0's `/cpus` node: the first cluster's first core, whose
    /// `reg` is 0 on every 26A434 board.
    pub fn boot_processor(&self) -> soc::Processor {
        let cluster = &self.clusters[0];
        soc::Processor {
            cluster_type: if cluster.performance {
                PERFORMANCE
            } else {
                EFFICIENCY
            },
            reg: 0,
            l2_bytes: Some(cluster.l2_bytes),
        }
    }

    /// Maximum logical guest CPU slots. Shared execution budgets one per
    /// observed physical core; native SMT siblings do not add guest slots.
    pub fn cpus(&self) -> u8 {
        self.shared.map_or_else(
            || self.clusters.iter().map(|cluster| cluster.cores).sum(),
            |plan| plan.maximum,
        )
    }

    /// Configured execution groups, not a native cache-sharing count.
    pub fn cluster_count(&self) -> u8 {
        if self.shared.is_some() {
            1
        } else {
            u8::try_from(self.clusters.len())
                .expect("declared cluster count exceeds the commpage width")
        }
    }

    /// Logical CPU number → configured guest execution cluster number.
    pub fn cpu_clusters(&self) -> Vec<u8> {
        if let Some(plan) = self.shared {
            return vec![0; usize::from(plan.maximum)];
        }
        self.clusters
            .iter()
            .enumerate()
            .flat_map(|(index, cluster)| core::iter::repeat_n(index as u8, cluster.cores.into()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_profile_uses_observed_capacity_and_its_actual_cpu0_semantics() {
        let observed = DarwinAvailability {
            maximum_slots: 16,
            available_slots: 12,
            physical_active: Some(6),
            physical_maximum: Some(8),
            logical_active: Some(12),
            logical_maximum: Some(16),
        };
        for model in models() {
            let source = Hardware::of_model(model, 1 << 34).unwrap();
            let cpu0 = source.boot_processor();
            let shared = source.clone().with_availability(observed).unwrap();
            assert_eq!((shared.active_cpus(), shared.cpus()), (6, 8), "{model}");
            assert_eq!(shared.cpu_clusters(), vec![0; 8], "{model}");
            assert_eq!(shared.clusters.len(), 1, "{model}");
            let actual = shared.boot_processor();
            assert_eq!(
                (actual.cluster_type, actual.reg, actual.l2_bytes),
                (cpu0.cluster_type, cpu0.reg, cpu0.l2_bytes),
                "{model}"
            );
            assert_eq!(shared.native_availability(), Some(&observed));
            assert!(!shared.has_cache_sharing());
            assert!(source.has_cache_sharing());
            assert_eq!(shared.clusters[0].l1i_bytes, source.clusters[0].l1i_bytes);
            assert_eq!(shared.clusters[0].l1d_bytes, source.clusters[0].l1d_bytes);
            assert_eq!(shared.clusters[0].l2_bytes, source.clusters[0].l2_bytes);
            assert_eq!(
                (shared.chip_id, shared.model, shared.cpu_family),
                (source.chip_id, source.model, source.cpu_family)
            );
        }
    }

    #[test]
    fn m2_topology_is_declared() {
        let m2 = Hardware::of(Chip::AppleM2, 1 << 34).unwrap();
        assert_eq!(m2.chip_id, 0x8112);
        assert_eq!(m2.cpus(), 8);
        assert_eq!(m2.cpu_clusters(), [0, 0, 0, 0, 1, 1, 1, 1]);
        assert_eq!(m2.cpu_family, CPUFAMILY_ARM_BLIZZARD_AVALANCHE);
        assert_eq!(m2.cpu_subfamily, CPUSUBFAMILY_ARM_HG);
        assert_eq!(
            (m2.brand, m2.model, m2.target),
            ("Apple M2", "Mac14,3", "J473AP")
        );
        assert_eq!(
            m2.clusters[1],
            Cluster {
                cores: 4,
                performance: true,
                l1i_bytes: 192 << 10,
                l1d_bytes: 128 << 10,
                l2_bytes: 16 << 20,
            }
        );
        assert!(!m2.memory_tagging);
    }

    /// Each SoC variant's family and subfamily are XNU's for its parts, and
    /// the Pro and Max have a second P cluster.
    #[test]
    fn each_soc_variant_takes_its_own_family_and_clusters() {
        let cases = [
            (
                0x8103,
                CPUFAMILY_ARM_FIRESTORM_ICESTORM,
                CPUSUBFAMILY_ARM_HG,
                8,
            ),
            (
                0x6000,
                CPUFAMILY_ARM_FIRESTORM_ICESTORM,
                CPUSUBFAMILY_ARM_HS,
                10,
            ),
            (
                0x6001,
                CPUFAMILY_ARM_FIRESTORM_ICESTORM,
                CPUSUBFAMILY_ARM_HC_HD,
                10,
            ),
            (
                0x8112,
                CPUFAMILY_ARM_BLIZZARD_AVALANCHE,
                CPUSUBFAMILY_ARM_HG,
                8,
            ),
            (
                0x6020,
                CPUFAMILY_ARM_BLIZZARD_AVALANCHE,
                CPUSUBFAMILY_ARM_HS,
                12,
            ),
            (
                0x6021,
                CPUFAMILY_ARM_BLIZZARD_AVALANCHE,
                CPUSUBFAMILY_ARM_HC_HD,
                12,
            ),
            (0x8122, CPUFAMILY_ARM_IBIZA, CPUSUBFAMILY_ARM_HG, 8),
            (0x6030, CPUFAMILY_ARM_LOBOS, CPUSUBFAMILY_ARM_HS, 12),
            (0x6031, CPUFAMILY_ARM_PALMA, CPUSUBFAMILY_ARM_HC_HD, 16),
            (0x8132, CPUFAMILY_ARM_DONAN, CPUSUBFAMILY_ARM_HG, 10),
            (0x6040, CPUFAMILY_ARM_BRAVA, CPUSUBFAMILY_ARM_HS, 16),
            (0x6041, CPUFAMILY_ARM_BRAVA, CPUSUBFAMILY_ARM_HC_HD, 16),
            (0x8140, CPUFAMILY_ARM_TAHITI, CPUSUBFAMILY_ARM_HP, 6),
            (0x8142, CPUFAMILY_ARM_HIDRA, CPUSUBFAMILY_ARM_HG, 10),
            (0x8152, CPUFAMILY_ARM_KOMODO, CPUSUBFAMILY_ARM_HG, 12),
        ];
        for (chip_id, family, subfamily, cpus) in cases {
            let hardware = Hardware::of_soc(chip_id, 1 << 34).unwrap();
            assert_eq!(hardware.cpu_family, family, "{chip_id:#x}");
            assert_eq!(hardware.cpu_subfamily, subfamily, "{chip_id:#x}");
            assert_eq!(hardware.cpus(), cpus, "{chip_id:#x}");
            assert!(!hardware.clusters[0].performance);
            assert_eq!(hardware.cpu_clusters().len(), usize::from(cpus));
        }
        assert_eq!(
            Hardware::of(Chip::AppleM1, 1 << 34).unwrap().chip_id,
            0x8103
        );
        assert_eq!(
            Hardware::of(Chip::AppleM3, 1 << 34).unwrap().chip_id,
            0x8122
        );
    }

    /// A SoC without a `machine::soc` row has no hosted board and refuses
    /// by name rather than borrowing another chip's values.
    #[test]
    fn socs_without_a_row_refuse() {
        let error = Hardware::of_soc(0x6050, 1 << 34).unwrap_err().to_string();
        assert!(error.contains("no hosted board"), "{error}");
    }

    /// Every board has a hosted machine, an Ultra two dies of its Max.
    #[test]
    fn every_board_has_a_hosted_machine() {
        for board in BOARDS {
            let hardware = Hardware::of_soc(board.chip_id, 1 << 34).unwrap();
            assert_eq!(hardware.cache_line, CACHE_LINE);
            assert!(
                hardware
                    .clusters
                    .iter()
                    .all(|cluster| cluster.l1i_bytes != 0)
            );
        }
        for (ultra, max) in [(0x6002, 0x6001), (0x6022, 0x6021), (0x6032, 0x6031)] {
            let ultra = Hardware::of_soc(ultra, 1 << 34).unwrap();
            let max = Hardware::of_soc(max, 1 << 34).unwrap();
            assert_eq!(ultra.cpus(), 2 * max.cpus());
            assert_eq!(ultra.cpu_family, max.cpu_family);
            assert_eq!(&ultra.clusters[..3], &max.clusters[..]);
            assert_eq!(&ultra.clusters[3..], &max.clusters[..]);
        }
    }

    /// The debug counts are the identification's; the kernel version is the
    /// installed guest system's, never a built-in value.
    #[test]
    fn the_debug_counts_are_the_chips_and_the_kernel_version_the_installs() {
        let m2 = Hardware::of(Chip::AppleM2, 1 << 34).unwrap();
        assert_eq!((m2.breakpoints, m2.watchpoints), (6, 4));
        assert_eq!(m2.kernel_version, None);
    }

    /// Every board's SoC has a row whose parts XNU's families cover, and
    /// every chip's base SoC comes first.
    #[test]
    fn every_board_names_a_soc_row_with_known_families() {
        for board in BOARDS {
            for layout in board.clusters {
                let part = soc::midr_part(board.chip_id, layout.cluster_type).unwrap();
                assert!(
                    FAMILIES.iter().any(|(known, ..)| *known == part),
                    "{part:#x}"
                );
            }
        }
        for chip in Chip::ALL {
            let first = BOARDS
                .iter()
                .find(|board| soc::chip(board.chip_id) == Some(chip))
                .unwrap();
            assert_eq!(first.chip_id & 0xf000, 0x8000, "{}", chip.name());
        }
    }
}
