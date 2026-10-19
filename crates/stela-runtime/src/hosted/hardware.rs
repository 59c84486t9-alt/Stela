//! The Apple-silicon machine a hosted process observes: the chip's CPU
//! family, topology and cache line, which the commpage and the `hw.*`
//! sysctls report instead of the x86 host's. Memory size is the host's, as
//! the guest's allocations are.
//!
//! Values from XNU `osfmk/mach/machine.h` (CPU types, subtypes, families)
//! and the M2's published topology: four Avalanche performance cores and
//! four Blizzard efficiency cores in two clusters, 128-byte cache lines.
use crate::machine::Chip;
use anyhow::{Result, bail};

pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;
pub const CPU_SUBTYPE_ARM64E: u32 = 2;
/// `CPU_SUBTYPE_MASK`: the capability bits above the subtype.
pub const CPU_SUBTYPE_MASK: u32 = 0xff00_0000;
/// `CPU_SUBTYPE_PTRAUTH_ABI`: an arm64e process using the stable PAC ABI.
pub const CPU_SUBTYPE_PTRAUTH_ABI: u32 = 0x8000_0000;
pub const CPUFAMILY_ARM_BLIZZARD_AVALANCHE: u32 = 0xda33_d83d;

/// One cluster of identical cores.
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
    pub chip: Chip,
    /// `hw.model` and `hw.product`.
    pub model: &'static str,
    /// `hw.target`: the board.
    pub target: &'static str,
    /// The device tree's `product-soc-name`: `machdep.cpu.brand_string`.
    pub brand: &'static str,
    pub cpu_family: u32,
    pub cache_line: u32,
    /// In logical CPU order: XNU numbers the efficiency cluster first.
    pub clusters: Vec<Cluster>,
    /// `hw.memsize`: the host's physical memory.
    pub memory_bytes: u64,
}

impl Hardware {
    pub fn of(chip: Chip, memory_bytes: u64) -> Result<Self> {
        let (cpu_family, model, target, brand, clusters) = match chip {
            // The Mac mini (M2, 2023): Blizzard cores with 128 KiB L1I,
            // 64 KiB L1D and a 4 MiB L2; Avalanche cores with 192 KiB L1I,
            // 128 KiB L1D and a 16 MiB L2.
            Chip::AppleM2 => (
                CPUFAMILY_ARM_BLIZZARD_AVALANCHE,
                "Mac14,3",
                "J473AP",
                "Apple M2",
                vec![
                    Cluster {
                        cores: 4,
                        performance: false,
                        l1i_bytes: 128 << 10,
                        l1d_bytes: 64 << 10,
                        l2_bytes: 4 << 20,
                    },
                    Cluster {
                        cores: 4,
                        performance: true,
                        l1i_bytes: 192 << 10,
                        l1d_bytes: 128 << 10,
                        l2_bytes: 16 << 20,
                    },
                ],
            ),
            other => bail!(
                "the hosted machine profile of {} (CPU family and topology) is not declared",
                other.name()
            ),
        };
        Ok(Self {
            chip,
            model,
            target,
            brand,
            cpu_family,
            cache_line: 128,
            clusters,
            memory_bytes,
        })
    }

    pub fn cpus(&self) -> u8 {
        self.clusters.iter().map(|cluster| cluster.cores).sum()
    }

    /// Logical CPU number → cluster number.
    pub fn cpu_clusters(&self) -> Vec<u8> {
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
    fn m2_topology_is_declared_and_others_refuse() {
        let m2 = Hardware::of(Chip::AppleM2, 1 << 34).unwrap();
        assert_eq!(m2.cpus(), 8);
        assert_eq!(m2.cpu_clusters(), [0, 0, 0, 0, 1, 1, 1, 1]);
        assert!(Hardware::of(Chip::AppleM1, 1 << 34).is_err());
    }
}
