//! Validate the DeviceTree's PE affinities before constructing identities.
//!
//! `reg` names one physical PE independently of its cluster type; adding a
//! synthetic MPIDR Aff2 for a P core must never make a duplicated `reg`
//! appear to be another CPU. Cores sharing an Aff1 cluster describe one
//! shared L2 capacity. A cluster may mix core types, as the T8152's original
//! DeviceTree mixes P and M cores in cluster 1. No fixed cluster/core count or
//! generation label participates in this validation.
pub mod assigned;

use super::Processor;
use crate::Result;
use alloc::collections::BTreeMap;
use stela_contracts::refuse;

/// A kernel's compiled CPU topology bounds: CPUs, clusters and the highest
/// physical cluster number (MPIDR Aff1). XNU's `ml_parse_cpu_topology`
/// checks them only with `assert`, which release kernels compile out, so a
/// DeviceTree beyond them overruns the kernel's CPU and cluster arrays
/// silently (`osfmk/arm64/machine_routines.c`). Its per-cluster CPU offset
/// table also needs the sum over clusters of the highest Aff0 plus one to
/// fit the CPU count, so holes in Aff0 consume slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelLimits {
    cpus: usize,
    clusters: usize,
    cluster_id: u32,
}

impl KernelLimits {
    pub const fn new(cpus: usize, clusters: usize, cluster_id: u32) -> Self {
        Self {
            cpus,
            clusters,
            cluster_id,
        }
    }

    /// Refuse `processors` that exceed these bounds.
    pub fn check(self, processors: &[Processor]) -> Result<()> {
        let mut spans = BTreeMap::new();
        for processor in processors {
            let span = spans.entry(processor.reg >> 8).or_insert(0);
            *span = (*span).max((processor.reg & 0xff) as usize + 1);
        }
        let cluster_id = spans.keys().copied().max().unwrap_or(0);
        let span: usize = spans.values().sum();
        if processors.len() > self.cpus {
            return Err(refuse!(
                "{processors_len} CPUs exceed the kernel's {cpus} (MAX_CPUS)",
                processors_len = processors.len(),
                cpus = self.cpus
            ));
        }
        if spans.len() > self.clusters {
            return Err(refuse!(
                "{spans_len} CPU clusters exceed the kernel's {clusters} (MAX_CPU_CLUSTERS)",
                spans_len = spans.len(),
                clusters = self.clusters
            ));
        }
        if cluster_id > self.cluster_id {
            return Err(refuse!(
                "CPU cluster {cluster_id} exceeds the kernel's highest, {cluster_id2} (MAX_CPU_CLUSTER_PHY_ID)",
                cluster_id,
                cluster_id2 = self.cluster_id
            ));
        }
        if span > self.cpus {
            return Err(refuse!(
                "the clusters' Aff0 spans need {span} CPU slots, beyond the kernel's {cpus}",
                span,
                cpus = self.cpus
            ));
        }
        Ok(())
    }
}

pub(super) fn validate(processors: &[Processor]) -> Result<()> {
    for (index, processor) in processors.iter().enumerate() {
        for previous in &processors[..index] {
            if previous.reg == processor.reg {
                return Err(refuse!(
                    "duplicate CPU affinity reg {reg:#x}",
                    reg = processor.reg
                ));
            }
            if previous.reg >> 8 == processor.reg >> 8 && previous.l2_bytes != processor.l2_bytes {
                return Err(refuse!(
                    "CPU cluster {cluster:#x} has conflicting l2-cache-size values",
                    cluster = processor.reg >> 8
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe(kind: u8, reg: u32, l2: Option<u32>) -> Processor {
        Processor {
            cluster_type: kind,
            reg,
            l2_bytes: l2,
        }
    }

    /// XNU's T6000 bounds (20 CPUs, 6 clusters, cluster 10) admit the M1
    /// Ultra's J375d topology and refuse one CPU, cluster, cluster number
    /// or Aff0 slot more.
    #[test]
    fn kernel_limits_bound_cpus_clusters_cluster_ids_and_aff0_spans() {
        let limits = KernelLimits::new(20, 6, 10);
        let mut j375d = alloc::vec::Vec::new();
        for die in [0, 0x800] {
            j375d.extend([0, 1].map(|core| pe(b'E', die | core, Some(4 << 20))));
            for cluster in [0x100, 0x200] {
                j375d.extend((0..4).map(|core| pe(b'P', die | cluster | core, Some(16 << 20))));
            }
        }
        assert_eq!(limits.check(&j375d), Ok(()));
        let mut more = j375d.clone();
        more.push(pe(b'E', 2, Some(4 << 20)));
        assert!(
            limits
                .check(&more)
                .unwrap_err()
                .to_string()
                .contains("MAX_CPUS")
        );
        let clusters: alloc::vec::Vec<_> = (0..7).map(|c| pe(b'P', c << 8, None)).collect();
        assert!(
            limits
                .check(&clusters)
                .unwrap_err()
                .to_string()
                .contains("MAX_CPU_CLUSTERS")
        );
        assert!(
            limits
                .check(&[pe(b'P', 0xb00, None)])
                .unwrap_err()
                .to_string()
                .contains("PHY_ID")
        );
        // Two cores at Aff0 0 and 15 of each of two clusters need 32 slots.
        let sparse = [0x000, 0x00f, 0x100, 0x10f].map(|reg| pe(b'P', reg, None));
        assert!(
            limits
                .check(&sparse)
                .unwrap_err()
                .to_string()
                .contains("Aff0 spans")
        );
    }

    #[test]
    fn duplicate_affinities_cannot_be_hidden_by_different_cluster_types() {
        for kind in *b"EP" {
            let processors = [pe(b'E', 0, Some(4 << 20)), pe(kind, 0, Some(4 << 20))];
            assert!(
                validate(&processors)
                    .unwrap_err()
                    .to_string()
                    .contains("duplicate CPU affinity")
            );
        }
    }

    #[test]
    fn one_physical_cluster_has_one_shared_cache_geometry() {
        let first = pe(b'P', 0x100, Some(16 << 20));
        for second in [pe(b'P', 0x101, Some(8 << 20)), pe(b'P', 0x101, None)] {
            assert!(validate(&[first, second]).is_err());
        }
    }

    #[test]
    fn heterogeneous_and_multidie_clusters_remain_independent() {
        let processors = [
            pe(b'E', 0, Some(4 << 20)),
            pe(b'E', 3, Some(4 << 20)),
            pe(b'P', 0x100, Some(16 << 20)),
            pe(b'M', 0x105, Some(16 << 20)),
            pe(b'E', 0x800, Some(8 << 20)),
            pe(b'E', 0x801, Some(8 << 20)),
            pe(b'P', 0x900, Some(24 << 20)),
            pe(b'P', 0x905, Some(24 << 20)),
        ];
        assert!(validate(&processors).is_ok());
        // Unknown cluster letters and absent caches are handled by the
        // SoC's capability binding, not guessed by topology validation.
        assert!(validate(&[pe(b'M', 0xa00, None), pe(b'M', 0xa01, None)]).is_ok());
    }
    /// Original Firmware/all_flash/DeviceTree.j873gap.im4p, decoded SHA-256
    /// 3252a3f13dc025ffa8551c7a5da6a71501f76ea6c5d38aa35390f9268a6dc378:
    /// cpu6/7 are P and cpu8..11 are M inside the same Aff1 cluster.
    #[test]
    fn original_m6_mixed_performance_cluster_is_valid_topology() {
        let processors = [
            pe(b'E', 0, Some(8 << 20)),
            pe(b'E', 1, Some(8 << 20)),
            pe(b'E', 2, Some(8 << 20)),
            pe(b'E', 3, Some(8 << 20)),
            pe(b'E', 4, Some(8 << 20)),
            pe(b'E', 5, Some(8 << 20)),
            pe(b'P', 0x100, Some(20 << 20)),
            pe(b'P', 0x101, Some(20 << 20)),
            pe(b'M', 0x102, Some(20 << 20)),
            pe(b'M', 0x103, Some(20 << 20)),
            pe(b'M', 0x104, Some(20 << 20)),
            pe(b'M', 0x105, Some(20 << 20)),
        ];
        assert!(validate(&processors).is_ok());
        let cores = super::super::core_types(0x8152).unwrap();
        let mpidrs: alloc::vec::Vec<_> = processors
            .iter()
            .map(|pe| {
                cores
                    .iter()
                    .find(|core| core.cluster_type == pe.cluster_type)
                    .unwrap()
                    .mpidr(pe.reg)
                    .unwrap()
            })
            .collect();
        assert_eq!(
            mpidrs,
            [
                0x8000_0000,
                0x8000_0001,
                0x8000_0002,
                0x8000_0003,
                0x8000_0004,
                0x8000_0005,
                0x8001_0100,
                0x8001_0101,
                0x8004_0102,
                0x8004_0103,
                0x8004_0104,
                0x8004_0105,
            ]
        );
        // XNU groups physical clusters using DT reg, independently of
        // core type. The M affinity must not split this shared P/M L2.
        for (pe, mpidr) in processors.iter().zip(&mpidrs) {
            assert_eq!(
                (*mpidr >> 16) & 7,
                u64::from(match pe.cluster_type {
                    b'E' => 0u8,
                    b'P' => 1,
                    b'M' => 4,
                    _ => unreachable!(),
                })
            );
            assert_eq!((*mpidr >> 8) & 0xf, u64::from(pe.reg >> 8));
            assert_eq!(*mpidr & 0xff, u64::from(pe.reg & 0xff));
        }
        assert_eq!(
            mpidrs
                .iter()
                .filter(|mpidr| (*mpidr >> 8) & 0xf == 1)
                .count(),
            6
        );
    }
}
