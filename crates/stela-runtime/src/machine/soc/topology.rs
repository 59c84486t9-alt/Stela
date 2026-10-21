//! Validate the DeviceTree's PE affinities before constructing identities.
//!
//! `reg` names one physical PE independently of its cluster type; adding a
//! synthetic MPIDR Aff2 for a P core must never make a duplicated `reg`
//! appear to be another CPU. Cores sharing an Aff1 cluster describe one
//! cluster type and one shared L2 capacity. No fixed cluster/core count or
//! generation label participates in this validation.
use super::Processor;
use alloc::{format, string::String};

pub(super) fn validate(processors: &[Processor]) -> Result<(), String> {
    for (index, processor) in processors.iter().enumerate() {
        for previous in &processors[..index] {
            if previous.reg == processor.reg {
                return Err(format!("duplicate CPU affinity reg {:#x}", processor.reg));
            }
            if previous.reg >> 8 == processor.reg >> 8 {
                if previous.cluster_type != processor.cluster_type {
                    return Err(format!(
                        "CPU cluster {:#x} has conflicting cluster types",
                        processor.reg >> 8
                    ));
                }
                if previous.l2_bytes != processor.l2_bytes {
                    return Err(format!(
                        "CPU cluster {:#x} has conflicting l2-cache-size values",
                        processor.reg >> 8
                    ));
                }
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

    #[test]
    fn duplicate_affinities_cannot_be_hidden_by_different_cluster_types() {
        for kind in [b'E', b'P'] {
            let processors = [pe(b'E', 0, Some(4 << 20)), pe(kind, 0, Some(4 << 20))];
            assert!(
                validate(&processors)
                    .unwrap_err()
                    .contains("duplicate CPU affinity")
            );
        }
    }

    #[test]
    fn one_physical_cluster_has_one_type_and_shared_cache_geometry() {
        let first = pe(b'P', 0x100, Some(16 << 20));
        for second in [
            pe(b'E', 0x101, Some(16 << 20)),
            pe(b'P', 0x101, Some(8 << 20)),
            pe(b'P', 0x101, None),
        ] {
            assert!(validate(&[first, second]).is_err());
        }
    }

    #[test]
    fn heterogeneous_and_multidie_clusters_remain_independent() {
        let processors = [
            pe(b'E', 0, Some(4 << 20)),
            pe(b'E', 3, Some(4 << 20)),
            pe(b'P', 0x100, Some(16 << 20)),
            pe(b'P', 0x105, Some(16 << 20)),
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
}
