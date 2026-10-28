//! Original per-PE startup registers, independent of legacy PIO lockdown.
use super::Node;
use crate::platform::apple::lockdown;
use alloc::{format, string::String, vec::Vec};

/// One original `cpu-impl-reg` block, with no inferred lockdown offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessorRegisters {
    pub cpu: usize,
    pub physical: u64,
    pub bytes: u64,
}

/// Every PE owns exactly one original complete block. The words XNU and
/// m1n1 use are defined by `lockdown::PE_WORDS`, independently of CTRR.
/// This descriptor grants neither a reset address nor a legacy lock pair.
pub(super) fn processor_registers(root: &Node<'_>) -> Result<Vec<ProcessorRegisters>, String> {
    let cpus = root.child("cpus").ok_or("DeviceTree has no /cpus")?;
    let mut result: Vec<ProcessorRegisters> = Vec::new();
    let mut failure = None;
    cpus.visit(&mut |node| {
        if failure.is_some() || node.property("cluster-type").is_none() {
            return;
        }
        let cpu = result.len();
        let parse = || -> Result<ProcessorRegisters, String> {
            let raw = node
                .property("cpu-impl-reg")
                .filter(|raw| raw.len() == 16)
                .ok_or_else(|| {
                    format!("PE {cpu} cpu-impl-reg must be one complete address/size pair")
                })?;
            let physical = u64::from_le_bytes(raw[..8].try_into().expect("checked address"));
            let bytes = u64::from_le_bytes(raw[8..].try_into().expect("checked size"));
            let end = physical
                .checked_add(bytes)
                .ok_or_else(|| format!("PE {cpu} cpu-impl-reg extent wraps"))?;
            if !physical.is_multiple_of(lockdown::WORD_BYTES)
                || lockdown::PE_WORDS.iter().any(|offset| {
                    offset
                        .checked_add(lockdown::WORD_BYTES)
                        .is_none_or(|last| last > bytes)
                })
                || result
                    .iter()
                    .any(|other| physical < other.physical + other.bytes && other.physical < end)
            {
                return Err(format!(
                    "PE {cpu} cpu-impl-reg is unaligned, short or aliases another PE"
                ));
            }
            Ok(ProcessorRegisters {
                cpu,
                physical,
                bytes,
            })
        };
        match parse() {
            Ok(block) => result.push(block),
            Err(error) => failure = Some(error),
        }
    })
    .ok_or("DeviceTree CPU register walk failed")?;
    match failure {
        Some(error) => Err(error),
        None => Ok(result),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_contracts::adt::encode;

    fn tree(blocks: &[Vec<u8>]) -> Vec<u8> {
        let children: Vec<_> = blocks
            .iter()
            .map(|raw| {
                encode(
                    &[
                        ("name", b"cpu\0"),
                        ("cluster-type", b"P"),
                        ("cpu-impl-reg", raw),
                    ],
                    &[],
                )
            })
            .collect();
        encode(
            &[("name", b"device-tree\0")],
            &[encode(&[("name", b"cpus\0")], &children)],
        )
    }
    fn range(physical: u64, bytes: u64) -> Vec<u8> {
        [physical.to_le_bytes(), bytes.to_le_bytes()].concat()
    }

    #[test]
    fn startup_blocks_preserve_each_pe_without_a_lockdown_requirement() {
        let raw = tree(&[range(0x200000000, 0x4000), range(0x200010000, 0x4000)]);
        assert_eq!(
            processor_registers(&Node::root(&raw).unwrap()).unwrap(),
            [
                ProcessorRegisters {
                    cpu: 0,
                    physical: 0x200000000,
                    bytes: 0x4000
                },
                ProcessorRegisters {
                    cpu: 1,
                    physical: 0x200010000,
                    bytes: 0x4000
                },
            ]
        );
    }

    #[test]
    fn malformed_or_aliasing_startup_blocks_never_return_a_partial_roster() {
        let good = range(0x200000000, 0x4000);
        for bad in [
            vec![],
            vec![0; 15],
            [good.clone(), good.clone()].concat(),
            range(u64::MAX - 7, 16),
            range(0x200008001, 0x4000),
            range(0x200008000, lockdown::CORE_THRTL_CFG2 + 4),
            range(0x200000000, 0x4000),
            range(0x200002000, 0x4000),
        ] {
            let raw = tree(&[good.clone(), bad]);
            assert!(processor_registers(&Node::root(&raw).unwrap()).is_err());
        }
    }
}
