//! The running handoff PE, preserving the board's processor indices.
use super::{Node, Processor};
use crate::Result;
use alloc::{format, string::String};
use stela_contracts::refuse;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootProcessor {
    /// Index into the unchanged prepared processor/resource roster.
    pub cpu: usize,
    pub path: String,
    pub affinity: u32,
    pub cluster_type: u8,
}

/// Original templates can have no running node. A boot bundle's provenance
/// intake additionally requires one, bound to the immutable original tree.
/// This parser only joins the published state to the exact board roster.
pub(super) fn boot_processor(
    root: &Node<'_>,
    processors: &[Processor],
) -> Result<Option<BootProcessor>> {
    let children = root
        .child("cpus")
        .and_then(|cpus| cpus.children())
        .ok_or(refuse!("DeviceTree has no complete /cpus roster"))?;
    let nodes: alloc::vec::Vec<_> = children
        .iter()
        .filter(|cpu| cpu.property("cluster-type").is_some())
        .collect();
    if nodes.len() != processors.len() {
        return Err(refuse!(
            "handoff CPU nodes differ from the processor roster"
        ));
    }
    let mut boot = None;
    for (cpu, (node, processor)) in nodes.iter().zip(processors).enumerate() {
        match node.property("state") {
            None | Some(b"waiting\0") => continue,
            Some(b"running\0") => {}
            Some(_) => return Err(refuse!("PE {cpu} state is not running or waiting", cpu)),
        }
        if boot.is_some() {
            return Err(refuse!("DeviceTree has more than one running CPU"));
        }
        let name = node
            .property("name")
            .and_then(|name| name.strip_suffix(&[0]))
            .and_then(|name| core::str::from_utf8(name).ok())
            .filter(|name| {
                !name.is_empty() && !name.contains(['/', '\0']) && !matches!(*name, "." | "..")
            })
            .ok_or(refuse!("running CPU has no unique child name"))?;
        if nodes
            .iter()
            .filter(|other| other.property("name") == node.property("name"))
            .count()
            != 1
        {
            return Err(refuse!("running CPU has an ambiguous child name"));
        }
        if node.property("reg") != Some(processor.reg.to_le_bytes().as_slice())
            || node.property("cluster-type") != Some([processor.cluster_type, 0].as_slice())
        {
            return Err(refuse!(
                "running CPU identity differs from the processor roster"
            ));
        }
        boot = Some(BootProcessor {
            cpu,
            path: format!("/cpus/{name}"),
            affinity: processor.reg,
            cluster_type: processor.cluster_type,
        });
    }
    Ok(boot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use stela_contracts::adt::encode;

    fn tree(states: &[Option<&[u8]>]) -> Vec<u8> {
        let children: Vec<_> = states
            .iter()
            .enumerate()
            .map(|(index, state)| {
                let reg = (index as u32 * 0x100).to_le_bytes();
                let name = format!("cpu{}\0", 9 - index);
                let mut fields = alloc::vec![
                    ("name", name.as_bytes()),
                    ("cluster-type", b"P\0".as_slice()),
                    ("reg", reg.as_slice())
                ];
                if let Some(state) = state {
                    fields.push(("state", state));
                }
                encode(&fields, &[])
            })
            .collect();
        encode(
            &[("name", b"device-tree\0")],
            &[encode(&[("name", b"cpus\0")], &children)],
        )
    }

    fn roster() -> [Processor; 2] {
        [
            Processor {
                cluster_type: b'P',
                reg: 0,
                l2_bytes: None,
            },
            Processor {
                cluster_type: b'P',
                reg: 0x100,
                l2_bytes: None,
            },
        ]
    }

    #[test]
    fn running_state_selects_an_existing_pe_without_sorting_names_or_affinities() {
        let bytes = tree(&[Some(b"waiting\0"), Some(b"running\0")]);
        assert_eq!(
            boot_processor(&Node::root(&bytes).unwrap(), &roster()).unwrap(),
            Some(BootProcessor {
                cpu: 1,
                path: "/cpus/cpu8".into(),
                affinity: 0x100,
                cluster_type: b'P'
            })
        );
        for states in [
            [None, None],
            [Some(b"waiting\0".as_slice()), Some(b"waiting\0")],
        ] {
            let bytes = tree(&states);
            assert_eq!(
                boot_processor(&Node::root(&bytes).unwrap(), &roster()).unwrap(),
                None
            );
        }
    }

    #[test]
    fn ambiguous_or_malformed_running_state_cannot_select_a_pe() {
        for states in [
            [b"running\0".as_slice(), b"running\0".as_slice()],
            [b"waiting\0", b"running"],
            [b"unknown\0", b"running\0"],
        ] {
            let bytes = tree(&states.map(Some));
            assert!(boot_processor(&Node::root(&bytes).unwrap(), &roster()).is_err());
        }
        let bytes = tree(&[Some(b"waiting\0"), Some(b"running\0")]);
        let mut wrong = roster();
        wrong[1].reg = 1;
        assert!(boot_processor(&Node::root(&bytes).unwrap(), &wrong).is_err());
        assert!(boot_processor(&Node::root(&bytes).unwrap(), &roster()[..1]).is_err());
    }
}
