//! Selected PE provenance and the prepared CPU sequence retained across loading.
use alloc::{format, string::String, vec::Vec};
use stela_loader::apple_device_tree::{DeviceTree, Node, Property};
use stela_runtime::boot_bundle::{BootCpu, BootCpuSelection};

#[derive(Debug, PartialEq, Eq)]
struct Cpu {
    path: String,
    affinity: u32,
    cluster_type: u8,
    running: bool,
}

fn property<'a>(node: &'a Node, name: &str) -> Result<&'a Property, String> {
    let mut properties = node.properties.iter().filter(|p| p.name() == name);
    let property = properties
        .next()
        .ok_or_else(|| format!("boot CPU topology lacks {name}"))?;
    if properties.next().is_some() || property.placeholder {
        return Err(format!(
            "boot CPU topology has ambiguous or unresolved {name}"
        ));
    }
    Ok(property)
}

fn cpus(tree: &DeviceTree) -> Result<Vec<Cpu>, String> {
    // Node lookups select the first matching child. Refuse duplicate structural
    // containers instead of letting source and runtime choose different lists.
    if tree
        .root
        .children
        .iter()
        .filter(|n| n.name() == Some("cpus"))
        .count()
        != 1
    {
        return Err("boot CPU topology requires exactly one /cpus".into());
    }
    let parent = tree.node("/cpus").ok_or("boot CPU topology lacks /cpus")?;
    property(parent, "name")?;
    if parent.children.is_empty() {
        return Err("boot CPU topology is empty".into());
    }
    let mut cpus: Vec<Cpu> = Vec::new();
    for node in &parent.children {
        let name = property(node, "name")?
            .as_str()
            .ok_or("boot CPU name is not UTF-8")?;
        if name.is_empty() || name.contains('/') || matches!(name, "." | "..") {
            return Err("boot CPU name is not one original child component".into());
        }
        let path = format!("/cpus/{name}");
        let cluster_type = match property(node, "cluster-type")?.value.as_slice() {
            [kind @ (b'E' | b'P' | b'M'), 0] => *kind,
            _ => return Err(format!("{path} has no original E/P/M cluster-type")),
        };
        let affinity = property(node, "reg")?
            .as_u32()
            .ok_or_else(|| format!("{path} affinity is not one u32"))?;
        let running = match property(node, "state")?.value.as_slice() {
            b"running\0" => true,
            b"waiting\0" => false,
            _ => return Err(format!("{path} state is not running or waiting")),
        };
        if cpus
            .iter()
            .any(|cpu| cpu.path == path || cpu.affinity == affinity)
        {
            return Err("boot CPU topology repeats a path or raw affinity".into());
        }
        cpus.push(Cpu {
            path,
            affinity,
            cluster_type,
            running,
        });
    }
    Ok(cpus)
}

fn identity(cpu: &Cpu, selected: &BootCpu) -> bool {
    cpu.path == selected.path
        && cpu.affinity == selected.affinity
        && cpu.cluster_type == selected.cluster_type
}

/// Immutable prepared sequence: live patches may change memory facts, but may
/// neither replace a CPU nor change its position or selected running state.
pub(super) struct Prepared {
    cpus: Vec<Cpu>,
    processor: usize,
}

impl Prepared {
    pub(super) fn verify(
        original: &DeviceTree,
        prepared: &DeviceTree,
        selected: &BootCpu,
    ) -> Result<Self, String> {
        let source = cpus(original)?;
        let cpus = cpus(prepared)?;
        if !source
            .get(selected.original_index)
            .is_some_and(|cpu| identity(cpu, selected))
        {
            return Err(
                "boot_cpu differs from its original path/index/affinity/cluster-type".into(),
            );
        }
        let mut previous = None;
        for cpu in &cpus {
            let index = source
                .iter()
                .position(|original| {
                    original.path == cpu.path
                        && original.affinity == cpu.affinity
                        && original.cluster_type == cpu.cluster_type
                })
                .ok_or("prepared CPU differs from its immutable original identity")?;
            if previous.is_some_and(|previous| index <= previous) {
                return Err("prepared CPUs reorder the original topology".into());
            }
            previous = Some(index);
        }
        let processor = cpus
            .iter()
            .position(|cpu| identity(cpu, selected))
            .ok_or("selected original CPU is absent from prepared topology")?;
        if cpus.iter().filter(|cpu| cpu.running).count() != 1 || !cpus[processor].running {
            return Err("prepared topology must have exactly one running selected CPU".into());
        }
        if selected.selection == BootCpuSelection::FirstPerformance
            && cpus.iter().position(|cpu| cpu.cluster_type == b'P') != Some(processor)
        {
            return Err("automatic boot CPU is not the first retained original P-core".into());
        }
        Ok(Self { cpus, processor })
    }

    pub(super) fn processor(&self) -> usize {
        self.processor
    }

    pub(super) fn validate_live(&self, tree: &DeviceTree) -> Result<(), String> {
        if cpus(tree)? != self.cpus {
            return Err(
                "live CPU identities/order/running state differ from verified preparation".into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn tree(running: Option<&str>) -> DeviceTree {
        let mut tree = DeviceTree {
            root: Node::named("device-tree").unwrap(),
        };
        tree.ensure_child("/", "cpus").unwrap();
        // Neither node names nor affinities are sorted; DT traversal is authority.
        for (name, affinity, kind) in [
            ("cpu9", 1u32, b'E'),
            ("cpu4", 0x101, b'P'),
            ("cpu2", 0x100, b'P'),
        ] {
            tree.ensure_child("/cpus", name).unwrap();
            let path = format!("/cpus/{name}");
            for (key, value) in [
                ("reg", affinity.to_le_bytes().to_vec()),
                ("cluster-type", vec![kind, 0]),
                (
                    "state",
                    if running == Some(name) {
                        b"running\0".to_vec()
                    } else {
                        b"waiting\0".to_vec()
                    },
                ),
            ] {
                tree.set_property(&path, key, value).unwrap();
            }
        }
        tree
    }

    fn selected() -> BootCpu {
        BootCpu {
            path: "/cpus/cpu4".into(),
            affinity: 0x101,
            cluster_type: b'P',
            original_index: 1,
            selection: BootCpuSelection::FirstPerformance,
        }
    }

    #[test]
    fn selected_pe_uses_retained_prepared_order_and_immutable_source_index() {
        let original = tree(None);
        let prepared = tree(Some("cpu4"));
        let record = selected();
        let contract = Prepared::verify(&original, &prepared, &record).unwrap();
        assert_eq!(contract.processor(), 1);
        assert!(contract.validate_live(&prepared).is_ok());
        let mut retained = prepared.clone();
        retained.node_mut("/cpus").unwrap().children.remove(0);
        let contract = Prepared::verify(&original, &retained, &record).unwrap();
        assert_eq!(contract.processor(), 0);
        assert_eq!(record.original_index, 1);
        assert!(contract.validate_live(&retained).is_ok());
        // A variant may remove the first source P. Select the first retained P.
        let mut retained = tree(Some("cpu2"));
        retained.node_mut("/cpus").unwrap().children.remove(1);
        let record = BootCpu {
            path: "/cpus/cpu2".into(),
            affinity: 0x100,
            original_index: 2,
            ..record
        };
        assert_eq!(
            Prepared::verify(&original, &retained, &record)
                .unwrap()
                .processor(),
            1
        );
    }

    #[test]
    fn explicit_override_does_not_authorize_an_automatic_later_p_or_wrong_source_identity() {
        let original = tree(None);
        let prepared = tree(Some("cpu9"));
        let explicit = BootCpu {
            path: "/cpus/cpu9".into(),
            affinity: 1,
            cluster_type: b'E',
            original_index: 0,
            selection: BootCpuSelection::Explicit,
        };
        assert_eq!(
            Prepared::verify(&original, &prepared, &explicit)
                .unwrap()
                .processor(),
            0
        );
        let automatic = BootCpu {
            selection: BootCpuSelection::FirstPerformance,
            ..explicit
        };
        assert!(Prepared::verify(&original, &prepared, &automatic).is_err());
        let prepared = tree(Some("cpu2"));
        let later = BootCpu {
            path: "/cpus/cpu2".into(),
            affinity: 0x100,
            original_index: 2,
            ..selected()
        };
        assert!(Prepared::verify(&original, &prepared, &later).is_err());
        let prepared = tree(Some("cpu4"));
        for wrong in [
            BootCpu {
                path: "/cpus/unknown".into(),
                ..selected()
            },
            BootCpu {
                affinity: 0x100,
                ..selected()
            },
            BootCpu {
                cluster_type: b'E',
                ..selected()
            },
            BootCpu {
                original_index: 0,
                ..selected()
            },
            BootCpu {
                original_index: usize::MAX,
                ..selected()
            },
        ] {
            assert!(Prepared::verify(&original, &prepared, &wrong).is_err());
        }
    }

    #[test]
    fn changed_prepared_or_live_cpu_sequences_and_running_states_refuse() {
        let original = tree(None);
        let prepared = tree(Some("cpu4"));
        let contract = Prepared::verify(&original, &prepared, &selected()).unwrap();
        let mut mutations = vec![tree(None), tree(Some("cpu2"))];
        let mut extra_running = prepared.clone();
        extra_running
            .set_property("/cpus/cpu9", "state", b"running\0".to_vec())
            .unwrap();
        mutations.push(extra_running);
        let mut reordered = prepared.clone();
        reordered.node_mut("/cpus").unwrap().children.swap(0, 2);
        mutations.push(reordered);
        let mut deleted = prepared.clone();
        deleted.node_mut("/cpus").unwrap().children.remove(2);
        // Preparation may retain a proper subsequence; live patches cannot prune it.
        assert!(Prepared::verify(&original, &deleted, &selected()).is_ok());
        assert!(contract.validate_live(&deleted).is_err());
        for (key, value) in [
            ("name", b"renamed\0".to_vec()),
            ("reg", 2u32.to_le_bytes().to_vec()),
            ("cluster-type", b"E\0".to_vec()),
        ] {
            let mut changed = prepared.clone();
            changed.set_property("/cpus/cpu4", key, value).unwrap();
            mutations.push(changed);
        }
        for changed in mutations {
            assert!(Prepared::verify(&original, &changed, &selected()).is_err());
            assert!(contract.validate_live(&changed).is_err());
        }
    }

    #[test]
    fn duplicate_malformed_and_unresolved_cpu_fields_are_never_authority() {
        let original = tree(None);
        let prepared = tree(Some("cpu4"));
        for key in ["name", "reg", "cluster-type", "state"] {
            let mut duplicate = prepared.clone();
            let node = duplicate.node_mut("/cpus/cpu4").unwrap();
            node.properties.push(node.property(key).unwrap().clone());
            let mut unresolved = prepared.clone();
            unresolved
                .node_mut("/cpus/cpu4")
                .unwrap()
                .property_mut(key)
                .unwrap()
                .placeholder = true;
            let mut missing = prepared.clone();
            missing.node_mut("/cpus/cpu4").unwrap().remove_property(key);
            for changed in [duplicate, unresolved, missing] {
                assert!(
                    Prepared::verify(&original, &changed, &selected()).is_err(),
                    "{key}"
                );
                assert!(
                    Prepared::verify(&changed, &prepared, &selected()).is_err(),
                    "source {key}"
                );
            }
        }
        for (key, value) in [
            ("name", b"../bad\0".to_vec()),
            ("reg", vec![1; 8]),
            ("cluster-type", b"PP\0".to_vec()),
            ("state", b"starting\0".to_vec()),
        ] {
            let mut changed = prepared.clone();
            changed.set_property("/cpus/cpu4", key, value).unwrap();
            assert!(Prepared::verify(&original, &changed, &selected()).is_err());
        }
        let mut duplicate = prepared.clone();
        duplicate
            .root
            .children
            .push(duplicate.node("/cpus").unwrap().clone());
        assert!(Prepared::verify(&original, &duplicate, &selected()).is_err());
        let mut duplicate = prepared.clone();
        let children = &mut duplicate.node_mut("/cpus").unwrap().children;
        children.push(children[0].clone());
        assert!(Prepared::verify(&original, &duplicate, &selected()).is_err());
        let mut aliased = prepared.clone();
        aliased
            .set_property("/cpus/cpu2", "reg", 0x101u32.to_le_bytes().to_vec())
            .unwrap();
        assert!(Prepared::verify(&original, &aliased, &selected()).is_err());
    }
}
