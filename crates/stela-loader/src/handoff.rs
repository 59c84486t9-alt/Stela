//! iBoot DeviceTree hand-off rows that are neither boot policy
//! ([`crate::boot_policy`]) nor root selection ([`crate::root_selection`]):
//! the values iBoot's DeviceTree finalizer (26A434 J473 iBoot 0x22fb0, with
//! its CPU and `arm-io` pass 0x39600) derives from the template itself, and
//! the explicit list of rows Stela cannot yet produce. The whole contract,
//! row by row, is `docs/research/iboot-handoff.md`.
use crate::{apple_device_tree::DeviceTree, boot_policy::Decision};
use alloc::{format, string::String, vec, vec::Vec};
use anyhow::{Result, ensure};

const ROOT: &str = "/";
const CPUS: &str = "/cpus";
const ARM_IO: &str = "/arm-io";
const PLATFORM_NAME: &str = "platform-name";
const ENVIRONMENTS: &str = "osenvironments";

fn decision(path: &str, property: &str, value: &[u8], source: String) -> Decision {
    Decision {
        path: path.into(),
        property: property.into(),
        value_hex: hex::encode(value),
        source,
    }
}

fn text(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end]).ok()
}

/// `/ platform-name`: iBoot copies its platform name into the template's
/// slot, in place (0x245d4, "t8112" on J473). The template names the same
/// platform in `/arm-io device_type`, `<platform>-io`, whose name ends in
/// the chip ID's hex digits.
fn platform_name(
    tree: &mut DeviceTree,
    chip_id: Option<u32>,
    decisions: &mut Vec<Decision>,
    gaps: &mut Vec<String>,
) {
    let Some(width) = tree.property(ROOT, PLATFORM_NAME).map(|p| p.value.len()) else {
        return;
    };
    let platform = tree
        .property(ARM_IO, "device_type")
        .and_then(|p| text(&p.value))
        .and_then(|t| t.strip_suffix("-io"))
        .filter(|name| name.len() < width)
        .filter(|name| chip_id.is_some_and(|id| name.ends_with(&format!("{id:x}"))))
        .map(String::from);
    let Some(platform) = platform else {
        gaps.push(format!(
            "/ {PLATFORM_NAME}: /arm-io device_type names no <platform>-io of this chip; \
             template value kept"
        ));
        return;
    };
    let mut value = vec![0; width];
    value[..platform.len()].copy_from_slice(platform.as_bytes());
    if tree
        .set_property(ROOT, PLATFORM_NAME, value.clone())
        .is_ok()
    {
        decisions.push(decision(
            ROOT,
            PLATFORM_NAME,
            &value,
            format!("/arm-io device_type {platform}-io: iBoot's platform name, in place"),
        ));
    }
}

/// `/cpus max_cpus`, `e-core-count` and `p-core-count` (iBoot 0x39718..
/// 0x39774): the SoC's CPU count and each cluster's enabled cores. Every
/// template CPU is enabled on the emulated chip, so the counts are the
/// template's CPU nodes by `cluster-type`.
fn core_counts(
    tree: &mut DeviceTree,
    decisions: &mut Vec<Decision>,
    gaps: &mut Vec<String>,
) -> Result<()> {
    let Some(cpus) = tree.node(CPUS) else {
        return Ok(());
    };
    let (mut total, mut efficiency, mut performance) = (0u32, 0u32, 0u32);
    for cpu in cpus
        .children
        .iter()
        .filter(|c| c.property("state").is_some())
    {
        total += 1;
        match cpu
            .property("cluster-type")
            .map(|p| p.value.first().copied())
        {
            Some(Some(b'E')) => efficiency += 1,
            Some(Some(b'P')) => performance += 1,
            _ => {
                gaps.push(format!(
                    "/cpus max_cpus, e-core-count, p-core-count: {} has no E or P cluster-type",
                    cpu.name().unwrap_or("?")
                ));
                return Ok(());
            }
        }
    }
    if total == 0 {
        return Ok(());
    }
    for (property, count, source) in [
        ("max_cpus", total, "the template's CPU nodes"),
        (
            "e-core-count",
            efficiency,
            "the template's E-cluster CPU nodes",
        ),
        (
            "p-core-count",
            performance,
            "the template's P-cluster CPU nodes",
        ),
    ] {
        let value = count.to_le_bytes().to_vec();
        decisions.push(decision(CPUS, property, &value, source.into()));
        tree.set_property(CPUS, property, value)?;
    }
    Ok(())
}

const CHOSEN: &str = "/chosen";

/// The machine's identity rows: iBoot reads the ECID from the chip's fuse
/// pair at 0x23d2c8800 for both `unique-chip-id` and `die-id` (0x23ab4,
/// 0x23b6c; both getters reach 0x40a78) and writes `unique-device-id` as
/// the ECID followed by the 32-bit chip ID (0x23af8..0x23b64), each in place
/// in the template's slot. Stela's machine ECID is a per-machine value its
/// install tooling generates and persists; without one the template's zeros
/// stay and the rows are unresolved, never invented.
pub fn apply_identity(
    tree: &mut DeviceTree,
    ecid: Option<u64>,
    chip_id: Option<u32>,
) -> Result<(Vec<Decision>, Vec<String>)> {
    let (mut decisions, mut gaps) = (vec![], vec![]);
    let Some(ecid) = ecid else {
        gaps.push(
            "/chosen unique-chip-id, die-id, unique-device-id: no machine ECID given (--ecid)"
                .into(),
        );
        return Ok((decisions, gaps));
    };
    ensure!(ecid != 0, "a machine ECID is nonzero");
    let mut fill = |name: &str, value: Vec<u8>, source: String| -> Result<()> {
        let Some(slot) = tree.property(CHOSEN, name) else {
            return Ok(());
        };
        ensure!(
            slot.value.len() >= value.len(),
            "{CHOSEN} {name} is {} bytes; iBoot writes {}",
            slot.value.len(),
            value.len()
        );
        let mut bytes = slot.value.clone();
        bytes[..value.len()].copy_from_slice(&value);
        decisions.push(decision(CHOSEN, name, &bytes, source));
        tree.set_property(CHOSEN, name, bytes)
    };
    let ecid_bytes = ecid.to_le_bytes().to_vec();
    fill(
        "unique-chip-id",
        ecid_bytes.clone(),
        "the machine ECID (--ecid)".into(),
    )?;
    fill(
        "die-id",
        ecid_bytes.clone(),
        "the machine ECID: iBoot reads die-id from the same fuses".into(),
    )?;
    match chip_id {
        Some(chip) => {
            let mut value = ecid_bytes;
            value.extend_from_slice(&chip.to_le_bytes());
            fill(
                "unique-device-id",
                value,
                format!("the machine ECID, then chip ID {chip:#x}, as iBoot composes it"),
            )?;
        }
        None => gaps.push("/chosen unique-device-id: the identity names no chip ID".into()),
    }
    Ok((decisions, gaps))
}

/// Rows iBoot writes that Stela cannot produce yet, each with its reason.
fn unproduced(tree: &DeviceTree) -> Vec<String> {
    let mut gaps = vec![
        "/chosen dram-vendor, dram-vendor-id, dram-type: no DRAM identity model".into(),
        "/chosen firmware-version, system-firmware-version, iboot-stage-one-tag, \
         iboot-stage-one-variant, iboot-stage-two-tag: iBoot's own versions; Stela is not iBoot"
            .into(),
        "/chosen boot-nonce: no AP nonce model (iBoot derives it from NVRAM \
         com.apple.System.boot-nonce)"
            .into(),
        "/chosen boot-command, /chosen/handoff boot_type: the previous stage's boot command is \
         not modeled (TXM reads an absent boot-command as not 7)"
            .into(),
        "/chosen iboot-handoff: iBoot's hand-off carveout (region 1) is not placed".into(),
        "/pram reg, /chosen embedded-panic-log-size: the panic carveout (region 98) is not placed"
            .into(),
        "/chosen trusted-boot-policy-measurement: no LocalPolicy measurement model".into(),
        "/chosen restore-security-overrides0..3: iBoot's override table is not modeled; no \
         consumer reads them"
            .into(),
        "/chosen/boot-object-manifests, /chosen/secure-boot-hashes: iBoot deletes both when it \
         loaded no boot objects (0xe8e8c); which objects a restore boot loads is unobserved"
            .into(),
        "/cpus/<boot cpu> clock-frequency, memory-frequency, bus-frequency: the SoC's boot \
         clock rates are not in machine::soc"
            .into(),
    ];
    if tree.node("/arm-io/sep").is_some() {
        gaps.push(
            "/arm-io/sep sepfw-loaded, sepfw-booted, sep-boot-slot; /arm-io/sep/iop-sep-nub \
             rsepfirmware: iBoot writes them with the SEPFW memory-map entry when it loads SEP \
             firmware (0x29dbc, 0x105a48); the bundle maps SEPFW without them, so \
             AppleSEPManager loads its firmware at run time"
                .into(),
        );
    }
    gaps
}

/// Apply the template-derived rows; returns their decisions and the rows
/// that stay unresolved.
pub fn apply(tree: &mut DeviceTree, chip_id: Option<u32>) -> Result<(Vec<Decision>, Vec<String>)> {
    let mut decisions = vec![];
    let mut gaps = vec![];
    platform_name(tree, chip_id, &mut decisions, &mut gaps);
    core_counts(tree, &mut decisions, &mut gaps)?;
    gaps.extend(unproduced(tree));
    Ok((decisions, gaps))
}

/// iBoot's finalizer deletes `/osenvironments` once the selected
/// environment is applied (0x24d44); no consumer reads it afterwards.
pub fn remove_environments(tree: &mut DeviceTree) -> Option<Decision> {
    let root = tree.node_mut(ROOT)?;
    let before = root.children.len();
    root.children.retain(|c| c.name() != Some(ENVIRONMENTS));
    (root.children.len() != before).then(|| {
        decision(
            "/osenvironments",
            "",
            &[],
            "removed: iBoot deletes the node after applying an environment".into(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apple_device_tree::Node;

    fn tree() -> DeviceTree {
        let mut tree = DeviceTree {
            root: Node::named("device-tree").unwrap(),
        };
        tree.set_property(ROOT, PLATFORM_NAME, vec![0; 32]).unwrap();
        tree.ensure_child(ROOT, "arm-io").unwrap();
        tree.set_property(ARM_IO, "device_type", b"t8112-io\0".to_vec())
            .unwrap();
        tree.ensure_child(ROOT, "cpus").unwrap();
        for (index, cluster) in b"EEP".iter().copied().enumerate() {
            let cpu = format!("cpu{index}");
            tree.ensure_child(CPUS, &cpu).unwrap();
            let path = format!("{CPUS}/{cpu}");
            tree.set_property(&path, "state", b"waiting\0".to_vec())
                .unwrap();
            tree.set_property(&path, "cluster-type", vec![cluster, 0])
                .unwrap();
        }
        tree.ensure_child(ROOT, ENVIRONMENTS).unwrap();
        tree
    }

    #[test]
    fn platform_name_and_core_counts_come_from_the_template() -> Result<()> {
        let mut tree = tree();
        let (decisions, gaps) = apply(&mut tree, Some(0x8112))?;
        let name = &tree.property(ROOT, PLATFORM_NAME).unwrap().value;
        assert_eq!(name.len(), 32);
        assert_eq!(&name[..6], b"t8112\0");
        let count = |p: &str| tree.property(CPUS, p).unwrap().as_u32();
        assert_eq!(count("max_cpus"), Some(3));
        assert_eq!(count("e-core-count"), Some(2));
        assert_eq!(count("p-core-count"), Some(1));
        assert_eq!(decisions.len(), 4);
        assert!(!gaps.iter().any(|g| g.contains(PLATFORM_NAME)));
        assert!(gaps.iter().any(|g| g.contains("dram-vendor")));
        Ok(())
    }

    #[test]
    fn an_unnamed_platform_or_cluster_is_reported_not_guessed() -> Result<()> {
        let mut tree = tree();
        tree.set_property("/cpus/cpu2", "cluster-type", vec![b'X', 0])?;
        // The template's platform is another chip's.
        let (decisions, gaps) = apply(&mut tree, Some(0x8103))?;
        assert!(decisions.is_empty());
        assert!(tree.property(CPUS, "max_cpus").is_none());
        assert_eq!(
            tree.property(ROOT, PLATFORM_NAME).unwrap().value,
            vec![0; 32]
        );
        assert!(gaps.iter().any(|g| g.contains(PLATFORM_NAME)));
        assert!(gaps.iter().any(|g| g.contains("cpu2")));
        Ok(())
    }

    #[test]
    fn the_ecid_fills_the_identity_slots_as_iboot_composes_them() -> Result<()> {
        let mut tree = tree();
        tree.ensure_child(ROOT, "chosen")?;
        for (name, bytes) in [
            ("unique-chip-id", 8),
            ("die-id", 8),
            ("unique-device-id", 16),
        ] {
            tree.set_property(CHOSEN, name, vec![0; bytes])?;
        }
        let (decisions, gaps) =
            apply_identity(&mut tree, Some(0x1122_3344_5566_7788), Some(0x8112))?;
        assert!(gaps.is_empty());
        assert_eq!(decisions.len(), 3);
        let value = |name: &str| tree.property(CHOSEN, name).unwrap().value.clone();
        assert_eq!(
            value("unique-chip-id"),
            0x1122_3344_5566_7788u64.to_le_bytes()
        );
        assert_eq!(value("die-id"), value("unique-chip-id"));
        let device = value("unique-device-id");
        assert_eq!(device.len(), 16);
        assert_eq!(&device[..8], &value("unique-chip-id")[..]);
        assert_eq!(&device[8..12], &0x8112u32.to_le_bytes());
        assert_eq!(&device[12..], &[0; 4]);

        // No ECID: the zeros stay and the gap is named; zero is refused.
        tree.set_property(CHOSEN, "unique-chip-id", vec![0; 8])?;
        let (decisions, gaps) = apply_identity(&mut tree, None, Some(0x8112))?;
        assert!(decisions.is_empty());
        assert!(gaps[0].contains("no machine ECID"));
        assert_eq!(value_of(&tree, "unique-chip-id"), vec![0; 8]);
        assert!(apply_identity(&mut tree, Some(0), Some(0x8112)).is_err());
        Ok(())
    }

    fn value_of(tree: &DeviceTree, name: &str) -> Vec<u8> {
        tree.property(CHOSEN, name).unwrap().value.clone()
    }

    #[test]
    fn os_environments_are_deleted_once() {
        let mut tree = tree();
        assert!(remove_environments(&mut tree).is_some());
        assert!(tree.node("/osenvironments").is_none());
        assert!(remove_environments(&mut tree).is_none());
    }
}
