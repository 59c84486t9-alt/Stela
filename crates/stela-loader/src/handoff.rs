//! iBoot DeviceTree hand-off rows that are neither boot policy
//! ([`crate::boot_policy`]) nor root selection ([`crate::root_selection`]):
//! the values iBoot's DeviceTree finalizer (26A434 J473 iBoot 0x22fb0, with
//! its CPU and `arm-io` pass 0x39600) derives from the template itself, and
//! the explicit list of rows Stela cannot yet produce. The whole contract,
//! row by row, is `docs/research/iboot-handoff.md`.
use crate::{apple_device_tree::DeviceTree, boot_policy::Decision};
use alloc::{format, string::String, vec, vec::Vec};
use anyhow::{Result, ensure};
use serde::Serialize;
use stela_runtime::machine::soc;

const ROOT: &str = "/";
const CPUS: &str = "/cpus";
const ARM_IO: &str = "/arm-io";
const PLATFORM_NAME: &str = "platform-name";
const ENVIRONMENTS: &str = "osenvironments";

/// The previous boot stage's command, not the OS environment or root device.
/// Known codes come from 26A434 J473 LLB's dispatch table at raw 0x1544e8
/// (0x38-byte entries, command at +0x30), or its received-iBEC path at
/// 0x132c/0x2075c. The setter at 0xc76c0 records the byte at handoff +0xc;
/// iBoot imports that byte at 0xea4c8 and publishes it without remapping.
/// Values whose origin is unknown remain unrepresentable here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum BootCommand {
    Fsboot = 1,
    Kcgen = 2,
    Upgrade = 3,
    RecoverSystem = 4,
    TetheredRestore = 7,
    FieldDiags = 8,
    FsbootSafe = 9,
    Recover = 11,
    FieldDiagsPaired = 13,
    PostUpgrade = 14,
}

impl TryFrom<u8> for BootCommand {
    type Error = &'static str;

    fn try_from(value: u8) -> core::result::Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Fsboot),
            2 => Ok(Self::Kcgen),
            3 => Ok(Self::Upgrade),
            4 => Ok(Self::RecoverSystem),
            7 => Ok(Self::TetheredRestore),
            8 => Ok(Self::FieldDiags),
            9 => Ok(Self::FsbootSafe),
            11 => Ok(Self::Recover),
            13 => Ok(Self::FieldDiagsPaired),
            14 => Ok(Self::PostUpgrade),
            _ => Err("boot command has no modeled previous-stage origin"),
        }
    }
}

/// The command of a disk-loaded installed system. LLB promotes fsboot to
/// fsboot-safe when `-x` is set (0xd41d8..0xd4224), while post-upgrade keeps
/// its distinct command. Other origins do not load an installed System root.
pub fn installed_command(requested: Option<BootCommand>, boot_args: &str) -> Result<BootCommand> {
    let command = requested.unwrap_or(BootCommand::Fsboot);
    Ok(match command {
        BootCommand::Fsboot if boot_args.split_ascii_whitespace().any(|arg| arg == "-x") => {
            BootCommand::FsbootSafe
        }
        BootCommand::Fsboot | BootCommand::FsbootSafe | BootCommand::PostUpgrade => command,
        _ => anyhow::bail!("boot command {command:?} does not load an installed macOS System root"),
    })
}

/// Publish the explicit entry origin in both iBoot rows. Its writer takes
/// the saved byte through 0xdd848, then writes a u32 to `/chosen boot-command`
/// (0x24084..0x240ac) and `/chosen/handoff boot_type` (0x34098..0x340c0). No environment or
/// command-line flag supplies the missing fact when `command` is None.
pub fn apply_boot_command(
    tree: &mut DeviceTree,
    command: Option<BootCommand>,
) -> Result<(Vec<Decision>, Vec<String>)> {
    let Some(command) = command else {
        return Ok((
            vec![],
            vec![
                "/chosen boot-command, /chosen/handoff boot_type: no previous-stage boot origin \
                 was supplied"
                    .into(),
            ],
        ));
    };
    ensure!(tree.node(CHOSEN).is_some(), "DeviceTree has no {CHOSEN}");
    tree.ensure_child(CHOSEN, "handoff")?;
    let value = u32::from(command as u8).to_le_bytes().to_vec();
    let source = format!(
        "previous-stage entry origin {command:?} ({})",
        command as u8
    );
    let mut decisions = vec![];
    for (path, property) in [(CHOSEN, "boot-command"), ("/chosen/handoff", "boot_type")] {
        tree.set_property(path, property, value.clone())?;
        decisions.push(decision(path, property, &value, source.clone()));
    }
    Ok((decisions, vec![]))
}

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
/// template's CPU nodes by `cluster-type`. A SoC whose own pass already
/// counted its cores (the T6050's, [`crate::soc_variant`]) keeps its rows.
fn core_counts(
    tree: &mut DeviceTree,
    decisions: &mut Vec<Decision>,
    gaps: &mut Vec<String>,
) -> Result<()> {
    let Some(cpus) = tree.node(CPUS) else {
        return Ok(());
    };
    if cpus.property("max_cpus").is_some() {
        return Ok(());
    }
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

/// `/cpus/<cpu> l2-cache-size`, which XNU's `ml_parse_cpu_topology` reads
/// (absent, it records no L2). A template that gives a CPU node one size per
/// core variant instead (J700AP's P cores: `l2-cache-size-h17p` and
/// `l2-cache-size-h17a`) takes its SoC's own variant's
/// (`machine::soc::template_variant`); a node with no size of its SoC's
/// variant keeps none, reported.
fn l2_cache_sizes(
    tree: &mut DeviceTree,
    chip_id: Option<u32>,
    decisions: &mut Vec<Decision>,
    gaps: &mut Vec<String>,
) -> Result<()> {
    const SIZE: &str = "l2-cache-size";
    let Some(cpus) = tree.node(CPUS) else {
        return Ok(());
    };
    let variant = chip_id.and_then(soc::template_variant);
    let mut sizes = vec![];
    for cpu in &cpus.children {
        let per_variant = cpu
            .properties
            .iter()
            .any(|p| p.name().starts_with(SIZE) && p.name().len() > SIZE.len());
        if cpu.property(SIZE).is_some() || !per_variant {
            continue;
        }
        let name = cpu.name().unwrap_or("?");
        let chosen = variant.and_then(|variant| {
            let property = format!("{SIZE}-{variant}");
            Some((cpu.property(&property)?.value.clone(), property))
        });
        match chosen {
            Some((value, property)) => sizes.push((format!("{CPUS}/{name}"), value, property)),
            None => gaps.push(format!(
                "{CPUS}/{name} {SIZE}: the template gives per-variant sizes and none of this \
                 SoC's variant; XNU records no L2"
            )),
        }
    }
    for (path, value, property) in sizes {
        tree.set_property(&path, SIZE, value.clone())?;
        decisions.push(decision(
            &path,
            SIZE,
            &value,
            format!("{property}: the SoC's own core variant"),
        ));
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
        "/chosen iboot-handoff: iBoot's hand-off carveout (region 1) is not placed".into(),
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
             rsepfirmware: iBoot writes them only when it loads SEP firmware (0x29df4, \
             0x105a48), while its SEPFW memory-map entry is unconditional (0x29dd8); the bundle \
             reserves SEPFW without them, so AppleSEPManager loads its firmware at run time"
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
    l2_cache_sizes(tree, chip_id, &mut decisions, &mut gaps)?;
    gaps.extend(template_groups(tree));
    gaps.extend(unproduced(tree));
    Ok((decisions, gaps))
}

/// The template's variant groups: a root `:<group>` node whose `option`
/// lists variants, each with `:<group>_<variant>_<n>` overlay nodes beside
/// the properties they extend. The T6050 boards' `:sotra` group is merged
/// by its fused variant before this pass ([`crate::soc_variant`]). Another
/// group, J700AP's `:j700` (`has_mesa|no_mesa`), names a choice no fuse
/// model here makes, so its overlays stay unapplied, reported.
fn template_groups(tree: &DeviceTree) -> Vec<String> {
    let Some(root) = tree.node(ROOT) else {
        return vec![];
    };
    root.children
        .iter()
        .filter_map(|node| {
            let group = node.name()?.strip_prefix(':')?;
            let options = node.property("option")?.value.as_slice();
            let options = core::str::from_utf8(options).ok()?.trim_end_matches('\0');
            Some(format!(
                "template group :{group} ({options}): iBoot picks the variant from the chip; \
                 its :{group}_<variant>_<n> overlays stay unapplied"
            ))
        })
        .collect()
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
    fn every_known_entry_origin_publishes_the_same_u32_in_both_rows() -> Result<()> {
        let commands = [
            BootCommand::Fsboot,
            BootCommand::Kcgen,
            BootCommand::Upgrade,
            BootCommand::RecoverSystem,
            BootCommand::TetheredRestore,
            BootCommand::FieldDiags,
            BootCommand::FsbootSafe,
            BootCommand::Recover,
            BootCommand::FieldDiagsPaired,
            BootCommand::PostUpgrade,
        ];
        for command in commands {
            assert_eq!(BootCommand::try_from(command as u8), Ok(command));
            let mut tree = tree();
            tree.ensure_child(ROOT, "chosen")?;
            tree.ensure_child(CHOSEN, "handoff")?;
            tree.set_property("/chosen/handoff", "other", vec![0x5a])?;
            let (decisions, gaps) = apply_boot_command(&mut tree, Some(command))?;
            assert!(gaps.is_empty());
            assert_eq!(decisions.len(), 2);
            let expected = u32::from(command as u8).to_le_bytes();
            assert_eq!(value_of(&tree, "boot-command"), expected);
            assert_eq!(
                tree.property("/chosen/handoff", "boot_type").unwrap().value,
                expected
            );
            assert_eq!(
                tree.property("/chosen/handoff", "other").unwrap().value,
                [0x5a]
            );
        }
        for value in 0..=u8::MAX {
            assert_eq!(
                BootCommand::try_from(value).is_ok(),
                commands.iter().any(|c| *c as u8 == value)
            );
        }
        Ok(())
    }

    #[test]
    fn an_unstated_origin_is_reported_without_inference_from_restore_flags() -> Result<()> {
        let mut tree = tree();
        tree.ensure_child(ROOT, "chosen")?;
        tree.set_property(CHOSEN, "osenvironment", b"darwinos-ramdisk\0".to_vec())?;
        tree.set_property(CHOSEN, "boot-args", b"rd=md0 -restore\0".to_vec())?;
        let (decisions, gaps) = apply_boot_command(&mut tree, None)?;
        assert!(decisions.is_empty());
        assert_eq!(gaps.len(), 1);
        assert!(tree.property(CHOSEN, "boot-command").is_none());
        assert!(tree.node("/chosen/handoff").is_none());
        Ok(())
    }

    #[test]
    fn installed_entry_origins_preserve_post_upgrade_and_promote_safe_fsboot() -> Result<()> {
        assert_eq!(installed_command(None, "-v")?, BootCommand::Fsboot);
        assert_eq!(installed_command(None, "-v -x")?, BootCommand::FsbootSafe);
        assert_eq!(
            installed_command(Some(BootCommand::Fsboot), "-x")?,
            BootCommand::FsbootSafe
        );
        assert_eq!(
            installed_command(Some(BootCommand::PostUpgrade), "-v -x")?,
            BootCommand::PostUpgrade
        );
        assert_eq!(
            installed_command(Some(BootCommand::FsbootSafe), "-v")?,
            BootCommand::FsbootSafe
        );
        for command in [
            BootCommand::Upgrade,
            BootCommand::Recover,
            BootCommand::RecoverSystem,
            BootCommand::TetheredRestore,
            BootCommand::Kcgen,
            BootCommand::FieldDiags,
            BootCommand::FieldDiagsPaired,
        ] {
            assert!(installed_command(Some(command), "-v").is_err());
        }
        Ok(())
    }

    /// J700AP's P cores carry only per-variant L2 sizes; the A18 Pro's
    /// cores are H17P, and another SoC names no variant.
    #[test]
    fn template_variant_groups_stay_unapplied_and_reported() -> Result<()> {
        let mut tree = tree();
        assert!(template_groups(&tree).is_empty());
        tree.ensure_child(ROOT, ":sotra")?;
        tree.set_property("/:sotra", "option", b"h17s|h17c|h17d\0".to_vec())?;
        tree.ensure_child(ROOT, ":version")?;
        tree.set_property("/:version", "version", 1u32.to_le_bytes().to_vec())?;
        assert_eq!(
            template_groups(&tree),
            [
                "template group :sotra (h17s|h17c|h17d): iBoot picks the variant from the chip; \
              its :sotra_<variant>_<n> overlays stay unapplied"
            ]
        );
        Ok(())
    }

    #[test]
    fn per_variant_l2_sizes_take_the_socs_own_variant() -> Result<()> {
        let template = || -> Result<DeviceTree> {
            let mut tree = tree();
            tree.set_property(
                "/cpus/cpu0",
                "l2-cache-size",
                (4u32 << 20).to_le_bytes().to_vec(),
            )?;
            tree.set_property(
                "/cpus/cpu2",
                "l2-cache-size-h17p",
                (16u32 << 20).to_le_bytes().to_vec(),
            )?;
            tree.set_property(
                "/cpus/cpu2",
                "l2-cache-size-h17a",
                (8u32 << 20).to_le_bytes().to_vec(),
            )?;
            Ok(tree)
        };
        let mut tree = template()?;
        let (mut decisions, mut gaps) = (vec![], vec![]);
        l2_cache_sizes(&mut tree, Some(0x8140), &mut decisions, &mut gaps)?;
        assert!(gaps.is_empty());
        assert_eq!(decisions.len(), 1);
        assert_eq!(
            tree.property("/cpus/cpu2", "l2-cache-size").unwrap().value,
            (16u32 << 20).to_le_bytes()
        );
        assert_eq!(
            tree.property("/cpus/cpu0", "l2-cache-size").unwrap().value,
            (4u32 << 20).to_le_bytes()
        );
        assert!(tree.property("/cpus/cpu1", "l2-cache-size").is_none());
        let mut tree = template()?;
        let (mut decisions, mut gaps) = (vec![], vec![]);
        l2_cache_sizes(&mut tree, Some(0x8132), &mut decisions, &mut gaps)?;
        assert!(decisions.is_empty());
        assert_eq!(gaps.len(), 1);
        assert!(tree.property("/cpus/cpu2", "l2-cache-size").is_none());
        Ok(())
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
