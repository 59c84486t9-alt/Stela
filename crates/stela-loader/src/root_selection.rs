//! The `/chosen` values that tell the kernel which installed volume to root
//! from and where its boot objects are, as iBoot writes them.
//!
//! Known, from 26A434:
//!
//! - `AppleFileSystemDriver` (kernel collection `__text` file offset
//!   0x248eb10) reads `/chosen apfs-preboot-uuid` first, and only it when
//!   present: the root is the System-role volume of that volume group, or
//!   the volume with that UUID. Without it, `associated-volume-group` names
//!   the group whose container's Recovery-role volume is the root. Without
//!   either, `boot-uuid` names the root volume. Each is a UUID string,
//!   NUL-terminated data of at most 37 bytes (the kernel's getters refuse
//!   longer values), so the template's 38 zero bytes name no volume.
//! - iBoot (`iBoot.j473.RELEASE` 0xea50c) writes `apfs-preboot-uuid` and
//!   `boot-uuid` both as the volume group for a macOS boot, and
//!   `associated-volume-group` as the group with `boot-uuid` from its
//!   `/recovery` lookup for a recovery boot; UUIDs are 37 bytes,
//!   `uuid_unparse` text and a NUL (0xea83c).
//! - `boot-objects-path` is `/<volume group>/boot/<nsih>`, the boot
//!   directory relative to the Preboot volume (at most 0x400 bytes):
//!   UABaseSystem's `_prebootUUID` takes the volume group from its second
//!   component, and iBoot strips its own mount prefix before writing it
//!   (0xea8e4).
//!
//! Inferred: a recovery boot removes `apfs-preboot-uuid` so the kernel
//! reads `associated-volume-group`, and its `boot-uuid` is the Recovery
//! volume's UUID.
//!
//! Known: with `rd=` in its boot-args iBoot skips this writer (0x244f8..
//! 0x24530), so a ramdisk boot keeps the template's 38 zero bytes. Stela
//! removes them instead, which TXM's darwin expert reads as the null volume
//! UUID rather than an invalid length (docs/research/iboot-handoff.md).
use crate::Result;
use crate::{apple_device_tree::DeviceTree, boot_policy::Decision};
use alloc::{format, string::String, vec::Vec};
use stela_contracts::require;
pub use stela_formats::boot_bundle::schema::Root;

const CHOSEN: &str = "/chosen";
pub const APFS_PREBOOT_UUID: &str = "apfs-preboot-uuid";
pub const ASSOCIATED_VOLUME_GROUP: &str = "associated-volume-group";
pub const BOOT_UUID: &str = "boot-uuid";
pub const BOOT_OBJECTS_PATH: &str = "boot-objects-path";
/// The kernel's bound on a UUID property: 36 characters and a NUL.
const UUID_PROPERTY_BYTES: usize = 37;
/// The kernel's bound on `boot-objects-path`.
const BOOT_OBJECTS_PATH_LIMIT: usize = 0x400;

fn uuid_property(text: &str) -> Result<Vec<u8>> {
    require!(
        text.len() + 1 == UUID_PROPERTY_BYTES
            && crate::boot_selection::parse_uuid(text.as_bytes()).is_some(),
        "{text} is not a UUID",
        text = alloc::format!("{text:?}")
    );
    let mut value = text.to_ascii_uppercase().into_bytes();
    value.push(0);
    Ok(value)
}

fn boot_objects_path(volume_group: &str, boot_hash: &str) -> Result<Vec<u8>> {
    let mut value = format!("/{volume_group}/boot/{boot_hash}").into_bytes();
    value.push(0);
    require!(
        value.len() <= BOOT_OBJECTS_PATH_LIMIT,
        "boot-objects-path is longer than {BOOT_OBJECTS_PATH_LIMIT} bytes",
        BOOT_OBJECTS_PATH_LIMIT
    );
    Ok(value)
}

/// Write `root` into `/chosen`; returns what was decided.
pub fn apply(tree: &mut DeviceTree, root: &Root) -> Result<Vec<Decision>> {
    require!(
        tree.node(CHOSEN).is_some(),
        "DeviceTree has no {CHOSEN}",
        CHOSEN
    );
    let mut decisions = Vec::new();
    let mut set = |tree: &mut DeviceTree, property: &str, value: Vec<u8>, source: String| {
        decisions.push(Decision {
            path: CHOSEN.into(),
            property: property.into(),
            value_hex: hex::encode(&value),
            source,
        });
        tree.set_property(CHOSEN, property, value)
    };
    let (keep, source): (&[&str], String) = match root {
        Root::System {
            volume_group,
            boot_hash,
        } => {
            let source = format!("macOS from volume group {volume_group}");
            let uuid = uuid_property(volume_group)?;
            set(tree, APFS_PREBOOT_UUID, uuid.clone(), source.clone())?;
            set(tree, BOOT_UUID, uuid, source.clone())?;
            set(
                tree,
                BOOT_OBJECTS_PATH,
                boot_objects_path(volume_group, boot_hash)?,
                source.clone(),
            )?;
            (&[APFS_PREBOOT_UUID, BOOT_UUID, BOOT_OBJECTS_PATH], source)
        }
        Root::PairedRecovery {
            volume_group,
            recovery_volume,
            boot_hash,
        } => {
            let source = format!("recoveryOS paired with volume group {volume_group}");
            set(
                tree,
                ASSOCIATED_VOLUME_GROUP,
                uuid_property(volume_group)?,
                source.clone(),
            )?;
            set(
                tree,
                BOOT_UUID,
                uuid_property(recovery_volume)?,
                format!("{source}: its Recovery volume"),
            )?;
            set(
                tree,
                BOOT_OBJECTS_PATH,
                boot_objects_path(volume_group, boot_hash)?,
                source.clone(),
            )?;
            (
                &[ASSOCIATED_VOLUME_GROUP, BOOT_UUID, BOOT_OBJECTS_PATH],
                source,
            )
        }
        Root::SystemRecovery {
            volume,
            directory,
            boot_hash,
        } => {
            let source = format!("System Recovery volume {volume}");
            set(tree, BOOT_UUID, uuid_property(volume)?, source.clone())?;
            set(
                tree,
                BOOT_OBJECTS_PATH,
                boot_objects_path(directory, boot_hash)?,
                source.clone(),
            )?;
            (&[BOOT_UUID, BOOT_OBJECTS_PATH], source)
        }
        Root::Ramdisk => (&[], "a ramdisk root".into()),
    };
    let chosen = tree.node_mut(CHOSEN).expect("checked");
    for property in [
        APFS_PREBOOT_UUID,
        ASSOCIATED_VOLUME_GROUP,
        BOOT_UUID,
        BOOT_OBJECTS_PATH,
    ] {
        if !keep.contains(&property) && chosen.property(property).is_some() {
            chosen.remove_property(property);
            decisions.push(Decision {
                path: CHOSEN.into(),
                property: property.into(),
                value_hex: String::new(),
                source: format!("removed: {source}"),
            });
        }
    }
    Ok(decisions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apple_device_tree::Node;
    use alloc::vec;

    const GROUP: &str = "A304C51B-D22F-4CDD-829D-3E30CB5BD87B";
    const RECOVERY: &str = "11111111-2222-3333-4444-555555555555";

    fn tree() -> DeviceTree {
        let mut root = Node::named("device-tree").unwrap();
        let mut chosen = Node::named("chosen").unwrap();
        // The J473 template's slot.
        chosen.set_property(APFS_PREBOOT_UUID, vec![0; 38]).unwrap();
        root.children.push(chosen);
        DeviceTree { root }
    }

    fn value<'a>(tree: &'a DeviceTree, property: &str) -> Option<&'a [u8]> {
        tree.property(CHOSEN, property).map(|p| p.value.as_slice())
    }

    #[test]
    fn a_macos_boot_names_its_volume_group_and_boot_directory() {
        let mut tree = tree();
        let hash = "AB".repeat(48);
        let root = Root::System {
            volume_group: GROUP.to_ascii_lowercase(),
            boot_hash: hash.clone(),
        };
        let decisions = apply(&mut tree, &root).unwrap();
        let uuid = format!("{GROUP}\0").into_bytes();
        assert_eq!(uuid.len(), UUID_PROPERTY_BYTES);
        assert_eq!(value(&tree, APFS_PREBOOT_UUID), Some(uuid.as_slice()));
        assert_eq!(value(&tree, BOOT_UUID), Some(uuid.as_slice()));
        assert_eq!(
            value(&tree, BOOT_OBJECTS_PATH),
            Some(format!("/{}/boot/{hash}\0", GROUP.to_ascii_lowercase()).as_bytes())
        );
        assert_eq!(value(&tree, ASSOCIATED_VOLUME_GROUP), None);
        assert_eq!(decisions.len(), 3);
    }

    #[test]
    fn a_recovery_boot_names_the_group_and_its_recovery_volume() {
        let mut tree = tree();
        let root = Root::PairedRecovery {
            volume_group: GROUP.into(),
            recovery_volume: RECOVERY.into(),
            boot_hash: "CD".repeat(48),
        };
        apply(&mut tree, &root).unwrap();
        assert_eq!(value(&tree, APFS_PREBOOT_UUID), None);
        assert_eq!(
            value(&tree, ASSOCIATED_VOLUME_GROUP),
            Some(format!("{GROUP}\0").as_bytes())
        );
        assert_eq!(
            value(&tree, BOOT_UUID),
            Some(format!("{RECOVERY}\0").as_bytes())
        );
    }

    #[test]
    fn system_recovery_names_its_volume_and_boot_directory_alone() {
        let mut tree = tree();
        let hash = "EF".repeat(48);
        let root = Root::SystemRecovery {
            volume: RECOVERY.into(),
            directory: GROUP.into(),
            boot_hash: hash.clone(),
        };
        apply(&mut tree, &root).unwrap();
        assert_eq!(value(&tree, APFS_PREBOOT_UUID), None);
        assert_eq!(value(&tree, ASSOCIATED_VOLUME_GROUP), None);
        assert_eq!(
            value(&tree, BOOT_UUID),
            Some(format!("{RECOVERY}\0").as_bytes())
        );
        assert_eq!(
            value(&tree, BOOT_OBJECTS_PATH),
            Some(format!("/{GROUP}/boot/{hash}\0").as_bytes())
        );
    }

    #[test]
    fn a_ramdisk_boot_removes_the_template_slot_and_bad_uuids_are_refused() {
        let mut tree = tree();
        let decisions = apply(&mut tree, &Root::Ramdisk).unwrap();
        assert_eq!(value(&tree, APFS_PREBOOT_UUID), None);
        assert_eq!(decisions.len(), 1);
        let bad = Root::System {
            volume_group: "not-a-uuid".into(),
            boot_hash: "00".into(),
        };
        assert!(apply(&mut tree, &bad).is_err());
        let mut empty = DeviceTree {
            root: Node::named("device-tree").unwrap(),
        };
        assert!(apply(&mut empty, &Root::Ramdisk).is_err());
    }
}
