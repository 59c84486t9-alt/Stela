//! Which BuildManifest identities and components a build and profile need:
//! the one definition `stela boot prepare`, the restore inventory and
//! `stela setup` share.
//!
//! A profile is a Mac the engine presents, by its `Ap,ProductType`. The
//! profile registry (`isa/apple-soc-facts.json` `boards[]`, derived from the
//! IPSWs by `cargo xtask soc-facts`) gives its `ApChipID`, `ApBoardID` and
//! `DeviceClass`, and the BuildManifest identities with exactly those values
//! are the profile's. An identity's purpose is its own `Info.RestoreBehavior`:
//! `Update` restores keep data; `Erase` with a `RestoreRamDisk` erases;
//! `Erase` without one is the installed system's set. Components are named by
//! their BuildManifest keys, never by archive member names, and a missing one
//! is refused with the build and the profile.
use super::manifest::{Component, Identity, RestoreManifest};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::fmt;
use stela_runtime::payload::Purpose;

/// The registry, as `cargo xtask soc-facts` writes it.
const REGISTRY: &str = include_str!("../../../../isa/apple-soc-facts.json");
/// The component only an erase or update restore has: the ramdisk restored
/// runs from.
pub const RESTORE_RAMDISK: &str = "RestoreRamDisk";

/// Whether a component belongs only to the macOS system volume, which a
/// recovery-only erase restore (`SystemImage` false) never asks for: the
/// system image, its seal metadata and the cryptexes installed with it.
pub fn system_volume(component: &str) -> bool {
    matches!(component, "OS" | "Ap,SystemVolumeCanonicalMetadata")
        || component.starts_with("Cryptex1,")
}

/// The synthetic IPSW's profile (`payload::synthetic_ipsw`), which no Mac
/// has.
pub const SYNTHETIC: (&str, u32, u32, &str) = ("StelaTest1,1", 0xfe01, 0x01, "stelatestap");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub model: String,
    pub chip_id: u32,
    pub board_id: u32,
    pub device_class: String,
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}, ApChipID {:#x}, ApBoardID {:#x})",
            self.model, self.device_class, self.chip_id, self.board_id
        )
    }
}

#[derive(Deserialize)]
struct Registry {
    boards: Vec<Board>,
}

#[derive(Deserialize)]
struct Board {
    product_type: String,
    chip_id: String,
    board_id: String,
    device_class: String,
}

fn hex(value: &str) -> Option<u32> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    u32::from_str_radix(digits, 16).ok()
}

impl Profile {
    /// The registry's profile of `model`.
    pub fn of(model: &str) -> Result<Self> {
        if model == SYNTHETIC.0 {
            let (model, chip_id, board_id, device_class) = SYNTHETIC;
            return Ok(Self {
                model: model.into(),
                chip_id,
                board_id,
                device_class: device_class.into(),
            });
        }
        let registry: Registry =
            serde_json::from_str(REGISTRY).context("the profile registry is malformed")?;
        let board = registry
            .boards
            .into_iter()
            .find(|board| board.product_type == model)
            .with_context(|| {
                format!("{model} is not in the profile registry (isa/apple-soc-facts.json)")
            })?;
        Ok(Self {
            model: board.product_type,
            chip_id: hex(&board.chip_id).context("registry ApChipID")?,
            board_id: hex(&board.board_id).context("registry ApBoardID")?,
            device_class: board.device_class,
        })
    }

    /// Whether `identity` is this profile's.
    pub fn owns(&self, identity: &Identity) -> bool {
        identity.device_class == self.device_class
            && identity.ap_chip_id.as_deref().and_then(hex) == Some(self.chip_id)
            && identity.ap_board_id.as_deref().and_then(hex) == Some(self.board_id)
    }
}

/// What an identity is for, from its own `RestoreBehavior`.
pub fn purpose(identity: &Identity) -> Option<Purpose> {
    match identity.restore_behavior.as_deref()? {
        "Update" => Some(Purpose::Update),
        "Erase" if identity.components.contains_key(RESTORE_RAMDISK) => Some(Purpose::Erase),
        "Erase" => Some(Purpose::Installed),
        _ => None,
    }
}

fn purpose_name(purpose: Purpose) -> &'static str {
    match purpose {
        Purpose::Erase => "erase restore",
        Purpose::Update => "update restore",
        Purpose::Installed => "installed system",
    }
}

/// The profile's identities in `manifest`, in manifest order.
pub fn identities<'a>(manifest: &'a RestoreManifest, profile: &Profile) -> Vec<&'a Identity> {
    manifest
        .identities
        .iter()
        .filter(|identity| profile.owns(identity))
        .collect()
}

/// The profile's one identity for `purpose`.
pub fn identity<'a>(
    manifest: &'a RestoreManifest,
    profile: &Profile,
    purpose: Purpose,
) -> Result<&'a Identity> {
    let mut matching = identities(manifest, profile)
        .into_iter()
        .filter(|identity| self::purpose(identity) == Some(purpose));
    match (matching.next(), matching.next()) {
        (Some(identity), None) => Ok(identity),
        (None, _) => bail!(
            "macOS {} has no {} identity for {profile}",
            manifest.product_build,
            purpose_name(purpose)
        ),
        (Some(_), Some(_)) => bail!(
            "macOS {} has several {} identities for {profile}",
            manifest.product_build,
            purpose_name(purpose)
        ),
    }
}

/// The profile's identity named by its `Info.Variant`.
pub fn variant<'a>(
    manifest: &'a RestoreManifest,
    profile: &Profile,
    variant: &str,
) -> Result<&'a Identity> {
    let owned = identities(manifest, profile);
    owned
        .iter()
        .find(|identity| identity.variant == variant)
        .copied()
        .with_context(|| {
            let variants: Vec<&str> = owned.iter().map(|i| i.variant.as_str()).collect();
            format!(
                "macOS {} has no {variant:?} identity for {profile}; it has {variants:?}",
                manifest.product_build
            )
        })
}

/// Component `name` of `identity`, or of another identity of the profile
/// when `identity` lacks it; returns the identity that has it.
pub fn component<'a>(
    manifest: &'a RestoreManifest,
    profile: &Profile,
    identity: &'a Identity,
    name: &str,
) -> Result<(&'a Identity, &'a Component)> {
    std::iter::once(identity)
        .chain(identities(manifest, profile))
        .find_map(|owner| owner.components.get(name).map(|c| (owner, c)))
        .with_context(|| {
            format!(
                "macOS {} lists no {name} component for {profile}",
                manifest.product_build
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::restore::manifest::inspect;

    fn manifest() -> RestoreManifest {
        let identity =
            |chip: &str, board: &str, class: &str, variant: &str, behavior: &str, ramdisk: bool| {
                let ramdisk = if ramdisk {
                    "<key>RestoreRamDisk</key><dict><key>Info</key><dict><key>Path</key>\
                 <string>ramdisk.dmg</string></dict></dict>"
                } else {
                    ""
                };
                format!(
                    "<dict><key>ApChipID</key><string>{chip}</string><key>ApBoardID</key>\
                 <string>{board}</string><key>Info</key><dict><key>DeviceClass</key>\
                 <string>{class}</string><key>Variant</key><string>{variant}</string>\
                 <key>RestoreBehavior</key><string>{behavior}</string></dict>\
                 <key>Manifest</key><dict><key>KernelCache</key><dict><key>Info</key><dict>\
                 <key>Path</key><string>kernel</string></dict></dict>{ramdisk}</dict></dict>"
                )
            };
        let identities = [
            identity(
                "0x8112",
                "0x28",
                "j413ap",
                "Customer Erase Install (IPSW)",
                "Erase",
                true,
            ),
            identity(
                "0x8112",
                "0x24",
                "j473ap",
                "Customer Erase Install (IPSW)",
                "Erase",
                true,
            ),
            identity(
                "0x8112",
                "0x24",
                "j473ap",
                "Customer Upgrade Install (IPSW)",
                "Update",
                true,
            ),
            identity("0x8112", "0x24", "j473ap", "macOS Customer", "Erase", false),
        ]
        .concat();
        let plist = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict>\
             <key>ProductVersion</key><string>27.0.1</string><key>ProductBuildVersion</key>\
             <string>26A434</string><key>SupportedProductTypes</key><array/>\
             <key>BuildIdentities</key><array>{identities}</array></dict></plist>"
        );
        inspect(plist.as_bytes(), None).unwrap()
    }

    #[test]
    fn profiles_come_from_the_registry() {
        let profile = Profile::of("Mac14,3").unwrap();
        assert_eq!(
            (
                profile.chip_id,
                profile.board_id,
                profile.device_class.as_str()
            ),
            (0x8112, 0x24, "j473ap")
        );
        assert_eq!(Profile::of("Mac14,2").unwrap().device_class, "j413ap");
        let error = Profile::of("Mac99,1").unwrap_err().to_string();
        assert!(error.contains("not in the profile registry"), "{error}");
        assert_eq!(Profile::of(SYNTHETIC.0).unwrap().board_id, SYNTHETIC.2);
    }

    /// Every registry board is a selectable profile: its model resolves, its
    /// ApChipID has a SoC row and CPU profile, and its `/cpus` bind to that
    /// row's PEs or refuse for a stated gap: J700AP's P cores carry only
    /// per-variant L2 sizes (the bundle resolves them,
    /// `soc::template_variant`), and the T6050 template leaves
    /// `product-soc-name` to the variant its fuses pick, which every T6050
    /// board's profile gives (`stela_loader::soc_variant`). The registry's cluster
    /// aggregate gives each cluster its first PE's type, so J873gAP's M cores
    /// read as P here (`isa/apple-board-interfaces.json` keeps them).
    #[test]
    fn every_registry_board_resolves_to_a_soc_row() {
        use stela_runtime::machine::soc;
        let registry: serde_json::Value = serde_json::from_str(REGISTRY).unwrap();
        let boards = registry["boards"].as_array().unwrap();
        assert_eq!(boards.len(), 59);
        let mut bound = 0;
        for board in boards {
            let model = board["product_type"].as_str().unwrap();
            let profile = Profile::of(model).unwrap();
            assert_eq!(
                profile.device_class,
                board["device_class"].as_str().unwrap()
            );
            let chip = soc::chip(profile.chip_id).unwrap_or_else(|| panic!("{model}"));
            let processors: Vec<soc::Processor> = board["clusters"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|cluster| {
                    let kind = cluster["cluster_type"].as_str().unwrap().as_bytes()[0];
                    let l2 = cluster["l2_cache_size"].as_u64().map(|b| b as u32);
                    cluster["reg"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(move |reg| soc::Processor {
                            cluster_type: kind,
                            reg: hex(reg.as_str().unwrap()).unwrap(),
                            l2_bytes: l2,
                        })
                })
                .collect();
            let Some(name) = board["product_soc_name"].as_str() else {
                assert_eq!(profile.chip_id, 0x6050, "{model}");
                let fuses = stela_loader::soc_variant::fuses(profile.chip_id, profile.board_id);
                assert!(
                    stela_loader::soc_variant::decode(fuses.expect(model)).is_ok(),
                    "{model}"
                );
                continue;
            };
            match soc::cpus(profile.chip_id, name, &processors) {
                Ok(cpus) => {
                    assert_eq!(cpus.chip, chip, "{model}");
                    bound += 1;
                }
                Err(reason) => {
                    assert_eq!(profile.chip_id, 0x8140, "{model}: {reason}");
                    assert!(reason.contains("no l2-cache-size"), "{model}: {reason}");
                    assert!(soc::template_variant(0x8140).is_some());
                }
            }
        }
        assert_eq!(bound, 59 - 7 - 1);
    }

    #[test]
    fn identities_are_chosen_by_board_and_restore_behavior() {
        let manifest = manifest();
        let profile = Profile::of("Mac14,3").unwrap();
        assert_eq!(identities(&manifest, &profile).len(), 3);
        let erase = identity(&manifest, &profile, Purpose::Erase).unwrap();
        assert_eq!(erase.index, 1);
        assert_eq!(
            identity(&manifest, &profile, Purpose::Update)
                .unwrap()
                .index,
            2
        );
        assert_eq!(
            identity(&manifest, &profile, Purpose::Installed)
                .unwrap()
                .index,
            3
        );
        assert_eq!(
            variant(&manifest, &profile, "macOS Customer")
                .unwrap()
                .index,
            3
        );
        let (owner, ramdisk) = component(&manifest, &profile, erase, RESTORE_RAMDISK).unwrap();
        assert_eq!((owner.index, ramdisk.path.as_str()), (1, "ramdisk.dmg"));
        let installed = identity(&manifest, &profile, Purpose::Installed).unwrap();
        // The installed set lacks the ramdisk; another identity has it.
        assert_eq!(
            component(&manifest, &profile, installed, RESTORE_RAMDISK)
                .unwrap()
                .0
                .index,
            1
        );
        let error = component(&manifest, &profile, erase, "SEP")
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "macOS 26A434 lists no SEP component for Mac14,3 (j473ap, ApChipID 0x8112, \
             ApBoardID 0x24)"
        );
        let other = Profile::of("Mac14,9").unwrap();
        let error = identity(&manifest, &other, Purpose::Erase)
            .unwrap_err()
            .to_string();
        assert!(error.starts_with("macOS 26A434 has no erase restore identity for Mac14,9"));
        assert!(variant(&manifest, &profile, "Missing").is_err());
    }
}
