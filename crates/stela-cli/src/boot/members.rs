//! The IPSW members `boot prepare` reads for one bundle. They are decided
//! from the BuildManifest before any other member is read, and every read
//! goes through [`Members`], which refuses a member the list lacks: so the
//! inputs a setup keeps on the USB to prepare bundles again
//! (`setup::inputs`), which are this list, cannot miss one prepare reads.
use super::{Roles, manifest_member};
use crate::restore::{self, components, manifest::Identity, manifest::RestoreManifest};
use anyhow::{Result, bail};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

/// The BuildManifest, which names every other member.
pub(super) const BUILD_MANIFEST: &str = "BuildManifest.plist";

/// What decides the members of one bundle.
pub(super) struct Choice<'a> {
    pub(super) report: &'a RestoreManifest,
    pub(super) profile: &'a components::Profile,
    pub(super) identity: &'a Identity,
    pub(super) roles: &'a Roles,
    /// The Cryptex1 trust caches, which only `--cryptex-trust-caches` reads.
    pub(super) cryptex_trust_caches: bool,
}

/// The members of `ipsw` a bundle of `choice` reads, each once.
pub(super) fn names(ipsw: &Path, choice: &Choice<'_>) -> Result<BTreeSet<String>> {
    let Choice {
        report,
        profile,
        identity,
        roles,
        cryptex_trust_caches,
    } = *choice;
    let owned = components::identities(report, profile);
    let owns = |name: &str| owned.iter().any(|i| i.components.contains_key(name));
    let mut components = vec![
        roles.kernel,
        roles.sptm,
        roles.txm,
        roles.device_tree,
        roles.trust_cache.0,
    ];
    components.extend(roles.ramdisk.map(|(name, _)| name));
    if let Some((name, _)) = roles.root_hash
        && owns(name)
    {
        components.push(name);
    }
    if owns(roles.sep) {
        components.push(roles.sep);
    }
    // Board firmware comes from the restore ramdisk, read separately when
    // the bundle does not boot it.
    if roles.ramdisk.is_none() && owns(components::RESTORE_RAMDISK) {
        components.push(components::RESTORE_RAMDISK);
    }
    if cryptex_trust_caches {
        components.extend(
            identity
                .components
                .keys()
                .map(String::as_str)
                .filter(|name| name.starts_with("Cryptex1,") && name.ends_with("TrustCache")),
        );
    }
    let mut names = BTreeSet::from([BUILD_MANIFEST.to_owned()]);
    for name in components {
        let (_, entry) = components::component(report, profile, identity, name)?;
        names.insert(entry.path.clone());
    }
    let variant = identity.macos_variant.as_ref().unwrap_or(&identity.variant);
    for cryptex1 in [false, true] {
        let member = manifest_member(cryptex1, variant, &identity.device_class);
        if restore::archive::has_member(ipsw, &member)? {
            names.insert(member);
        }
    }
    Ok(names)
}

/// The image `boot prepare` reads, through its member list alone.
pub(super) struct Members {
    ipsw: PathBuf,
    names: BTreeSet<String>,
}

impl Members {
    pub(super) fn new(ipsw: PathBuf, names: BTreeSet<String>) -> Self {
        Self { ipsw, names }
    }

    pub(super) fn path(&self) -> &Path {
        &self.ipsw
    }

    fn listed(&self, name: &str) -> Result<()> {
        if !self.names.contains(name) {
            bail!("boot prepare reads {name}, which its member list (boot::members::names) lacks");
        }
        Ok(())
    }

    /// Whether the list holds `name`: an optional member the image has.
    pub(super) fn has(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    /// Member `name`, whole, refusing more than `maximum` bytes.
    pub(super) fn read(&self, name: &str, maximum: u64) -> Result<Vec<u8>> {
        self.listed(name)?;
        restore::archive::read_member(&self.ipsw, name, maximum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::restore::payload::SYNTHETIC_MODEL;
    use std::io::Write as _;

    /// An image of the synthetic model whose erase identity names every
    /// component a restore bundle reads, and members nothing reads.
    fn image(path: &Path) {
        let (_, chip, board, class) = components::SYNTHETIC;
        let restore = [
            ("RestoreKernelCache", "kernelcache.restore"),
            (
                "RestoreDeviceTree",
                "Firmware/all_flash/DeviceTree.restore.im4p",
            ),
            ("RestoreTrustCache", "Firmware/restore.trustcache"),
            (
                "Ap,RestoreSecurePageTableMonitor",
                "Firmware/sptm.restore.im4p",
            ),
            (
                "Ap,RestoreTrustedExecutionMonitor",
                "Firmware/txm.restore.im4p",
            ),
            ("RestoreSEP", "Firmware/all_flash/sep.restore.im4p"),
            ("RestoreRamDisk", "restore-ramdisk.dmg"),
            ("OS", "system.dmg"),
            ("KernelCache", "kernelcache.release"),
        ];
        let entries: String = restore
            .iter()
            .map(|(component, path)| {
                format!(
                    "<key>{component}</key><dict><key>Digest</key><data>AAECAw==</data>\
                     <key>Info</key><dict><key>Path</key><string>{path}</string></dict></dict>"
                )
            })
            .collect();
        let manifest = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict>\
             <key>ProductVersion</key><string>0.0.1</string>\
             <key>ProductBuildVersion</key><string>STELA1</string>\
             <key>SupportedProductTypes</key><array><string>{SYNTHETIC_MODEL}</string></array>\
             <key>BuildIdentities</key><array><dict>\
             <key>Ap,ProductType</key><string>{SYNTHETIC_MODEL}</string>\
             <key>ApChipID</key><string>{chip:#x}</string>\
             <key>ApBoardID</key><string>{board:#x}</string><key>Info</key><dict>\
             <key>DeviceClass</key><string>{class}</string><key>Variant</key>\
             <string>Customer Erase Install (IPSW)</string><key>RestoreBehavior</key>\
             <string>Erase</string></dict><key>Manifest</key><dict>{entries}</dict></dict>\
             </array></dict></plist>"
        );
        let mut zip = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file(BUILD_MANIFEST, options).unwrap();
        zip.write_all(manifest.as_bytes()).unwrap();
        for (_, member) in restore {
            zip.start_file(member, options).unwrap();
            zip.write_all(member.as_bytes()).unwrap();
        }
        zip.finish().unwrap();
    }

    #[test]
    fn a_restore_bundle_reads_its_components_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image.ipsw");
        image(&path);
        let names = crate::boot::restore_inputs(&path, SYNTHETIC_MODEL).unwrap();
        assert_eq!(
            names,
            [
                BUILD_MANIFEST,
                "Firmware/all_flash/DeviceTree.restore.im4p",
                "Firmware/all_flash/sep.restore.im4p",
                "Firmware/restore.trustcache",
                "Firmware/sptm.restore.im4p",
                "Firmware/txm.restore.im4p",
                "kernelcache.restore",
                "restore-ramdisk.dmg",
            ]
        );
        // Prepare reads only through the list: a member it lacks, such as
        // the system image, is refused, so the kept inputs cannot drift
        // from what prepare reads.
        let members = Members::new(path, names.into_iter().collect());
        assert_eq!(
            members.read("restore-ramdisk.dmg", 1024).unwrap(),
            b"restore-ramdisk.dmg"
        );
        let refused = members.read("system.dmg", 1024).unwrap_err().to_string();
        assert!(refused.contains("member list"), "{refused}");
        assert!(!members.has("system.dmg"));
    }
}
