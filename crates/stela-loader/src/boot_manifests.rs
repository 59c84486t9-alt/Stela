//! Preserve an original boot object's IM4M for the kernel's manifest consumers.
//!
//! 26A434 J473 iBoot's loaded-object publisher (file 0xe8c2c) writes
//! `/chosen/boot-object-manifests/<object>` as a physical address and byte
//! length (0xe8dc8..0xe8e18), and its matching SHA-384 into
//! `/chosen/secure-boot-hashes/<object>` (0xe8e24..0xe8e54). Names without
//! an explicit override are the object's four-character payload tag
//! (0xe8d84..0xe8dc8). Publication preserves evidence; it does not validate
//! the signature or manufacture iBoot's authentication-state record.
//!
//! `secure-boot-hashes/sfr-manifest-hash` is the digest of the manifest that
//! admitted the system firmware the boot loaded (a MacBookPro18,3 booted by
//! iBoot-7429.41.5 shows it equal to its `ansf`, `ciof`, `tmuf`, `dcpf` and
//! `logo` rows). restored's `_write_ibfw` compares it with EAN key `ifw2`
//! to choose the iBoot slot to stage into and fails without it. A restore
//! boot's firmware comes from the IPSW under the one personalized ticket
//! that also admits the kernel ([`Object::admits_firmware`]).
use crate::{apple_device_tree::DeviceTree, boot_policy::Decision, im4m};
use alloc::{format, string::String, vec::Vec};
use anyhow::{Result, ensure};

const CHOSEN: &str = "/chosen";
const MANIFESTS: &str = "/chosen/boot-object-manifests";
const HASHES: &str = "/chosen/secure-boot-hashes";
const BOOT_HASH: &str = "boot-manifest-hash";
const FIRMWARE_HASH: &str = "sfr-manifest-hash";

/// A named original manifest, validated before its data region is placed.
pub struct Object {
    tag: String,
    bytes: u64,
    digest: [u8; im4m::SHA384_BYTES],
    /// The manifest also admitted the boot's system firmware.
    firmware: bool,
}

impl Object {
    /// Require a real IM4M which names the loaded payload, and whose whole
    /// encoding is the boot manifest already selected in `/chosen`.
    pub fn new(tree: &DeviceTree, tag: &str, original: &[u8]) -> Result<Self> {
        ensure!(
            tag.len() == 4 && tag.bytes().all(|b| b.is_ascii_alphanumeric()),
            "boot manifest object name is not a four-character payload tag"
        );
        let manifest = im4m::parse(original)?;
        ensure!(
            manifest.object(tag).is_some(),
            "boot manifest does not name the loaded {tag} payload"
        );
        let object = Self {
            tag: tag.into(),
            bytes: u64::try_from(original.len())?,
            digest: manifest.digest,
            firmware: false,
        };
        object.check_hash(tree)?;
        Ok(object)
    }

    /// The same manifest admitted the boot's system firmware, as one
    /// restore ticket does: it is also published as `sfr-manifest-hash`.
    pub fn admits_firmware(mut self) -> Self {
        self.firmware = true;
        self
    }

    /// The `secure-boot-hashes` rows this object publishes.
    fn hash_rows(&self) -> impl Iterator<Item = &str> {
        core::iter::once(self.tag.as_str()).chain(self.firmware.then_some(FIRMWARE_HASH))
    }

    fn check_hash(&self, tree: &DeviceTree) -> Result<()> {
        ensure!(
            tree.property(CHOSEN, BOOT_HASH)
                .is_some_and(|p| p.value == self.digest),
            "retained boot manifest differs from /chosen {BOOT_HASH}"
        );
        Ok(())
    }

    /// Reserve fixed-size rows before the DeviceTree itself is laid out.
    /// The caller must [`Self::place`] them before serializing the bundle.
    pub fn reserve(&self, tree: &mut DeviceTree) -> Result<()> {
        self.check_hash(tree)?;
        let rows = core::iter::once((MANIFESTS, self.tag.as_str()))
            .chain(self.hash_rows().map(|name| (HASHES, name)));
        for (path, name) in rows {
            ensure!(
                tree.property(path, name).is_none(),
                "boot manifest row {path}/{name} already exists"
            );
        }
        tree.ensure_child(CHOSEN, "boot-object-manifests")?;
        tree.set_property(MANIFESTS, &self.tag, self.range(0))?;
        tree.ensure_child(CHOSEN, "secure-boot-hashes")?;
        for name in self.hash_rows() {
            tree.set_property(HASHES, name, self.digest.to_vec())?;
        }
        Ok(())
    }

    fn range(&self, address: u64) -> Vec<u8> {
        [address.to_le_bytes(), self.bytes.to_le_bytes()].concat()
    }

    /// Fill the reserved physical range after placing the unchanged bytes.
    pub fn place(&self, tree: &mut DeviceTree, address: u64) -> Result<Vec<Decision>> {
        ensure!(
            address != 0 && address.checked_add(self.bytes).is_some(),
            "boot manifest physical range is empty or wraps"
        );
        self.check_hash(tree)?;
        ensure!(
            tree.property(MANIFESTS, &self.tag)
                .is_some_and(|p| p.value == self.range(0))
                && self.hash_rows().all(|name| {
                    tree.property(HASHES, name)
                        .is_some_and(|p| p.value == self.digest)
                }),
            "boot manifest reservation changed before placement"
        );
        let range = self.range(address);
        tree.set_property(MANIFESTS, &self.tag, range.clone())?;
        let hashes = self.hash_rows().map(|name| {
            let meaning = match name == FIRMWARE_HASH {
                true => "SHA-384 of the unchanged IM4M, which also admitted the system firmware",
                false => "SHA-384 of the unchanged IM4M",
            };
            (HASHES, name, self.digest.to_vec(), meaning)
        });
        Ok(core::iter::once((
            MANIFESTS,
            self.tag.as_str(),
            range,
            "physical address and exact IM4M length",
        ))
        .chain(hashes)
        .map(|(path, name, value, meaning)| Decision {
            path: path.into(),
            property: name.into(),
            value_hex: hex::encode(value),
            source: format!("retained boot manifest for loaded {}: {meaning}", self.tag),
        })
        .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::im4m::tests::{der, entry, manifest};

    fn input() -> (DeviceTree, Vec<u8>) {
        let bytes = manifest(&[], &[entry("krnl", &der(&[0x31], &[]))]);
        let mut tree = DeviceTree {
            root: crate::apple_device_tree::Node::named("device-tree").unwrap(),
        };
        tree.ensure_child("/", "chosen").unwrap();
        tree.set_property(CHOSEN, BOOT_HASH, im4m::sha384(&bytes).to_vec())
            .unwrap();
        (tree, bytes)
    }

    #[test]
    fn original_manifest_range_and_hash_keep_fixed_tree_size() -> Result<()> {
        let (mut tree, bytes) = input();
        let object = Object::new(&tree, "krnl", &bytes)?;
        object.reserve(&mut tree)?;
        let reserved_bytes = tree.encoded_bytes();
        let decisions = object.place(&mut tree, 0x8_0100_0000)?;
        assert_eq!(tree.encoded_bytes(), reserved_bytes);
        assert_eq!(
            tree.property(MANIFESTS, "krnl").unwrap().value,
            [
                0x8_0100_0000u64.to_le_bytes(),
                (bytes.len() as u64).to_le_bytes()
            ]
            .concat()
        );
        assert_eq!(
            tree.property(HASHES, "krnl").unwrap().value,
            im4m::sha384(&bytes)
        );
        assert_eq!(decisions.len(), 2);
        assert!(tree.property(HASHES, "state").is_none());
        Ok(())
    }

    #[test]
    fn mismatched_manifest_payload_and_changed_reservation_refuse() -> Result<()> {
        let (mut tree, bytes) = input();
        for tag in ["sptm", "state", "a/bc", ""] {
            assert!(Object::new(&tree, tag, &bytes).is_err());
        }
        assert!(Object::new(&tree, "krnl", b"not IM4M").is_err());
        let object = Object::new(&tree, "krnl", &bytes)?;
        object.reserve(&mut tree)?;
        assert!(object.reserve(&mut tree).is_err());
        assert!(object.place(&mut tree, 0).is_err());
        assert!(object.place(&mut tree, u64::MAX).is_err());
        tree.set_property(MANIFESTS, "krnl", object.range(1))?;
        assert!(object.place(&mut tree, 0x8_0100_0000).is_err());
        tree.set_property(CHOSEN, BOOT_HASH, alloc::vec![0; im4m::SHA384_BYTES])?;
        assert!(Object::new(&tree, "krnl", &bytes).is_err());
        assert!(object.place(&mut tree, 0x8_0100_0000).is_err());
        Ok(())
    }

    #[test]
    fn a_manifest_that_admitted_the_firmware_is_also_the_sfr_manifest() -> Result<()> {
        let (mut tree, bytes) = input();
        let object = Object::new(&tree, "krnl", &bytes)?.admits_firmware();
        object.reserve(&mut tree)?;
        let reserved_bytes = tree.encoded_bytes();
        let decisions = object.place(&mut tree, 0x8_0100_0000)?;
        assert_eq!(tree.encoded_bytes(), reserved_bytes);
        let digest = im4m::sha384(&bytes);
        assert_eq!(tree.property(HASHES, FIRMWARE_HASH).unwrap().value, digest);
        assert_eq!(tree.property(HASHES, "krnl").unwrap().value, digest);
        // Only the loaded object has a manifest region.
        assert!(tree.property(MANIFESTS, FIRMWARE_HASH).is_none());
        assert_eq!(decisions.len(), 3);
        // Without the firmware, there is no row.
        let (mut tree, bytes) = input();
        Object::new(&tree, "krnl", &bytes)?.reserve(&mut tree)?;
        assert!(tree.property(HASHES, FIRMWARE_HASH).is_none());
        Ok(())
    }

    #[test]
    fn an_existing_sfr_row_refuses_without_a_partial_record() -> Result<()> {
        let (mut tree, bytes) = input();
        let object = Object::new(&tree, "krnl", &bytes)?.admits_firmware();
        tree.ensure_child(CHOSEN, "secure-boot-hashes")?;
        tree.set_property(HASHES, FIRMWARE_HASH, alloc::vec![0; im4m::SHA384_BYTES])?;
        let before = tree.clone();
        assert!(object.reserve(&mut tree).is_err());
        assert_eq!(tree, before);
        Ok(())
    }

    #[test]
    fn a_conflicting_hash_does_not_leave_a_partial_manifest_record() -> Result<()> {
        let (mut tree, bytes) = input();
        let object = Object::new(&tree, "krnl", &bytes)?;
        tree.ensure_child(CHOSEN, "secure-boot-hashes")?;
        tree.set_property(HASHES, "krnl", alloc::vec![0; im4m::SHA384_BYTES])?;
        let before = tree.clone();
        assert!(object.reserve(&mut tree).is_err());
        assert_eq!(tree, before);
        Ok(())
    }
}
