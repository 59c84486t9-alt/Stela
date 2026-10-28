//! Synthetic payload fixtures shared by downstream tests.
use super::*;
use alloc::{vec, vec::Vec};

/// An in-memory file.
pub struct Memory(pub Vec<u8>);

impl ReadAt for Memory {
    type Error = &'static str;
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<(), &'static str> {
        let start = offset as usize;
        let bytes = self.0.get(start..start + buffer.len()).ok_or("past end")?;
        buffer.copy_from_slice(bytes);
        Ok(())
    }
}

/// A three-identity manifest and the members' contents.
pub fn manifest() -> (PayloadManifest, Vec<(String, Vec<u8>)>) {
    let contents: Vec<(String, Vec<u8>)> = [
        ("kernelcache.release.test", vec![1u8; 3000]),
        (
            "Firmware/os.dmg.aea",
            (0..2_500_000u32).map(|i| i as u8).collect(),
        ),
        ("update.dmg", vec![9u8; 10]),
        (
            "Firmware/Manifests/restore/macOS Customer/apticket.test.im4m",
            vec![],
        ),
    ]
    .into_iter()
    .map(|(name, data)| (name.to_string(), data))
    .collect();
    let pem = "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n";
    let manifest = PayloadManifest {
        schema_version: 1,
        kind: KIND.into(),
        product_version: "27.0.1".into(),
        product_build: "26A434".into(),
        model: "Mac14,3".into(),
        device_class: "j473ap".into(),
        source: SourceImage {
            file_name: "Test.ipsw".into(),
            bytes: 1,
            sha256: Some("0".repeat(64)),
            build_manifest_sha256: "1".repeat(64),
            catalog_sha1: None,
        },
        layout: Layout::Split { slice_bytes: 1000 },
        members: contents
            .iter()
            .map(|(name, data)| Member {
                name: name.clone(),
                bytes: data.len() as u64,
                sha256: Some(crate::sha256(data)),
                sha384: None,
            })
            .collect(),
        identities: vec![
            IdentitySet {
                index: 20,
                variant: "Customer Erase Install (IPSW)".into(),
                purpose: Purpose::Erase,
                members: vec![contents[0].0.clone(), contents[1].0.clone()],
            },
            IdentitySet {
                index: 80,
                variant: "Customer Upgrade Install (IPSW)".into(),
                purpose: Purpose::Update,
                members: vec![contents[0].0.clone(), contents[2].0.clone()],
            },
        ],
        global_manifests: vec![contents[3].0.clone()],
        aea_keys: vec![AeaKey {
            member: contents[1].0.clone(),
            header_sha256: "2".repeat(64),
            url: "https://wkms-public.apple.com/fcs-keys/x".into(),
            key_pem: pem.into(),
            key_sha256: crate::sha256(pem.as_bytes()),
            url_asset_sha256: None,
        }],
        block_hashes: None,
    };
    (manifest, contents)
}
