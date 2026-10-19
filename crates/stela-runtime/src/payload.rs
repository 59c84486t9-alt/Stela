//! The restore payload: the IPSW members an installation needs, how they are
//! stored on removable media, and verified reads of them.
//!
//! `stela efi install --ipsw` writes a payload manifest beside the members,
//! either as split slices for FAT32 or as the whole IPSW. `stela.efi` reads
//! either form before boot services end, verifies every member's SHA-256
//! and copies the Erase subset into the target disk's staging partition.
//! The restore client reads the staged copy through the same
//! [`PayloadSource`] trait afterwards.
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod gpt;
pub mod staging;
pub mod zip;

pub const KIND: &str = "stela_restore_payload";
pub const MANIFEST_FILE: &str = "payload.json";
/// FAT32's largest file.
pub const MAX_SLICE_BYTES: u64 = 4 * 1024 * 1024 * 1024 - 1;
const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadError {
    /// The manifest or a staging header is malformed or inconsistent.
    Manifest(&'static str),
    Archive(&'static str),
    Unsupported(&'static str),
    Disk(&'static str),
    /// A member's bytes differ from the manifest.
    Verification {
        member: String,
        reason: &'static str,
    },
    Io(String),
}

impl PayloadError {
    pub fn io(error: impl fmt::Debug) -> Self {
        Self::Io(format!("{error:?}"))
    }
}

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(what) => write!(f, "payload manifest: {what}"),
            Self::Archive(what) => write!(f, "archive: {what}"),
            Self::Unsupported(what) => write!(f, "unsupported: {what}"),
            Self::Disk(what) => write!(f, "target disk: {what}"),
            Self::Verification { member, reason } => write!(f, "{member}: {reason}"),
            Self::Io(what) => write!(f, "read failed: {what}"),
        }
    }
}

/// Random-access reads of a file or partition; each call fills `buffer`.
pub trait ReadAt {
    type Error: fmt::Debug;
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error>;
}

/// A borrowed source, so one disk can be opened as several containers in
/// turn.
impl<R: ReadAt + ?Sized> ReadAt for &mut R {
    type Error = R::Error;

    fn len(&self) -> u64 {
        (**self).len()
    }

    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
        (**self).read_at(offset, buffer)
    }
}

/// A member's bytes in order. `Ok(0)` ends the member.
pub trait MemberRead {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, PayloadError>;
}

/// Where the restore client gets payload members, whatever stores them.
pub trait PayloadSource {
    type Reader<'a>: MemberRead
    where
        Self: 'a;
    fn manifest(&self) -> &PayloadManifest;
    /// Stream a member named in the manifest. Bytes are verified only by
    /// reading the member to the end, as [`copy_verified`] does.
    fn open(&mut self, name: &str) -> Result<Self::Reader<'_>, PayloadError>;
}

#[derive(Debug)]
pub enum CopyError<E> {
    Payload(PayloadError),
    Sink(E),
}

impl<E: fmt::Debug> fmt::Display for CopyError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Payload(error) => write!(f, "{error}"),
            Self::Sink(error) => write!(f, "write failed: {error:?}"),
        }
    }
}

/// Stream a member through `sink` and check its length and SHA-256 at the
/// end. The sink sees every byte before verification finishes, so a caller
/// that keeps the bytes must commit them only after this returns `Ok`.
pub fn copy_verified<S: PayloadSource, E>(
    source: &mut S,
    member: &Member,
    buffer: &mut [u8],
    mut sink: impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), CopyError<E>> {
    let mismatch = |reason| {
        CopyError::Payload(PayloadError::Verification {
            member: member.name.clone(),
            reason,
        })
    };
    let mut reader = source.open(&member.name).map_err(CopyError::Payload)?;
    let mut hash = Sha256::new();
    let mut total = 0u64;
    loop {
        let count = reader.read(buffer).map_err(CopyError::Payload)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > member.bytes {
            return Err(mismatch("longer than the manifest says"));
        }
        hash.update(&buffer[..count]);
        sink(&buffer[..count]).map_err(CopyError::Sink)?;
    }
    if total != member.bytes {
        return Err(mismatch("shorter than the manifest says"));
    }
    if hex::encode(hash.finalize()) != member.sha256 {
        return Err(mismatch("SHA-256 differs from the manifest"));
    }
    Ok(())
}

/// The source IPSW the payload came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceImage {
    pub file_name: String,
    pub bytes: u64,
    pub sha256: String,
    pub build_manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Layout {
    /// `<images>/<build>/<member>.NNN` slices of at most `slice_bytes`.
    Split { slice_bytes: u64 },
    /// The whole IPSW at `path`, relative to the volume root.
    Archive { path: String },
    /// Members in a staging partition.
    Staged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// The ZIP member path in the IPSW.
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    /// A full restore that erases the target.
    Erase,
    /// A restore that keeps user data.
    Update,
    /// The installed OS's own objects.
    Installed,
}

/// One BuildManifest identity of the payload's model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentitySet {
    /// Its index in `BuildIdentities`.
    pub index: u32,
    pub variant: String,
    pub purpose: Purpose,
    pub members: Vec<String>,
}

/// A prefetched public AEA key response, so the restore needs no network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AeaKey {
    pub member: String,
    pub header_sha256: String,
    pub url: String,
    pub key_pem: String,
    pub key_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadManifest {
    pub schema_version: u32,
    pub kind: String,
    pub product_version: String,
    pub product_build: String,
    pub model: String,
    pub device_class: String,
    pub source: SourceImage,
    pub layout: Layout,
    pub members: Vec<Member>,
    pub identities: Vec<IdentitySet>,
    /// The global `apticket` manifests, which no identity names.
    pub global_manifests: Vec<String>,
    pub aea_keys: Vec<AeaKey>,
}

/// A relative path made of ordinary components only.
pub fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && !path.contains(['\\', '\0', ':'])
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

fn sha256_hex(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The payload directory for a build, relative to the volume root.
pub fn images_directory(build: &str) -> String {
    format!("EFI/stela/images/{build}")
}

/// Slices a member of `bytes` takes; an empty member still has one.
pub fn slice_count(bytes: u64, slice_bytes: u64) -> u64 {
    bytes.div_ceil(slice_bytes).max(1)
}

/// A slice's path relative to the build's payload directory.
pub fn slice_path(member: &str, index: u64) -> String {
    format!("{member}.{index:03}")
}

impl PayloadManifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, PayloadError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(PayloadError::Manifest("exceeds 16 MiB"));
        }
        let manifest: Self =
            serde_json::from_slice(bytes).map_err(|_| PayloadError::Manifest("malformed JSON"))?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), PayloadError> {
        let fail = |what| Err(PayloadError::Manifest(what));
        if self.schema_version != 1 || self.kind != KIND {
            return fail("unknown schema");
        }
        if self.product_build.is_empty()
            || !self
                .product_build
                .bytes()
                .all(|b| b.is_ascii_alphanumeric())
        {
            return fail("invalid build");
        }
        if !sha256_hex(&self.source.sha256) || !sha256_hex(&self.source.build_manifest_sha256) {
            return fail("invalid source digest");
        }
        match &self.layout {
            Layout::Split { slice_bytes } if (1..=MAX_SLICE_BYTES).contains(slice_bytes) => {}
            Layout::Split { .. } => return fail("slice size outside 1..=4 GiB-1"),
            Layout::Archive { path } if safe_path(path) => {}
            Layout::Archive { .. } => return fail("unsafe archive path"),
            Layout::Staged => {}
        }
        let mut names: Vec<&str> = Vec::with_capacity(self.members.len());
        for member in &self.members {
            if !safe_path(&member.name) || !sha256_hex(&member.sha256) {
                return fail("unsafe member name or invalid digest");
            }
            names.push(&member.name);
        }
        names.sort_unstable();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            return fail("duplicate member");
        }
        let known = |name: &str| names.binary_search(&name).is_ok();
        let referenced = self
            .identities
            .iter()
            .flat_map(|identity| identity.members.iter())
            .chain(&self.global_manifests)
            .chain(self.aea_keys.iter().map(|key| &key.member));
        if !referenced.into_iter().all(|name| known(name)) {
            return fail("names a member it does not list");
        }
        for key in &self.aea_keys {
            if crate::sha256(key.key_pem.as_bytes()) != key.key_sha256
                || !sha256_hex(&key.header_sha256)
            {
                return fail("AEA key digest mismatch");
            }
        }
        Ok(())
    }

    pub fn member(&self, name: &str) -> Option<&Member> {
        self.members.iter().find(|member| member.name == name)
    }

    /// The members a full restore needs: the Erase identity's and the
    /// global manifests, in manifest order, laid out for staging.
    pub fn erase_subset(&self) -> Result<Self, PayloadError> {
        let erase: Vec<&IdentitySet> = self
            .identities
            .iter()
            .filter(|identity| identity.purpose == Purpose::Erase)
            .collect();
        let [identity] = erase[..] else {
            return Err(PayloadError::Manifest(
                "expected exactly one Erase identity",
            ));
        };
        let wanted =
            |name: &String| identity.members.contains(name) || self.global_manifests.contains(name);
        let members: Vec<Member> = self
            .members
            .iter()
            .filter(|member| wanted(&member.name))
            .cloned()
            .collect();
        Ok(Self {
            layout: Layout::Staged,
            identities: alloc::vec![identity.clone()],
            aea_keys: self
                .aea_keys
                .iter()
                .filter(|key| wanted(&key.member))
                .cloned()
                .collect(),
            members,
            ..self.clone()
        })
    }

    pub fn total_bytes(&self) -> u64 {
        self.members.iter().map(|member| member.bytes).sum()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|error| error.to_string())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    /// An in-memory file.
    pub(crate) struct Memory(pub Vec<u8>);

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
    pub(crate) fn manifest() -> (PayloadManifest, Vec<(String, Vec<u8>)>) {
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
                sha256: "0".repeat(64),
                build_manifest_sha256: "1".repeat(64),
            },
            layout: Layout::Split { slice_bytes: 1000 },
            members: contents
                .iter()
                .map(|(name, data)| Member {
                    name: name.clone(),
                    bytes: data.len() as u64,
                    sha256: crate::sha256(data),
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
            }],
        };
        (manifest, contents)
    }

    #[test]
    fn manifests_round_trip_and_reject_unsafe_or_inconsistent_fields() {
        let (manifest, _) = manifest();
        let json = manifest.to_json();
        assert_eq!(PayloadManifest::parse(json.as_bytes()).unwrap(), manifest);
        let broken: [fn(&mut PayloadManifest); 8] = [
            |m| m.members[0].name = "../escape".into(),
            |m| m.members[0].sha256 = "A".repeat(64),
            |m| m.members[1].name = m.members[0].name.clone(),
            |m| m.identities[0].members.push("missing".into()),
            |m| {
                m.layout = Layout::Split {
                    slice_bytes: MAX_SLICE_BYTES + 1,
                }
            },
            |m| {
                m.layout = Layout::Archive {
                    path: "C:/x.ipsw".into(),
                }
            },
            |m| m.aea_keys[0].key_pem.push('x'),
            |m| m.product_build = "26A434/..".into(),
        ];
        for change in broken {
            let mut bad = manifest.clone();
            change(&mut bad);
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_erase_subset_keeps_erase_members_global_manifests_and_their_keys() {
        let (manifest, contents) = manifest();
        let subset = manifest.erase_subset().unwrap();
        let names: Vec<&str> = subset.members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(
            names,
            [&contents[0].0, &contents[1].0, &contents[3].0].map(String::as_str)
        );
        assert_eq!(subset.layout, Layout::Staged);
        assert_eq!(subset.identities.len(), 1);
        assert_eq!(subset.aea_keys.len(), 1);
        subset.validate().unwrap();
        let mut two = manifest.clone();
        two.identities[1].purpose = Purpose::Erase;
        assert!(two.erase_subset().is_err());
    }

    #[test]
    fn slices_cover_members_within_the_fat32_limit() {
        assert_eq!(slice_count(0, MAX_SLICE_BYTES), 1);
        assert_eq!(slice_count(MAX_SLICE_BYTES, MAX_SLICE_BYTES), 1);
        assert_eq!(slice_count(MAX_SLICE_BYTES + 1, MAX_SLICE_BYTES), 2);
        // The 26A434 OS image (11,274,289,152 bytes) takes three slices.
        assert_eq!(slice_count(11_274_289_152, MAX_SLICE_BYTES), 3);
        assert_eq!(slice_path("a/b.dmg", 2), "a/b.dmg.002");
        assert_eq!(images_directory("26A434"), "EFI/stela/images/26A434");
    }
}
