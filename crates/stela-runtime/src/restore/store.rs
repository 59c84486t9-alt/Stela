//! IPSW-backed verified random reads. Existing ZIP64 and bounded inflater own
//! archive parsing. A member is scanned once against immutable payload SHA-256;
//! retained 64-KiB block hashes then detect changes before returning any read.
//! BuildManifest's component digest is a different (Image4) digest and remains
//! attached to the selected identity; it is never replaced with the ZIP hash.
//!
//! A manifest that carries recorded hashes (`payload::BlockHashes`, which
//! the host that wrote it computed while hashing every member) needs no
//! scan to build them: [`Store::adopt_block_hashes`] takes the block hashes
//! and SHA-384s from the file the manifest names by SHA-256. Every read
//! checks its blocks against them, and a member read from its first byte to
//! its last is also checked against its SHA-384. [`Verify`] says when the
//! whole of each member is checked against those records: by default every
//! member, before StartRestore ([`Store::prepare`]); with
//! [`Verify::OnRead`] only the blocks the restore reads, as it reads them.
//! Both use the one block check, and a mismatch refuses the member by name.
use super::{
    Error, Result,
    plist::{self, Limits, Value},
};
use crate::payload::{
    MemberRead, PayloadManifest, Purpose, ReadAt,
    zip::{Archive, Entry},
};
use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use sha2::{Digest, Sha256, Sha384};

pub const BLOCK_BYTES: usize = crate::payload::HASH_BLOCK_BYTES as usize;
pub const MAX_READ_BYTES: usize = 1024 * 1024;
const MAX_BLOCKS: usize = 1 << 20;
const MAX_BUILD_MANIFEST_BYTES: usize = 64 * 1024 * 1024;
/// `Info.RestoreBehavior` of a BuildManifest identity that erases the
/// target, and of one that updates its installed system in place, keeping
/// the user's data.
pub const ERASE_BEHAVIOR: &str = "Erase";
pub const UPDATE_BEHAVIOR: &str = "Update";
#[derive(Debug, Clone)]
pub struct Identity {
    pub index: usize,
    pub value: Value,
}
impl Identity {
    pub fn info(&self) -> Result<&Value> {
        self.value.required("Info")
    }
    pub fn variant(&self) -> Result<&str> {
        self.info()?.required("Variant")?.string()
    }
    pub fn component(&self, name: &str) -> Result<&Value> {
        self.value.required("Manifest")?.required(name)
    }
    pub fn path(&self, name: &str) -> Result<&str> {
        self.component(name)?
            .required("Info")?
            .required("Path")?
            .string()
    }
    pub fn number(&self, key: &str) -> Result<u64> {
        let v = self.value.required(key)?;
        match v {
            Value::Integer(n) => Ok(*n),
            Value::String(s) => u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16)
                .map_err(|_| Error::Invalid("identity hex number")),
            _ => Err(Error::Invalid("identity number")),
        }
    }
}
/// When recorded hashes are checked against the whole of each member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Verify {
    /// Every member, read whole by [`Store::prepare`] before StartRestore.
    #[default]
    Full,
    /// Only the blocks each request reads, as it reads them.
    OnRead,
}
struct Verified {
    entry: Entry,
    blocks: Vec<[u8; 32]>,
    sha384: [u8; 48],
    /// For recorded hashes not yet checked against the whole member: the
    /// SHA-384 of its bytes read in order from its start, and how far they
    /// reach.
    whole: Option<(u64, Sha384)>,
}
pub struct Store<R> {
    reader: R,
    archive: Archive,
    manifest: PayloadManifest,
    /// This board's BuildIdentities, each with its original index.
    identities: Vec<Identity>,
    /// The selected identity's position in `identities`.
    current: usize,
    verified: BTreeMap<String, Verified>,
    block_count: usize,
    verify: Verify,
    /// The most recently read member and its resumable inflate position, so
    /// reading a deflate member block by block inflates it once rather than
    /// replaying it from the start each block.
    cursor: Option<(String, crate::payload::zip::Progress)>,
}
fn payload(e: impl core::fmt::Display) -> Error {
    Error::Payload(e.to_string())
}
impl<R: ReadAt> Store<R> {
    /// `selected` is supplied by the inventory (20 for the acceptance input),
    /// never selected by a build/version exception in the runtime.
    pub fn open(mut reader: R, manifest: PayloadManifest, selected: usize) -> Result<Self> {
        manifest.validate().map_err(payload)?;
        let archive = Archive::open(&mut reader).map_err(payload)?;
        if archive.entries().windows(2).any(|p| p[0].name == p[1].name) {
            return Err(Error::Invalid("duplicate ZIP member"));
        }
        let mut names: Vec<_> = archive.entries().iter().map(|e| e.name.as_str()).collect();
        names.sort_unstable();
        if names.windows(2).any(|p| p[0] == p[1]) {
            return Err(Error::Invalid("duplicate ZIP member"));
        }
        let entry = archive
            .find("BuildManifest.plist")
            .ok_or(Error::Invalid("missing BuildManifest"))?;
        if entry.bytes > MAX_BUILD_MANIFEST_BYTES as u64 {
            return Err(Error::Limit("BuildManifest bytes"));
        }
        let mut bytes = vec![0; entry.bytes as usize];
        archive
            .read_member_at(&mut reader, entry, 0, &mut bytes)
            .map_err(payload)?;
        if crate::sha256(&bytes) != manifest.source.build_manifest_sha256 {
            return Err(Error::Invalid("BuildManifest SHA-256"));
        }
        // A universal BuildManifest names every board. Only this board's
        // identities are kept, as they are decoded: the selected one and the
        // RecoveryOS identity `answers` looks up by ApChipID/ApBoardID.
        let mut identities = Vec::new();
        let mut count = 0;
        let mut sink = |index: usize, value: Value| {
            count = index + 1;
            let class = value
                .get("Info")
                .and_then(|info| info.get("DeviceClass"))
                .map(Value::string)
                .transpose()?;
            if index == selected || class == Some(manifest.device_class.as_str()) {
                identities.push(Identity { index, value });
            }
            Ok(())
        };
        plist::decode_streaming(
            &bytes,
            Limits {
                bytes: MAX_BUILD_MANIFEST_BYTES,
                nodes: 2_000_000,
                depth: 64,
            },
            plist::Stream {
                path: &["BuildIdentities"],
                sink: &mut sink,
            },
        )?;
        if count == 0 {
            return Err(Error::Invalid("BuildManifest has no BuildIdentities"));
        }
        drop(bytes);
        let current = identities
            .iter()
            .position(|identity| identity.index == selected)
            .ok_or(Error::Invalid("BuildManifest identity index"))?;
        let identity = &identities[current];
        // A restore runs an erase or an update identity; the inventory's
        // purpose must name the same behavior.
        let purpose = match identity.info()?.required("RestoreBehavior")?.string()? {
            ERASE_BEHAVIOR => Purpose::Erase,
            UPDATE_BEHAVIOR => Purpose::Update,
            _ => {
                return Err(Error::Invalid(
                    "selected identity is neither erase nor update",
                ));
            }
        };
        let set = manifest
            .identities
            .iter()
            .find(|s| s.index as usize == selected)
            .ok_or(Error::Invalid("identity absent from payload inventory"))?;
        if set.variant != identity.variant()?
            || set.purpose != purpose
            || identity.info()?.required("DeviceClass")?.string()? != manifest.device_class
        {
            return Err(Error::Invalid("payload/BuildManifest identity mismatch"));
        }
        Ok(Self {
            reader,
            archive,
            manifest,
            identities,
            current,
            verified: BTreeMap::new(),
            block_count: 0,
            verify: Verify::Full,
            cursor: None,
        })
    }
    pub fn manifest(&self) -> &PayloadManifest {
        &self.manifest
    }
    pub fn identity(&self) -> &Identity {
        &self.identities[self.current]
    }
    pub fn zip_entries(&self) -> &[Entry] {
        self.archive.entries()
    }
    pub fn identities(&self) -> &[Identity] {
        &self.identities
    }
    pub fn member_len(&self, path: &str) -> Result<u64> {
        self.manifest
            .member(path)
            .map(|m| m.bytes)
            .ok_or(Error::Invalid(
                "member absent from immutable payload inventory",
            ))
    }
    /// Admission/preflight work, before StartRestore: every inventory member
    /// is read whole and checked, against its recorded hashes or, without
    /// them, its SHA-256 (building its block hashes). With
    /// [`Verify::OnRead`] recorded members are left to the reads.
    pub fn prepare(&mut self) -> Result<()> {
        let paths: Vec<_> = self
            .manifest
            .members
            .iter()
            .map(|m| m.name.clone())
            .collect();
        for path in paths {
            match self.verified.get(&path) {
                Some(recorded) if recorded.whole.is_some() && self.verify == Verify::Full => {
                    self.check_whole(&path)?
                }
                Some(_) => {}
                None => self.verify(&path)?,
            }
        }
        Ok(())
    }
    /// When [`prepare`](Self::prepare) checks members with recorded hashes;
    /// [`Verify::Full`] unless set.
    pub fn set_verify(&mut self, verify: Verify) {
        self.verify = verify;
    }
    /// Take the manifest's recorded block hashes and SHA-384s from `file`,
    /// the contents of the file it names, in place of scanning to build
    /// them; members are checked against them as [`Verify`] says.
    pub fn adopt_block_hashes(&mut self, file: &[u8]) -> Result<()> {
        let blocks = self
            .manifest
            .block_hashes
            .as_ref()
            .ok_or(Error::Invalid("the payload names no block hashes"))?;
        if crate::sha256(file) != blocks.sha256 {
            return Err(Error::Payload(format!(
                "{}: SHA-256 differs from the payload manifest",
                blocks.file
            )));
        }
        let count = usize::try_from(self.manifest.hash_blocks())
            .map_err(|_| Error::Limit("member blocks"))?;
        if count > MAX_BLOCKS || file.len() != count * 32 {
            return Err(Error::Invalid("block hash file size"));
        }
        let mut at = 0;
        let mut adopted = BTreeMap::new();
        for member in &self.manifest.members {
            let entry = self
                .archive
                .find(&member.name)
                .ok_or(Error::Invalid("missing ZIP member"))?
                .clone();
            if entry.bytes != member.bytes {
                return Err(Error::Invalid("ZIP/payload member size mismatch"));
            }
            let mut sha384 = [0u8; 48];
            hex::decode_to_slice(member.sha384.as_deref().unwrap_or(""), &mut sha384)
                .map_err(|_| Error::Invalid("member SHA-384"))?;
            let n = member.bytes.div_ceil(BLOCK_BYTES as u64) as usize;
            let blocks = file[at * 32..(at + n) * 32].as_chunks::<32>().0.to_vec();
            at += n;
            adopted.insert(
                member.name.clone(),
                Verified {
                    entry,
                    blocks,
                    sha384,
                    whole: Some((0, Sha384::new())),
                },
            );
        }
        self.block_count = count;
        self.verified = adopted;
        Ok(())
    }
    /// Whether every member is checked as [`Verify`] requires before
    /// StartRestore.
    pub fn prepared(&self) -> bool {
        self.manifest.members.iter().all(|m| {
            self.verified
                .get(&m.name)
                .is_some_and(|v| v.whole.is_none() || self.verify == Verify::OnRead)
        })
    }
    /// One block of a member with recorded or scanned hashes, checked
    /// against its hash.
    fn block(&mut self, path: &str, block: u64) -> Result<Vec<u8>> {
        let size = self.member_len(path)?;
        let verified = &self.verified[path];
        let start = block * BLOCK_BYTES as u64;
        let entry = verified.entry.clone();
        let expected = verified.blocks[block as usize];
        let mut bytes = vec![0; (size - start).min(BLOCK_BYTES as u64) as usize];
        let mut progress = match self.cursor.take() {
            Some((p, progress)) if p == path => Some(progress),
            _ => None,
        };
        self.archive
            .read_member_resuming(&mut self.reader, &entry, &mut progress, start, &mut bytes)
            .map_err(payload)?;
        self.cursor = progress.map(|progress| (path.to_string(), progress));
        let actual: [u8; 32] = Sha256::digest(&bytes).into();
        if actual != expected {
            return Err(Error::Payload(format!(
                "{path}: source changed at block {block}"
            )));
        }
        Ok(bytes)
    }
    /// Read a member with recorded hashes whole, checking each block and
    /// then its SHA-384.
    fn check_whole(&mut self, path: &str) -> Result<()> {
        let blocks = self.verified[path].blocks.len() as u64;
        let mut hash = Sha384::new();
        for block in 0..blocks {
            hash.update(self.block(path, block)?);
        }
        let verified = self.verified.get_mut(path).expect("recorded");
        if <[u8; 48]>::from(hash.finalize()) != verified.sha384 {
            return Err(Error::Payload(format!(
                "{path}: SHA-384 differs from the payload manifest"
            )));
        }
        verified.whole = None;
        Ok(())
    }
    pub fn digest384(&self, path: &str) -> Result<&[u8; 48]> {
        self.verified
            .get(path)
            .map(|v| &v.sha384)
            .ok_or(Error::Invalid("member not prepared"))
    }
    pub fn verify(&mut self, path: &str) -> Result<()> {
        if self.verified.contains_key(path) {
            return Ok(());
        }
        let member = self
            .manifest
            .member(path)
            .ok_or(Error::Invalid("unlisted payload member"))?;
        let entry = self
            .archive
            .find(path)
            .ok_or(Error::Invalid("missing ZIP member"))?
            .clone();
        if entry.bytes != member.bytes {
            return Err(Error::Invalid("ZIP/payload member size mismatch"));
        }
        let blocks = usize::try_from(member.bytes.div_ceil(BLOCK_BYTES as u64))
            .map_err(|_| Error::Limit("member blocks"))?;
        if blocks > MAX_BLOCKS - self.block_count {
            return Err(Error::Limit("payload hash index"));
        }
        let mut stream = self
            .archive
            .open_member(&mut self.reader, &entry)
            .map_err(payload)?;
        let mut hash = Sha256::new();
        let mut hash384 = Sha384::new();
        let mut hashes = Vec::new();
        let mut buffer = vec![0; BLOCK_BYTES];
        let mut total = 0u64;
        loop {
            let mut done = 0;
            while done < buffer.len() {
                let n = stream.read(&mut buffer[done..]).map_err(payload)?;
                if n == 0 {
                    break;
                }
                done += n;
            }
            if done == 0 {
                break;
            }
            total += done as u64;
            if total > member.bytes {
                return Err(Error::Invalid("member exceeds inventory"));
            }
            hash.update(&buffer[..done]);
            hash384.update(&buffer[..done]);
            hashes.push(Sha256::digest(&buffer[..done]).into());
        }
        if total != member.bytes || hex::encode(hash.finalize()) != member.sha256 {
            return Err(Error::Payload(format!(
                "{path}: immutable SHA-256/length mismatch"
            )));
        }
        self.block_count += hashes.len();
        self.verified.insert(
            path.into(),
            Verified {
                entry,
                blocks: hashes,
                sha384: hash384.finalize().into(),
                whole: None,
            },
        );
        Ok(())
    }
    pub fn read_at(&mut self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        if len > MAX_READ_BYTES {
            return Err(Error::Limit("payload random read"));
        }
        let size = self.member_len(path)?;
        if offset.checked_add(len as u64).is_none_or(|end| end > size) {
            return Err(Error::Invalid("payload read range"));
        }
        self.verify(path)?;
        let mut result = Vec::with_capacity(len);
        let mut at = offset;
        while result.len() < len {
            let block = at / BLOCK_BYTES as u64;
            let bytes = self.block(path, block)?;
            let skip = (at - block * BLOCK_BYTES as u64) as usize;
            let n = (bytes.len() - skip).min(len - result.len());
            result.extend_from_slice(&bytes[skip..skip + n]);
            at += n as u64;
        }
        let verified = self.verified.get_mut(path).expect("verified above");
        if let Some((reached, hash)) = &mut verified.whole
            && *reached == offset
            && !result.is_empty()
        {
            hash.update(&result);
            *reached += result.len() as u64;
            if *reached == size {
                let actual: [u8; 48] = hash.clone().finalize().into();
                if actual != verified.sha384 {
                    return Err(Error::Payload(format!(
                        "{path}: SHA-384 differs from the payload manifest"
                    )));
                }
                verified.whole = None;
            }
        }
        Ok(result)
    }
    pub fn read_component(&mut self, name: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        let path = self.identity().path(name)?.to_string();
        self.read_at(&path, offset, len)
    }
    pub fn read_small(&mut self, path: &str) -> Result<Vec<u8>> {
        let n =
            usize::try_from(self.member_len(path)?).map_err(|_| Error::Limit("small member"))?;
        self.read_at(path, 0, n)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::payload::{
        IdentitySet, Member,
        tests::{Memory, manifest},
        zip::tests::archive,
    };
    pub(crate) fn fixture(data: &[u8], deflate: bool) -> Store<Memory> {
        with_components(data, deflate, &[])
    }
    /// Give a store's manifest AEA keys, for the staged-answer tests.
    pub(crate) fn set_aea_keys(store: &mut Store<Memory>, keys: Vec<crate::payload::AeaKey>) {
        store.manifest.aea_keys = keys;
    }
    /// Drop a member from a store's inventory, as a trimmed medium leaves it.
    pub(crate) fn drop_member(store: &mut Store<Memory>, name: &str) {
        store.manifest.members.retain(|m| m.name != name);
    }
    /// The fixture with more BuildManifest components, each `(name, path,
    /// bytes)` with its SHA-384 as the Digest.
    pub(crate) fn with_components(
        data: &[u8],
        deflate: bool,
        extra: &[(&str, &str, &[u8])],
    ) -> Store<Memory> {
        with_digests(data, deflate, extra, &[])
    }
    /// `with_components` with the named components' Digest replaced, for a
    /// manifest whose digest covers something other than the member's
    /// bytes. Components naming one path share one member.
    pub(crate) fn with_digests(
        data: &[u8],
        deflate: bool,
        extra: &[(&str, &str, &[u8])],
        digests: &[(&str, [u8; 48])],
    ) -> Store<Memory> {
        let (reader, manifest) = parts(data, deflate, extra, digests, ERASE);
        Store::open(reader, manifest, 0).unwrap()
    }
    /// A BuildManifest identity's variant and behavior, and the purpose the
    /// inventory records for it.
    pub(crate) type Behavior = (&'static str, &'static str, Purpose);
    pub(crate) const ERASE: Behavior = (
        "Customer Erase Install (IPSW)",
        ERASE_BEHAVIOR,
        Purpose::Erase,
    );
    pub(crate) const UPDATE: Behavior = (
        "Customer Upgrade Install (IPSW)",
        UPDATE_BEHAVIOR,
        Purpose::Update,
    );
    /// The fixture's IPSW and inventory, its one identity `behavior`'s.
    pub(crate) fn parts(
        data: &[u8],
        deflate: bool,
        extra: &[(&str, &str, &[u8])],
        digests: &[(&str, [u8; 48])],
        behavior: Behavior,
    ) -> (Memory, PayloadManifest) {
        use sha2::{Digest, Sha384};
        let (variant, restore_behavior, purpose) = behavior;
        let mut components: BTreeMap<String, Value> = [(
            "OS".into(),
            Value::dict([
                ("Info", Value::dict([("Path", Value::from("os.dmg"))])),
                ("Digest", Value::Data(vec![1; 48])),
            ]),
        )]
        .into();
        for (name, path, bytes) in extra {
            components.insert(
                (*name).into(),
                Value::dict([
                    ("Info", Value::dict([("Path", Value::from(*path))])),
                    (
                        "Digest",
                        Value::Data(
                            digests
                                .iter()
                                .find(|(component, _)| component == name)
                                .map_or_else(
                                    || Sha384::digest(bytes).to_vec(),
                                    |(_, d)| d.to_vec(),
                                ),
                        ),
                    ),
                ]),
            );
        }
        let identity = Value::dict([
            (
                "Info",
                Value::dict([
                    ("Variant", Value::from(variant)),
                    ("RestoreBehavior", Value::from(restore_behavior)),
                    ("DeviceClass", Value::from("testap")),
                    ("OSDiskImageSize", Value::Integer(123)),
                ]),
            ),
            ("ApChipID", Value::from("0x8112")),
            ("ApBoardID", Value::from("0x24")),
            ("ApSecurityDomain", Value::from("0x1")),
            ("UniqueBuildID", Value::Data(vec![0x12; 8])),
            ("Manifest", Value::Dict(components)),
        ]);
        let build = plist::encode_xml(
            &Value::dict([("BuildIdentities", Value::Array(vec![identity]))]),
            Limits::default(),
        )
        .unwrap();
        let (mut m, _) = manifest();
        m.device_class = "testap".into();
        m.source.build_manifest_sha256 = crate::sha256(&build);
        m.global_manifests.clear();
        m.aea_keys.clear();
        let mut files: Vec<(&str, &[u8])> = vec![("os.dmg", data)];
        for (_, path, bytes) in extra {
            if !files.iter().any(|(name, _)| name == path) {
                files.push((*path, *bytes));
            }
        }
        m.members = files
            .iter()
            .map(|(name, bytes)| Member {
                name: (*name).into(),
                bytes: bytes.len() as u64,
                sha256: crate::sha256(bytes),
                sha384: None,
            })
            .collect();
        m.identities = vec![IdentitySet {
            index: 0,
            variant: variant.into(),
            purpose,
            members: files.iter().map(|(name, _)| (*name).into()).collect(),
        }];
        let entries: Vec<(&str, &[u8], bool)> =
            core::iter::once(("BuildManifest.plist", build.as_slice(), false))
                .chain(files.iter().map(|(name, bytes)| (*name, *bytes, deflate)))
                .collect();
        (Memory(archive(&entries, true)), m)
    }
    /// `s`'s member hashes as a block hash file, its manifest naming it.
    fn precomputed(s: &mut Store<Memory>, data: &[u8]) -> Vec<u8> {
        let file: Vec<u8> = data
            .chunks(BLOCK_BYTES)
            .flat_map(|block| Sha256::digest(block).to_vec())
            .collect();
        s.manifest.members[0].sha384 = Some(hex::encode(Sha384::digest(data)));
        s.manifest.block_hashes = Some(crate::payload::BlockHashes {
            file: crate::payload::BLOCK_HASHES_FILE.into(),
            block_bytes: crate::payload::HASH_BLOCK_BYTES,
            sha256: crate::sha256(&file),
        });
        s.manifest.validate().unwrap();
        file
    }

    #[test]
    fn recorded_hashes_check_every_member_before_the_restore_by_default() {
        let data: Vec<u8> = (0..BLOCK_BYTES * 2 + 5).map(|i| (i * 7) as u8).collect();
        let mut s = fixture(&data, true);
        let file = precomputed(&mut s, &data);
        s.adopt_block_hashes(&file).unwrap();
        assert!(!s.prepared(), "the whole member is still to be checked");
        s.prepare().unwrap();
        assert!(s.prepared());
        assert_eq!(s.read_at("os.dmg", 5, 10).unwrap(), data[5..15]);

        // The same records refuse a changed block or SHA-384 by name.
        let mut s = fixture(&data, true);
        let mut file = precomputed(&mut s, &data);
        file[64] ^= 1;
        s.manifest.block_hashes.as_mut().unwrap().sha256 = crate::sha256(&file);
        s.adopt_block_hashes(&file).unwrap();
        let error = s.prepare().unwrap_err().to_string();
        assert!(
            error.contains("os.dmg: source changed at block 2"),
            "{error}"
        );
        let mut s = fixture(&data, false);
        let file = precomputed(&mut s, &data);
        s.manifest.members[0].sha384 = Some("0".repeat(96));
        s.adopt_block_hashes(&file).unwrap();
        let error = s.prepare().unwrap_err().to_string();
        assert!(error.contains("os.dmg: SHA-384 differs"), "{error}");
        assert!(!s.prepared());
    }

    #[test]
    fn verify_on_read_checks_recorded_hashes_as_reads_reach_them() {
        let data: Vec<u8> = (0..BLOCK_BYTES * 2 + 5).map(|i| (i * 3) as u8).collect();
        let mut s = fixture(&data, false);
        let file = precomputed(&mut s, &data);
        assert!(!s.prepared());
        let error = s.adopt_block_hashes(&file[1..]).unwrap_err().to_string();
        assert!(error.contains("blocks.bin"), "{error}");
        s.set_verify(Verify::OnRead);
        s.adopt_block_hashes(&file).unwrap();
        // Nothing is left to read before the restore.
        assert!(s.prepared());
        s.prepare().unwrap();
        assert_eq!(s.digest384("os.dmg").unwrap(), &Sha384::digest(&data)[..]);
        assert_eq!(
            s.read_at("os.dmg", 10, 20).unwrap(),
            data[10..30],
            "a random read"
        );
        // Read in order from the start, the whole member meets its SHA-384.
        let mut whole = s.read_at("os.dmg", 0, BLOCK_BYTES).unwrap();
        whole.extend(
            s.read_at("os.dmg", BLOCK_BYTES as u64, data.len() - BLOCK_BYTES)
                .unwrap(),
        );
        assert_eq!(whole, data);

        // A block hash that differs refuses that block by number.
        let mut s = fixture(&data, true);
        let mut file = precomputed(&mut s, &data);
        file[32] ^= 1;
        s.manifest.block_hashes.as_mut().unwrap().sha256 = crate::sha256(&file);
        s.set_verify(Verify::OnRead);
        s.adopt_block_hashes(&file).unwrap();
        s.prepare().unwrap();
        s.read_at("os.dmg", 0, 10).unwrap();
        let error = s
            .read_at("os.dmg", BLOCK_BYTES as u64, 1)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("os.dmg: source changed at block 1"),
            "{error}"
        );

        // A SHA-384 that differs refuses the member once it is read whole.
        let mut s = fixture(&data, false);
        let file = precomputed(&mut s, &data);
        s.manifest.members[0].sha384 = Some("0".repeat(96));
        s.set_verify(Verify::OnRead);
        s.adopt_block_hashes(&file).unwrap();
        s.read_at("os.dmg", 0, BLOCK_BYTES).unwrap();
        let error = s
            .read_at("os.dmg", BLOCK_BYTES as u64, data.len() - BLOCK_BYTES)
            .unwrap_err()
            .to_string();
        assert!(error.contains("os.dmg: SHA-384 differs"), "{error}");
    }

    #[test]
    fn random_reads_cover_stored_and_deflated_zip64_and_refuse_changed_bytes() {
        let data: Vec<_> = (0..BLOCK_BYTES * 3 + 7).map(|i| i as u8).collect();
        for deflate in [false, true] {
            let mut s = fixture(&data, deflate);
            assert_eq!(s.identity().index, 0);
            assert_eq!(
                s.read_component("OS", BLOCK_BYTES as u64 - 3, 12).unwrap(),
                data[BLOCK_BYTES - 3..BLOCK_BYTES + 9]
            );
            assert!(s.read_at("os.dmg", u64::MAX, 2).is_err());
            assert!(s.read_at("unknown", 0, 0).is_err());
            assert!(s.read_at("os.dmg", 0, MAX_READ_BYTES + 1).is_err());
            assert_eq!(
                s.read_at("os.dmg", data.len() as u64, 0).unwrap(),
                Vec::<u8>::new()
            );
            if !deflate {
                let at = s
                    .reader
                    .0
                    .windows(16)
                    .position(|w| w == &data[..16])
                    .unwrap();
                s.reader.0[at] ^= 1;
                assert!(s.read_at("os.dmg", 0, 1).is_err());
            }
        }
    }
    #[test]
    fn a_restore_opens_an_erase_or_update_identity_its_inventory_names_alike() {
        let (reader, manifest) = parts(b"os", false, &[], &[], UPDATE);
        let store = Store::open(reader, manifest, 0).unwrap();
        assert_eq!(
            store
                .identity()
                .info()
                .unwrap()
                .required("RestoreBehavior")
                .unwrap()
                .string()
                .unwrap(),
            UPDATE_BEHAVIOR
        );
        // The inventory's purpose must name the identity's behavior.
        let (reader, mut manifest) = parts(b"os", false, &[], &[], UPDATE);
        manifest.identities[0].purpose = Purpose::Erase;
        let error = Store::open(reader, manifest, 0).err().unwrap().to_string();
        assert!(error.contains("identity mismatch"), "{error}");
        // An installed-system identity is no restore.
        let (reader, manifest) = parts(
            b"os",
            false,
            &[],
            &[],
            ("macOS Customer", "Install", Purpose::Installed),
        );
        let error = Store::open(reader, manifest, 0).err().unwrap().to_string();
        assert!(error.contains("neither erase nor update"), "{error}");
    }
    #[test]
    fn corrupt_inventory_fails_before_any_bytes_are_returned() {
        let mut s = fixture(b"hello", false);
        s.manifest.members[0].sha256 = "0".repeat(64);
        assert!(s.read_at("os.dmg", 0, 1).is_err());
        assert!(s.verified.is_empty());
    }
}
