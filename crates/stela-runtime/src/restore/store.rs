//! IPSW-backed verified random reads. Existing ZIP64 and bounded inflater own
//! archive parsing. A member is scanned once against immutable payload SHA-256;
//! retained 64-KiB block hashes then detect changes before returning any read.
//! BuildManifest's component digest is a different (Image4) digest and remains
//! attached to the selected identity; it is never replaced with the ZIP hash.
use super::{
    Error, Result,
    plist::{self, Limits, Value},
};
use crate::payload::{
    MemberRead, PayloadManifest, ReadAt,
    zip::{Archive, Entry},
};
use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use sha2::{Digest, Sha256, Sha384};

pub const BLOCK_BYTES: usize = 64 * 1024;
pub const MAX_READ_BYTES: usize = 1024 * 1024;
const MAX_BLOCKS: usize = 1 << 20;
const MAX_BUILD_MANIFEST_BYTES: usize = 64 * 1024 * 1024;
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
struct Verified {
    entry: Entry,
    blocks: Vec<[u8; 32]>,
    sha384: [u8; 48],
}
pub struct Store<R> {
    reader: R,
    archive: Archive,
    manifest: PayloadManifest,
    identities: Vec<Identity>,
    selected: usize,
    verified: BTreeMap<String, Verified>,
    block_count: usize,
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
        let build = plist::decode(
            &bytes,
            Limits {
                bytes: MAX_BUILD_MANIFEST_BYTES,
                nodes: 2_000_000,
                depth: 64,
            },
        )?;
        let identities: Vec<_> = build
            .required("BuildIdentities")?
            .array()?
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, value)| Identity { index, value })
            .collect();
        let identity = identities
            .get(selected)
            .ok_or(Error::Invalid("BuildManifest identity index"))?;
        if identity.info()?.required("RestoreBehavior")?.string()? != "Erase" {
            return Err(Error::Invalid("selected identity is not erase"));
        }
        let set = manifest
            .identities
            .iter()
            .find(|s| s.index as usize == selected)
            .ok_or(Error::Invalid("identity absent from payload inventory"))?;
        if set.variant != identity.variant()?
            || set.purpose != crate::payload::Purpose::Erase
            || identity.info()?.required("DeviceClass")?.string()? != manifest.device_class
        {
            return Err(Error::Invalid("payload/BuildManifest identity mismatch"));
        }
        Ok(Self {
            reader,
            archive,
            manifest,
            identities,
            selected,
            verified: BTreeMap::new(),
            block_count: 0,
        })
    }
    pub fn manifest(&self) -> &PayloadManifest {
        &self.manifest
    }
    pub fn identity(&self) -> &Identity {
        &self.identities[self.selected]
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
    /// Admission/preflight work, before connecting restored: scan all staged
    /// inventory members once, then requests only read and verify touched blocks.
    pub fn prepare(&mut self) -> Result<()> {
        let paths: Vec<_> = self
            .manifest
            .members
            .iter()
            .map(|m| m.name.clone())
            .collect();
        for path in paths {
            self.verify(&path)?;
        }
        Ok(())
    }
    pub fn prepared(&self) -> bool {
        self.manifest
            .members
            .iter()
            .all(|m| self.verified.contains_key(&m.name))
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
        let verified = &self.verified[path];
        let mut result = Vec::with_capacity(len);
        let mut at = offset;
        while result.len() < len {
            let block = at / BLOCK_BYTES as u64;
            let start = block * BLOCK_BYTES as u64;
            let size = (size - start).min(BLOCK_BYTES as u64) as usize;
            let mut bytes = vec![0; size];
            self.archive
                .read_member_at(&mut self.reader, &verified.entry, start, &mut bytes)
                .map_err(payload)?;
            let actual: [u8; 32] = Sha256::digest(&bytes).into();
            if actual != verified.blocks[block as usize] {
                return Err(Error::Payload(format!(
                    "{path}: source changed at block {block}"
                )));
            }
            let skip = (at - start) as usize;
            let n = (size - skip).min(len - result.len());
            result.extend_from_slice(&bytes[skip..skip + n]);
            at += n as u64;
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
        IdentitySet, Member, Purpose,
        tests::{Memory, manifest},
        zip::tests::archive,
    };
    pub(crate) fn fixture(data: &[u8], deflate: bool) -> Store<Memory> {
        let identity = Value::dict([
            (
                "Info",
                Value::dict([
                    ("Variant", Value::from("Customer Erase Install (IPSW)")),
                    ("RestoreBehavior", Value::from("Erase")),
                    ("DeviceClass", Value::from("testap")),
                    ("OSDiskImageSize", Value::Integer(123)),
                ]),
            ),
            ("ApChipID", Value::from("0x8112")),
            ("ApBoardID", Value::from("0x24")),
            ("ApSecurityDomain", Value::from("0x1")),
            (
                "Manifest",
                Value::dict([(
                    "OS",
                    Value::dict([
                        ("Info", Value::dict([("Path", Value::from("os.dmg"))])),
                        ("Digest", Value::Data(vec![1; 48])),
                    ]),
                )]),
            ),
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
        m.members = vec![Member {
            name: "os.dmg".into(),
            bytes: data.len() as u64,
            sha256: crate::sha256(data),
        }];
        m.identities = vec![IdentitySet {
            index: 0,
            variant: "Customer Erase Install (IPSW)".into(),
            purpose: Purpose::Erase,
            members: vec!["os.dmg".into()],
        }];
        Store::open(
            Memory(archive(
                &[
                    ("BuildManifest.plist", &build, false),
                    ("os.dmg", data, deflate),
                ],
                true,
            )),
            m,
            0,
        )
        .unwrap()
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
    fn corrupt_inventory_fails_before_any_bytes_are_returned() {
        let mut s = fixture(b"hello", false);
        s.manifest.members[0].sha256 = "0".repeat(64);
        assert!(s.read_at("os.dmg", 0, 1).is_err());
        assert!(s.verified.is_empty());
    }
}
