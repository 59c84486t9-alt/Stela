//! An installed system's boot objects on its container's Preboot volume.
//!
//! Apple-silicon iBoot boots `Preboot/<volume-group>/boot/<nsih>/`, where
//! `nsih` is the SHA-384 next-stage manifest hash its LocalPolicy names, and
//! finds iBoot, the DeviceTree and firmware under `usr/standalone/firmware/`
//! and the kernel collection under
//! `System/Library/Caches/com.apple.kernelcaches/` (Asahi Linux docs
//! `fw/boot.md` and asahi-installer `src/osenum.py`, commits `0d1f891` and
//! `e93743d`). Reading the LocalPolicy is paused, so a boot directory is
//! taken only when it is the only one or the caller names it.
//!
//! Inside the boot directory, objects are identified by their Image4
//! payload type (`krnl`, `dtre`, `sptm`, `trxm`, `trst`, …) rather than by
//! file name, so no undocumented name is assumed.
use crate::{
    apfs::{
        ApfsError, Container, FileKind, Volume, uuid_text,
        volume::{APFS_VOL_ROLE_PREBOOT, APFS_VOL_ROLE_SYSTEM, Inode},
    },
    img4,
    payload::ReadAt,
};
use alloc::{format, string::String, vec, vec::Vec};

/// Directories of a boot directory that hold boot objects.
pub const OBJECT_DIRECTORIES: [&str; 2] = [
    "usr/standalone/firmware",
    "System/Library/Caches/com.apple.kernelcaches",
];
/// `System/Library/CoreServices/SystemVersion.plist` under the volume
/// group's Preboot directory (asahi-installer `src/osenum.py`).
pub const SYSTEM_VERSION: &str = "System/Library/CoreServices/SystemVersion.plist";
/// A SHA-384 in hexadecimal.
const BOOT_HASH_CHARACTERS: usize = 96;
const PEEK_BYTES: usize = 64;
const MAX_DEPTH: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrebootError {
    Apfs(ApfsError),
    /// No installed system's boot directory exists.
    NoBootDirectory,
    /// Several boot directories exist; choosing needs the LocalPolicy.
    Ambiguous(Vec<String>),
    /// A required boot object is missing or appears more than once.
    Object(String),
}

impl core::fmt::Display for PrebootError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Apfs(error) => write!(f, "{error}"),
            Self::NoBootDirectory => write!(f, "no Preboot volume group has a boot directory"),
            Self::Ambiguous(found) => write!(
                f,
                "{} boot directories ({}); choosing one needs the LocalPolicy nsih, which is paused",
                found.len(),
                found.join(", ")
            ),
            Self::Object(what) => write!(f, "{what}"),
        }
    }
}

impl From<ApfsError> for PrebootError {
    fn from(error: ApfsError) -> Self {
        Self::Apfs(error)
    }
}

pub type Result<T> = core::result::Result<T, PrebootError>;

/// One Image4 object in a boot directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    /// The path from the Preboot volume root.
    pub path: String,
    pub payload_type: [u8; 4],
    pub bytes: u64,
    pub oid: u64,
}

/// A boot directory and the objects in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootSet {
    pub volume_group: String,
    pub boot_hash: String,
    pub objects: Vec<Object>,
}

impl BootSet {
    /// `<volume-group>/boot/<boot-hash>`.
    pub fn directory(&self) -> String {
        format!("{}/boot/{}", self.volume_group, self.boot_hash)
    }

    /// The single object of this payload type; `None` when absent and an
    /// error when several exist.
    pub fn object(&self, payload_type: &[u8; 4]) -> Result<Option<&Object>> {
        let mut found = self
            .objects
            .iter()
            .filter(|o| &o.payload_type == payload_type);
        let first = found.next();
        if found.next().is_some() {
            return Err(PrebootError::Object(format!(
                "several `{}` objects in {}",
                String::from_utf8_lossy(payload_type),
                self.directory()
            )));
        }
        Ok(first)
    }

    /// The single object of this payload type, which must exist.
    pub fn require(&self, payload_type: &[u8; 4]) -> Result<&Object> {
        self.object(payload_type)?.ok_or_else(|| {
            PrebootError::Object(format!(
                "no `{}` object in {}",
                String::from_utf8_lossy(payload_type),
                self.directory()
            ))
        })
    }
}

fn is_boot_hash(name: &str) -> bool {
    name.len() == BOOT_HASH_CHARACTERS && name.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Every volume group directory with a `boot` directory on `preboot`: the
/// groups of the container's System volumes when there are any, else every
/// top-level directory that has one.
fn volume_groups<R: ReadAt>(container: &mut Container<R>, preboot: &Volume) -> Result<Vec<String>> {
    let systems: Vec<String> = container
        .volumes()?
        .iter()
        .filter(|v| v.role == APFS_VOL_ROLE_SYSTEM)
        .map(|v| uuid_text(&v.volume_group))
        .collect();
    let device = &mut container.device;
    let root = preboot.entries(device, crate::apfs::volume::ROOT_DIR_INO_NUM)?;
    Ok(root
        .into_iter()
        .filter(|entry| entry.kind == FileKind::Directory)
        .filter(|entry| {
            systems.is_empty() || systems.iter().any(|s| s.eq_ignore_ascii_case(&entry.name))
        })
        .filter(|entry| preboot.child(device, entry.oid, "boot").is_ok())
        .map(|entry| entry.name)
        .collect())
}

fn collect<R: ReadAt>(
    volume: &Volume,
    device: &mut crate::apfs::Device<R>,
    directory: &Inode,
    path: &str,
    depth: usize,
    objects: &mut Vec<Object>,
) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(PrebootError::Object(format!("{path} nests too deeply")));
    }
    for entry in volume.entries(device, directory.oid)? {
        let child_path = format!("{path}/{}", entry.name);
        let inode = volume.inode(device, entry.oid)?;
        match inode.kind {
            FileKind::Directory => {
                collect(volume, device, &inode, &child_path, depth + 1, objects)?
            }
            FileKind::Regular if inode.size >= PEEK_BYTES as u64 => {
                let mut prefix = [0u8; PEEK_BYTES];
                volume.read_at(device, &inode, 0, &mut prefix)?;
                if let Ok(payload_type) = img4::peek_payload_type(&prefix) {
                    objects.push(Object {
                        path: child_path,
                        payload_type,
                        bytes: inode.size,
                        oid: inode.oid,
                    });
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// The boot directory to use and its objects. `boot_hash` names one
/// explicitly; otherwise there must be exactly one.
pub fn boot_set<R: ReadAt>(
    container: &mut Container<R>,
    boot_hash: Option<&str>,
) -> Result<(Volume, BootSet)> {
    let preboot = container.volume_with_role(APFS_VOL_ROLE_PREBOOT)?;
    let mut candidates = Vec::new();
    for group in volume_groups(container, &preboot)? {
        let device = &mut container.device;
        let boot = preboot.lookup(device, &format!("{group}/boot"), true)?;
        for entry in preboot.entries(device, boot.oid)? {
            if entry.kind == FileKind::Directory && is_boot_hash(&entry.name) {
                candidates.push((group.clone(), entry.name));
            }
        }
    }
    let chosen = match boot_hash {
        Some(hash) => candidates
            .into_iter()
            .find(|(_, name)| name.eq_ignore_ascii_case(hash))
            .ok_or(PrebootError::NoBootDirectory)?,
        None => match candidates.len() {
            0 => return Err(PrebootError::NoBootDirectory),
            1 => candidates.remove(0),
            _ => {
                return Err(PrebootError::Ambiguous(
                    candidates
                        .iter()
                        .map(|(g, h)| format!("{g}/boot/{h}"))
                        .collect(),
                ));
            }
        },
    };
    let (volume_group, boot_hash) = chosen;
    let device = &mut container.device;
    let mut objects = Vec::new();
    for directory in OBJECT_DIRECTORIES {
        let path = format!("{volume_group}/boot/{boot_hash}/{directory}");
        let Ok(inode) = preboot.lookup(device, &path, true) else {
            continue;
        };
        if inode.kind == FileKind::Directory {
            collect(&preboot, device, &inode, &path, 0, &mut objects)?;
        }
    }
    Ok((
        preboot,
        BootSet {
            volume_group,
            boot_hash,
            objects,
        },
    ))
}

/// Read a whole boot object.
pub fn read<R: ReadAt>(
    container: &mut Container<R>,
    preboot: &Volume,
    object: &Object,
) -> Result<Vec<u8>> {
    let inode = preboot.inode(&mut container.device, object.oid)?;
    let mut bytes =
        vec![0u8; usize::try_from(inode.size).map_err(|_| ApfsError::Malformed("object size"))?];
    preboot.read_at(&mut container.device, &inode, 0, &mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apfs::tests::fixture;

    #[test]
    fn resolves_the_fixture_boot_directory_by_payload_type() -> Result<()> {
        let mut container = Container::open(fixture(), 0)?;
        let (preboot, set) = boot_set(&mut container, None)?;
        assert_eq!(set.volume_group, "A304C51B-D22F-4CDD-829D-3E30CB5BD87B");
        assert_eq!(set.boot_hash.len(), 96);
        let kernel = set.require(b"krnl")?;
        assert!(kernel.path.ends_with("com.apple.kernelcaches/kernelcache"));
        for kind in [b"dtre", b"sptm", b"trxm", b"trst"] {
            set.require(kind)?;
        }
        assert_eq!(set.object(b"rdsk")?, None);
        let bytes = read(&mut container, &preboot, kernel)?;
        let parts = img4::parse(&bytes).expect("an IMG4");
        assert!(parts.manifest.is_some());
        assert_eq!(img4::payload_type(parts.payload).unwrap(), *b"krnl");
        assert!(matches!(
            boot_set(&mut container, Some(&"0".repeat(96))),
            Err(PrebootError::NoBootDirectory)
        ));
        Ok(())
    }
}
