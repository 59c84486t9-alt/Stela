//! An installed system's boot objects on its container's Preboot volume.
//!
//! Apple-silicon iBoot boots `Preboot/<volume-group>/boot/<nsih>/`, where
//! `nsih` is the SHA-384 next-stage manifest hash its LocalPolicy names, and
//! finds iBoot, the DeviceTree and firmware under `usr/standalone/firmware/`
//! and the kernel collection under
//! `System/Library/Caches/com.apple.kernelcaches/` (Asahi Linux docs
//! `fw/boot.md` and asahi-installer `src/osenum.py`, commits `0d1f891` and
//! `e93743d`). Reading the LocalPolicy is paused, so this module lists every
//! candidate directory with its objects and the seal of its volume group's
//! System volume; `stela_loader::installed` chooses among them by evidence.
//!
//! Inside a boot directory, objects are identified by their Image4 payload
//! type (`krnl`, `dtre`, `sptm`, `trxm`, `trst`, `isys`, …) rather than by
//! file name, so no undocumented name is assumed. The same listing
//! ([`boot_sets`]) reads the recoveryOS volumes, which lay out their boot
//! directories alike (`stela_loader::recovery`).
use crate::{
    apfs::{
        ApfsError, Container, FileKind, Volume,
        btree::Seal,
        uuid_text,
        volume::{APFS_VOL_ROLE_PREBOOT, APFS_VOL_ROLE_SYSTEM, Inode},
    },
    img4,
    payload::ReadAt,
};
use alloc::{format, string::String, vec, vec::Vec};

/// Directories of a boot directory that hold boot objects.
pub const OBJECT_DIRECTORIES: [&str; 2] = [
    "usr/standalone",
    "System/Library/Caches/com.apple.kernelcaches",
];
/// `System/Library/CoreServices/SystemVersion.plist` under the volume
/// group's Preboot directory (asahi-installer `src/osenum.py`).
pub const SYSTEM_VERSION: &str = "System/Library/CoreServices/SystemVersion.plist";
/// A SHA-384 in hexadecimal.
const BOOT_HASH_CHARACTERS: usize = 96;
const PEEK_BYTES: usize = 64;
const ACTIVE: &str = "active";
/// The hash and a line ending, with room for padding.
const ACTIVE_LIMIT: u64 = 256;
const LOCAL_POLICY: &str = "LocalPolicy";
const IMG4_SUFFIX: &str = ".img4";
const RECOVERY_POLICY_SUFFIX: &str = ".recovery.img4";
/// LocalPolicy files are a signed manifest of a few kilobytes.
const LOCAL_POLICY_LIMIT: u64 = 1024 * 1024;
const MAX_DEPTH: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrebootError {
    Apfs(ApfsError),
    /// No installed system's boot directory exists.
    NoBootDirectory,
    /// A required boot object is missing or appears more than once.
    Object(String),
    /// The volume group has no System volume, or several.
    System(String),
}

impl core::fmt::Display for PrebootError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Apfs(error) => write!(f, "{error}"),
            Self::NoBootDirectory => write!(f, "no Preboot volume group has a boot directory"),
            Self::Object(what) | Self::System(what) => write!(f, "{what}"),
        }
    }
}

impl core::error::Error for PrebootError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Apfs(error) => Some(error),
            _ => None,
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

/// The volume groups of the container's System volumes.
pub fn system_groups<R: ReadAt>(container: &mut Container<R>) -> Result<Vec<String>> {
    Ok(container
        .volumes()?
        .iter()
        .filter(|v| v.role == APFS_VOL_ROLE_SYSTEM)
        .map(|v| uuid_text(&v.volume_group))
        .collect())
}

/// Every top-level directory of `volume` with a `boot` directory, among
/// `groups` when it names any.
fn volume_groups<R: ReadAt>(
    container: &mut Container<R>,
    volume: &Volume,
    groups: &[String],
) -> Result<Vec<String>> {
    let device = &mut container.device;
    let root = volume.entries(device, crate::apfs::volume::ROOT_DIR_INO_NUM)?;
    Ok(root
        .into_iter()
        .filter(|entry| entry.kind == FileKind::Directory)
        .filter(|entry| {
            groups.is_empty() || groups.iter().any(|s| s.eq_ignore_ascii_case(&entry.name))
        })
        .filter(|entry| volume.child(device, entry.oid, "boot").is_ok())
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

/// Every boot directory of the Preboot volume's System volume groups, with
/// its objects, and the Preboot volume itself.
pub fn candidates<R: ReadAt>(container: &mut Container<R>) -> Result<(Volume, Vec<BootSet>)> {
    let preboot = container.volume_with_role(APFS_VOL_ROLE_PREBOOT)?;
    let groups = system_groups(container)?;
    let sets = boot_sets(container, &preboot, &groups)?;
    if sets.is_empty() {
        return Err(PrebootError::NoBootDirectory);
    }
    Ok((preboot, sets))
}

/// Every `<group>/boot/<hash>/` directory of `volume`, with its Image4
/// objects, for the top-level directories `groups` names (every one with a
/// `boot` directory when it names none). A Preboot volume, a container's
/// paired Recovery volume and the RecoveryOSContainer's volume share this
/// layout (Asahi Linux docs `platform/stock-partition-layout.md`, commit
/// `0d1f891`).
pub fn boot_sets<R: ReadAt>(
    container: &mut Container<R>,
    volume: &Volume,
    groups: &[String],
) -> Result<Vec<BootSet>> {
    let mut sets = Vec::new();
    for group in volume_groups(container, volume, groups)? {
        let device = &mut container.device;
        let boot = volume.lookup(device, &format!("{group}/boot"), true)?;
        for entry in volume.entries(device, boot.oid)? {
            if entry.kind != FileKind::Directory || !is_boot_hash(&entry.name) {
                continue;
            }
            let mut objects = Vec::new();
            for directory in OBJECT_DIRECTORIES {
                let path = format!("{group}/boot/{}/{directory}", entry.name);
                let Ok(inode) = volume.lookup(device, &path, true) else {
                    continue;
                };
                if inode.kind == FileKind::Directory {
                    collect(volume, device, &inode, &path, 0, &mut objects)?;
                }
            }
            sets.push(BootSet {
                volume_group: group.clone(),
                boot_hash: entry.name,
                objects,
            });
        }
    }
    Ok(sets)
}

/// The boot directory `<group>/boot/active` names: the 26A434 J473 LLB
/// (0xd3a80) opens `<group>/boot/<nsih>` and, when that fails, reads the
/// 96 hexadecimal characters of `<group>/boot/active` and opens the
/// directory they name. `None` when the file is absent.
pub fn active<R: ReadAt>(
    container: &mut Container<R>,
    preboot: &Volume,
    group: &str,
) -> Result<Option<String>> {
    let path = format!("{group}/boot/{ACTIVE}");
    let device = &mut container.device;
    let Ok(inode) = preboot.lookup(device, &path, true) else {
        return Ok(None);
    };
    if inode.kind != FileKind::Regular || inode.size > ACTIVE_LIMIT {
        return Err(PrebootError::Object(format!(
            "{path} is not a boot hash file"
        )));
    }
    active_text(&preboot.read(device, &inode)?)
        .map(Some)
        .ok_or_else(|| {
            PrebootError::Object(format!("{path} does not hold a 96-character boot hash"))
        })
}

/// The boot hash an `active` file holds, ignoring surrounding whitespace
/// and NULs.
fn active_text(bytes: &[u8]) -> Option<String> {
    let text = core::str::from_utf8(bytes)
        .ok()?
        .trim_matches(|c: char| c.is_ascii_whitespace() || c == '\0');
    is_boot_hash(text).then(|| text.into())
}

/// Every LocalPolicy of the volume group: the `<name>.img4` files of
/// `<group>/LocalPolicy/` other than `<name>.recovery.img4`, with their
/// bytes (LLB's `%s/%s/LocalPolicy`, `%s/%s.img4` and `%s/%s.recovery.img4`).
pub fn local_policies<R: ReadAt>(
    container: &mut Container<R>,
    preboot: &Volume,
    group: &str,
) -> Result<Vec<(String, Vec<u8>)>> {
    let path = format!("{group}/{LOCAL_POLICY}");
    let device = &mut container.device;
    let Ok(directory) = preboot.lookup(device, &path, true) else {
        return Ok(Vec::new());
    };
    let mut policies = Vec::new();
    for entry in preboot.entries(device, directory.oid)? {
        if entry.kind != FileKind::Regular
            || !entry.name.ends_with(IMG4_SUFFIX)
            || entry.name.ends_with(RECOVERY_POLICY_SUFFIX)
        {
            continue;
        }
        let inode = preboot.inode(device, entry.oid)?;
        if inode.size > LOCAL_POLICY_LIMIT {
            return Err(PrebootError::Object(format!(
                "{path}/{} is larger than a LocalPolicy",
                entry.name
            )));
        }
        policies.push((
            format!("{path}/{}", entry.name),
            preboot.read(device, &inode)?,
        ));
    }
    Ok(policies)
}

/// The seal of the file system the volume group's System volume roots from
/// (`apfs_root_to_xid`); `None` when it is not sealed.
pub fn system_seal<R: ReadAt>(container: &mut Container<R>, group: &str) -> Result<Option<Seal>> {
    let systems: Vec<Volume> = container
        .volumes()?
        .into_iter()
        .filter(|v| {
            v.role == APFS_VOL_ROLE_SYSTEM && uuid_text(&v.volume_group).eq_ignore_ascii_case(group)
        })
        .collect();
    match &systems[..] {
        [system] => Ok(system.root_seal(&mut container.device)?),
        [] => Err(PrebootError::System(format!(
            "volume group {group} has no System volume"
        ))),
        _ => Err(PrebootError::System(format!(
            "volume group {group} has {} System volumes",
            systems.len()
        ))),
    }
}

/// The `IM4M` an `IMG4` object carries, read without its payload; `None`
/// for a bare `IM4P` or an `IMG4` without one.
pub fn manifest<R: ReadAt>(
    container: &mut Container<R>,
    preboot: &Volume,
    object: &Object,
) -> Result<Option<Vec<u8>>> {
    let device = &mut container.device;
    let inode = preboot.inode(device, object.oid)?;
    let mut prefix = [0u8; PEEK_BYTES];
    preboot.read_at(device, &inode, 0, &mut prefix)?;
    let malformed = |e: img4::Img4Error| PrebootError::Object(format!("{}: {e}", object.path));
    let Some(tail) = img4::tail_offset(&prefix).map_err(malformed)? else {
        return Ok(None);
    };
    let bytes = inode
        .size
        .checked_sub(tail as u64)
        .ok_or_else(|| PrebootError::Object(format!("{}: truncated IMG4", object.path)))?;
    let mut rest =
        vec![0u8; usize::try_from(bytes).map_err(|_| ApfsError::Malformed("object size"))?];
    preboot.read_at(device, &inode, tail as u64, &mut rest)?;
    Ok(img4::tail_manifest(&rest)
        .map_err(malformed)?
        .map(<[u8]>::to_vec))
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
    fn an_active_file_names_one_boot_hash() {
        let hash = "0a".repeat(48);
        assert_eq!(
            active_text(format!("{hash}\n").as_bytes()),
            Some(hash.clone())
        );
        assert_eq!(
            active_text(format!("{hash}\0").as_bytes()),
            Some(hash.clone())
        );
        assert_eq!(active_text(&hash.as_bytes()[..94]), None);
        assert_eq!(active_text(&[0xff; 96]), None);
    }

    #[test]
    fn lists_the_fixture_boot_directory_and_its_objects_by_payload_type() -> Result<()> {
        let mut container = Container::open(fixture(), 0)?;
        let (preboot, sets) = candidates(&mut container)?;
        let [set] = &sets[..] else {
            panic!("one boot directory expected, got {sets:?}");
        };
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
        assert_eq!(img4::payload_type(parts.payload).unwrap(), *b"krnl");
        assert_eq!(
            manifest(&mut container, &preboot, kernel)?.as_deref(),
            parts.manifest
        );
        // The fixture names its directory by neither file.
        assert_eq!(active(&mut container, &preboot, &set.volume_group)?, None);
        assert!(local_policies(&mut container, &preboot, &set.volume_group)?.is_empty());
        // The fixture has a Preboot volume only.
        assert!(matches!(
            system_seal(&mut container, &set.volume_group),
            Err(PrebootError::System(_))
        ));
        Ok(())
    }
}
