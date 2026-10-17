//! Volumes and their file-system records (Apple File System Reference,
//! "Volumes", "File-System Objects", "Data Streams", "Extended Fields",
//! "Snapshot Metadata" and "Sealed Volumes").
//!
//! File-system records are sorted by object identifier, then record type
//! ("File-System Objects": the `j_key_t` comparison rules), so every record
//! of one object is found from the lower bound `(oid, type)`. Directory
//! entries are scanned rather than located by name hash, which keeps lookup
//! independent of Unicode normalization: names compare byte for byte, and
//! ASCII letters case-insensitively on a case-insensitive volume.
use super::{
    ApfsError, Device, Result,
    btree::{Callback, Hash, Omap, Seal, Tree, Visit},
    object::{self, Header, OBJECT_TYPE_FS, OBJECT_TYPE_INTEGRITY_META, Storage},
    u16_at, u32_at, u64_at, uuid_at,
};
use crate::payload::ReadAt;
use alloc::{format, string::String, vec, vec::Vec};
use core::cmp::Ordering;

pub const APFS_VOL_ROLE_NONE: u16 = 0x0000;
pub const APFS_VOL_ROLE_SYSTEM: u16 = 0x0001;
pub const APFS_VOL_ROLE_USER: u16 = 0x0002;
pub const APFS_VOL_ROLE_RECOVERY: u16 = 0x0004;
pub const APFS_VOL_ROLE_VM: u16 = 0x0008;
pub const APFS_VOL_ROLE_PREBOOT: u16 = 0x0010;
pub const APFS_VOL_ROLE_INSTALLER: u16 = 0x0020;
/// `1 << APFS_VOLUME_ENUM_SHIFT`.
pub const APFS_VOL_ROLE_DATA: u16 = 0x0040;
/// `3 << APFS_VOLUME_ENUM_SHIFT`.
pub const APFS_VOL_ROLE_UPDATE: u16 = 0x00c0;

const APFS_MAGIC: &[u8; 4] = b"APSB";
const APFS_FS_UNENCRYPTED: u64 = 0x0000_0001;
const APFS_INCOMPAT_CASE_INSENSITIVE: u64 = 0x0000_0001;
const APFS_INCOMPAT_NORMALIZATION_INSENSITIVE: u64 = 0x0000_0008;
const APFS_INCOMPAT_SEALED_VOLUME: u64 = 0x0000_0020;

const OBJ_ID_MASK: u64 = 0x0fff_ffff_ffff_ffff;
const OBJ_TYPE_SHIFT: u32 = 60;
const APFS_TYPE_SNAP_METADATA: u8 = 1;
const APFS_TYPE_INODE: u8 = 3;
const APFS_TYPE_XATTR: u8 = 4;
const APFS_TYPE_FILE_EXTENT: u8 = 8;
const APFS_TYPE_DIR_REC: u8 = 9;

pub const ROOT_DIR_INO_NUM: u64 = 2;
const J_DREC_LEN_MASK: u32 = 0x0000_03ff;
const DREC_TYPE_MASK: u16 = 0x000f;
const J_FILE_EXTENT_LEN_MASK: u64 = 0x00ff_ffff_ffff_ffff;
const XATTR_DATA_STREAM: u16 = 0x0001;
const XATTR_DATA_EMBEDDED: u16 = 0x0002;
const INO_EXT_TYPE_NAME: u8 = 4;
const INO_EXT_TYPE_DSTREAM: u8 = 8;
const S_IFMT: u16 = 0o170000;
/// `UF_COMPRESSED` from BSD `sys/stat.h`: the data lives in a decmpfs
/// extended attribute or resource fork, which this reader does not inflate.
const UF_COMPRESSED: u32 = 0x0000_0020;
const INODE_HAS_UNCOMPRESSED_SIZE: u64 = 0x0004_0000;
pub const SYMLINK_EA_NAME: &str = "com.apple.fs.symlink";
const MAX_SYMLINKS: usize = 32;
/// `APFS_SEAL_BROKEN` in `integrity_meta_phys_t.im_flags`.
const APFS_SEAL_BROKEN: u32 = 1 << 0;

/// The type of a file-system object, from `mode_t` or a directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Directory,
    Regular,
    Symlink,
    /// FIFOs, devices, sockets and whiteouts.
    Other,
}

impl FileKind {
    fn from_mode(mode: u16) -> Self {
        match mode & S_IFMT {
            0o040000 => Self::Directory,
            0o100000 => Self::Regular,
            0o120000 => Self::Symlink,
            _ => Self::Other,
        }
    }

    /// `DT_*` values in `j_drec_val_t.flags`.
    fn from_drec(flags: u16) -> Self {
        match flags & DREC_TYPE_MASK {
            4 => Self::Directory,
            8 => Self::Regular,
            10 => Self::Symlink,
            _ => Self::Other,
        }
    }
}

/// `j_inode_val_t` and the extended fields this reader uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inode {
    pub oid: u64,
    pub parent: u64,
    /// The identifier its data stream's extents are keyed by.
    pub private_id: u64,
    pub kind: FileKind,
    pub mode: u16,
    pub bsd_flags: u32,
    pub internal_flags: u64,
    /// Bytes of the data stream (`j_dstream_t.size`); zero without one.
    pub size: u64,
    /// `uncompressed_size`, for a transparently compressed file.
    pub uncompressed_size: Option<u64>,
    pub name: Option<String>,
}

impl Inode {
    /// The file's length as its readers see it.
    pub fn logical_size(&self) -> u64 {
        if self.bsd_flags & UF_COMPRESSED != 0 {
            self.uncompressed_size.unwrap_or(self.size)
        } else {
            self.size
        }
    }
}

/// One directory entry (`j_drec_val_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub oid: u64,
    pub kind: FileKind,
}

/// One snapshot (`j_snap_metadata_val_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub name: String,
    pub xid: u64,
    /// The physical address of the volume superblock it preserves.
    pub superblock: u64,
}

/// One file extent: `length` bytes at logical `offset`, from physical
/// block `block`, or a hole when `block` is zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Extent {
    offset: u64,
    length: u64,
    block: u64,
}

/// A volume: the fields of `apfs_superblock_t` this reader uses and its
/// object map. Its trees open on demand, so a volume whose file system is
/// encrypted can still be listed by name and role.
#[derive(Debug, Clone)]
pub struct Volume {
    pub paddr: u64,
    /// Object-map lookups resolve as of this transaction: the volume's own,
    /// or a snapshot's.
    pub xid: u64,
    pub name: String,
    pub role: u16,
    pub uuid: [u8; 16],
    /// `apfs_volume_group_id`: shared by a System volume and its Data volume.
    pub volume_group: [u8; 16],
    pub incompatible_features: u64,
    pub fs_flags: u64,
    pub encrypted: bool,
    pub sealed: bool,
    /// `apfs_root_to_xid`: the transaction of the snapshot the volume roots
    /// from, or zero to root from the live file system.
    pub root_to_xid: u64,
    omap: Omap,
    root_tree_type: u32,
    root_tree_oid: u64,
    snapshot_tree_type: u32,
    snapshot_tree_oid: u64,
    fext_tree_type: u32,
    fext_tree_oid: u64,
    integrity_meta_oid: u64,
}

fn key_id_and_type(key: &[u8]) -> Result<(u64, u8)> {
    let value = u64_at(key, 0)?;
    Ok((value & OBJ_ID_MASK, (value >> OBJ_TYPE_SHIFT) as u8))
}

fn c_string(bytes: &[u8]) -> Result<String> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8(bytes[..end].to_vec()).map_err(|_| ApfsError::Malformed("name is not UTF-8"))
}

/// The extended fields of an inode or directory entry: `(type, data)`.
fn extended_fields(blob: &[u8]) -> Result<Vec<(u8, &[u8])>> {
    if blob.is_empty() {
        return Ok(Vec::new());
    }
    let count = u16_at(blob, 0)? as usize;
    // `xf_blob_t` and its `x_field_t` headers, then each value padded to a
    // multiple of eight bytes.
    let mut data = 4 + count * 4;
    let mut fields = Vec::with_capacity(count);
    for index in 0..count {
        let header = 4 + index * 4;
        let kind = *blob
            .get(header)
            .ok_or(ApfsError::Malformed("extended field"))?;
        let size = u16_at(blob, header + 2)? as usize;
        let value = blob
            .get(data..data + size)
            .ok_or(ApfsError::Malformed("extended field lies outside its blob"))?;
        fields.push((kind, value));
        data += size.next_multiple_of(8);
    }
    Ok(fields)
}

impl Volume {
    pub(crate) fn open<R: ReadAt>(device: &mut Device<R>, paddr: u64) -> Result<Self> {
        let block = device.read_object(paddr)?;
        let header = Header::parse(&block)?;
        if header.object_type() != OBJECT_TYPE_FS || block.get(32..36) != Some(APFS_MAGIC) {
            return Err(ApfsError::Malformed("not a volume superblock"));
        }
        let fs_flags = u64_at(&block, 264)?;
        let incompatible_features = u64_at(&block, 56)?;
        let omap = Omap::open(device, u64_at(&block, 128)?)?;
        Ok(Self {
            paddr,
            xid: header.xid,
            name: c_string(
                block
                    .get(704..960)
                    .ok_or(ApfsError::Malformed("volume name"))?,
            )?,
            role: u16_at(&block, 964)?,
            uuid: uuid_at(&block, 240)?,
            volume_group: uuid_at(&block, 1008)?,
            incompatible_features,
            fs_flags,
            encrypted: fs_flags & APFS_FS_UNENCRYPTED == 0,
            sealed: incompatible_features & APFS_INCOMPAT_SEALED_VOLUME != 0,
            root_to_xid: u64_at(&block, 968)?,
            omap,
            root_tree_type: u32_at(&block, 116)?,
            root_tree_oid: u64_at(&block, 136)?,
            snapshot_tree_type: u32_at(&block, 124)?,
            snapshot_tree_oid: u64_at(&block, 152)?,
            fext_tree_type: u32_at(&block, 1040)?,
            fext_tree_oid: u64_at(&block, 1032)?,
            integrity_meta_oid: u64_at(&block, 1024)?,
        })
    }

    fn case_insensitive(&self) -> bool {
        self.incompatible_features & APFS_INCOMPAT_CASE_INSENSITIVE != 0
    }

    /// Whether directory entries use `j_drec_hashed_key_t`.
    fn hashed_names(&self) -> bool {
        self.incompatible_features
            & (APFS_INCOMPAT_CASE_INSENSITIVE | APFS_INCOMPAT_NORMALIZATION_INSENSITIVE)
            != 0
    }

    /// A sealed volume's `integrity_meta_phys_t`: its hash type and the
    /// hash of the file-system tree's root node. A broken seal is refused.
    pub fn seal<R: ReadAt>(&self, device: &mut Device<R>) -> Result<Option<Seal>> {
        if !self.sealed {
            return Ok(None);
        }
        let mapping = self
            .omap
            .lookup(device, self.integrity_meta_oid, self.xid)?;
        let block = device.read_object(mapping.paddr)?;
        if Header::parse(&block)?.object_type() != OBJECT_TYPE_INTEGRITY_META {
            return Err(ApfsError::Malformed("expected integrity metadata"));
        }
        if u32_at(&block, 36)? & APFS_SEAL_BROKEN != 0 {
            return Err(ApfsError::Unsupported("a volume whose seal is broken"));
        }
        let hash = Hash::from_type(u32_at(&block, 40)?)?;
        let offset = u32_at(&block, 44)? as usize;
        let root = block
            .get(offset..offset + hash.size())
            .ok_or(ApfsError::Malformed("root hash lies outside its object"))?
            .to_vec();
        Ok(Some(Seal { hash, root }))
    }

    /// A volume tree by its `apfs_*_tree_type` and identifier;
    /// `seal_root` checks the root node against the seal's root hash.
    fn tree<R: ReadAt>(
        &self,
        device: &mut Device<R>,
        type_field: u32,
        oid: u64,
        seal_root: bool,
    ) -> Result<Tree> {
        let (root, headerless) = match Storage::of(type_field) {
            Storage::Physical => {
                // A physical root shows by its zero header whether it has one.
                let block = device.read_block(oid)?;
                (oid, block[..object::HEADER_BYTES].iter().all(|&b| b == 0))
            }
            Storage::Virtual => {
                let mapping = self.omap.lookup(device, oid, self.xid)?;
                (mapping.paddr, mapping.headerless)
            }
            Storage::Ephemeral => {
                return Err(ApfsError::Unsupported("ephemeral volume trees"));
            }
        };
        let seal = self.seal(device)?;
        let mut tree = Tree::open(device, root, self.xid, headerless, seal.as_ref(), seal_root)?;
        if Storage::of(type_field) == Storage::Virtual {
            tree.relative_to(oid);
        }
        Ok(tree)
    }

    fn fs_tree<R: ReadAt>(&self, device: &mut Device<R>) -> Result<Tree> {
        if self.encrypted {
            return Err(ApfsError::Encrypted);
        }
        self.tree(device, self.root_tree_type, self.root_tree_oid, true)
    }

    /// Visit the records of object `oid` with type `kind`, in order.
    fn records<R: ReadAt>(
        &self,
        device: &mut Device<R>,
        oid: u64,
        kind: u8,
        callback: &mut Callback<'_>,
    ) -> Result<()> {
        let tree = self.fs_tree(device)?;
        let compare =
            |key: &[u8]| -> Result<Ordering> { Ok(key_id_and_type(key)?.cmp(&(oid, kind))) };
        tree.visit(device, Some(&self.omap), &compare, &mut |key, value| {
            if key_id_and_type(key)? != (oid, kind) {
                return Ok(Visit::Stop);
            }
            callback(key, value)
        })
    }

    pub fn inode<R: ReadAt>(&self, device: &mut Device<R>, oid: u64) -> Result<Inode> {
        let mut found = None;
        self.records(device, oid, APFS_TYPE_INODE, &mut |_, value| {
            found = Some(value.to_vec());
            Ok(Visit::Stop)
        })?;
        let value = found.ok_or_else(|| ApfsError::NotFound(format!("inode {oid}")))?;
        let mode = u16_at(&value, 80)?;
        let internal_flags = u64_at(&value, 48)?;
        let mut size = 0;
        let mut name = None;
        for (kind, data) in extended_fields(value.get(92..).unwrap_or(&[]))? {
            match kind {
                INO_EXT_TYPE_DSTREAM => size = u64_at(data, 0)?,
                INO_EXT_TYPE_NAME => name = Some(c_string(data)?),
                _ => {}
            }
        }
        Ok(Inode {
            oid,
            parent: u64_at(&value, 0)?,
            private_id: u64_at(&value, 8)?,
            kind: FileKind::from_mode(mode),
            mode,
            bsd_flags: u32_at(&value, 68)?,
            internal_flags,
            size,
            uncompressed_size: (internal_flags & INODE_HAS_UNCOMPRESSED_SIZE != 0)
                .then(|| u64_at(&value, 84))
                .transpose()?,
            name,
        })
    }

    /// The entries of directory `oid`.
    pub fn entries<R: ReadAt>(&self, device: &mut Device<R>, oid: u64) -> Result<Vec<Entry>> {
        let hashed = self.hashed_names();
        let mut entries = Vec::new();
        self.records(device, oid, APFS_TYPE_DIR_REC, &mut |key, value| {
            let name = if hashed {
                let length = (u32_at(key, 8)? & J_DREC_LEN_MASK) as usize;
                key.get(12..12 + length)
            } else {
                let length = u16_at(key, 8)? as usize;
                key.get(10..10 + length)
            }
            .ok_or(ApfsError::Malformed("directory entry name"))?;
            entries.push(Entry {
                name: c_string(name)?,
                oid: u64_at(value, 0)?,
                kind: FileKind::from_drec(u16_at(value, 16)?),
            });
            Ok(Visit::Continue)
        })?;
        Ok(entries)
    }

    fn names_match(&self, stored: &str, wanted: &str) -> bool {
        stored == wanted
            || (self.case_insensitive()
                && stored.is_ascii()
                && wanted.is_ascii()
                && stored.eq_ignore_ascii_case(wanted))
    }

    /// The child of directory `parent` named `name`.
    pub fn child<R: ReadAt>(
        &self,
        device: &mut Device<R>,
        parent: u64,
        name: &str,
    ) -> Result<Entry> {
        self.entries(device, parent)?
            .into_iter()
            .find(|entry| self.names_match(&entry.name, name))
            .ok_or_else(|| ApfsError::NotFound(String::from(name)))
    }

    /// The inode at `path` from the volume root. Symbolic links in
    /// intermediate components are followed; the final one only when
    /// `follow` is set. Absolute link targets start at the volume root.
    pub fn lookup<R: ReadAt>(
        &self,
        device: &mut Device<R>,
        path: &str,
        follow: bool,
    ) -> Result<Inode> {
        let mut pending: Vec<String> = path
            .split('/')
            .filter(|c| !c.is_empty())
            .rev()
            .map(String::from)
            .collect();
        let mut current = self.inode(device, ROOT_DIR_INO_NUM)?;
        let mut links = 0;
        while let Some(component) = pending.pop() {
            match component.as_str() {
                "." => continue,
                ".." => {
                    if current.oid != ROOT_DIR_INO_NUM {
                        current = self.inode(device, current.parent)?;
                    }
                    continue;
                }
                _ => {}
            }
            if current.kind != FileKind::Directory {
                return Err(ApfsError::NotFound(format!(
                    "{path}: {} is not a directory",
                    component
                )));
            }
            let entry = self
                .child(device, current.oid, &component)
                .map_err(|_| ApfsError::NotFound(format!("{path} ({component})")))?;
            let inode = self.inode(device, entry.oid)?;
            if inode.kind == FileKind::Symlink && (follow || !pending.is_empty()) {
                links += 1;
                if links > MAX_SYMLINKS {
                    return Err(ApfsError::Malformed("too many symbolic links"));
                }
                let target = self.symlink_target(device, &inode)?;
                if target.starts_with('/') {
                    current = self.inode(device, ROOT_DIR_INO_NUM)?;
                }
                pending.extend(
                    target
                        .split('/')
                        .filter(|c| !c.is_empty())
                        .rev()
                        .map(String::from),
                );
                continue;
            }
            current = inode;
        }
        Ok(current)
    }

    /// An extended attribute of object `oid`, or `None`.
    pub fn xattr<R: ReadAt>(
        &self,
        device: &mut Device<R>,
        oid: u64,
        name: &str,
    ) -> Result<Option<Vec<u8>>> {
        let mut found: Option<(u16, Vec<u8>)> = None;
        self.records(device, oid, APFS_TYPE_XATTR, &mut |key, value| {
            let length = u16_at(key, 8)? as usize;
            let stored = c_string(
                key.get(10..10 + length)
                    .ok_or(ApfsError::Malformed("xattr name"))?,
            )?;
            if stored != name {
                return Ok(Visit::Continue);
            }
            let flags = u16_at(value, 0)?;
            let data_length = u16_at(value, 2)? as usize;
            let data = value
                .get(4..4 + data_length)
                .ok_or(ApfsError::Malformed("xattr data"))?;
            found = Some((flags, data.to_vec()));
            Ok(Visit::Stop)
        })?;
        match found {
            None => Ok(None),
            Some((flags, data)) if flags & XATTR_DATA_EMBEDDED != 0 => Ok(Some(data)),
            Some((flags, data)) if flags & XATTR_DATA_STREAM != 0 => {
                // `j_xattr_dstream_t`: the stream's identifier, then its size.
                let stream = u64_at(&data, 0)?;
                let size = u64_at(&data, 8)?;
                let mut bytes =
                    vec![0; usize::try_from(size).map_err(|_| ApfsError::Malformed("xattr size"))?];
                self.read_stream(device, stream, size, 0, &mut bytes)?;
                Ok(Some(bytes))
            }
            Some(_) => Err(ApfsError::Malformed(
                "xattr is neither embedded nor a stream",
            )),
        }
    }

    /// The target of a symbolic link.
    pub fn symlink_target<R: ReadAt>(
        &self,
        device: &mut Device<R>,
        inode: &Inode,
    ) -> Result<String> {
        let data = self
            .xattr(device, inode.oid, SYMLINK_EA_NAME)?
            .ok_or(ApfsError::Malformed("symbolic link without a target"))?;
        c_string(&data)
    }

    /// The extents of stream `private_id`, from the file-extent tree of a
    /// sealed volume or the file-system tree otherwise.
    fn extents<R: ReadAt>(&self, device: &mut Device<R>, private_id: u64) -> Result<Vec<Extent>> {
        let mut extents = Vec::new();
        if self.sealed && self.fext_tree_oid != 0 {
            let tree = self.tree(device, self.fext_tree_type, self.fext_tree_oid, false)?;
            let compare = |key: &[u8]| -> Result<Ordering> { Ok(u64_at(key, 0)?.cmp(&private_id)) };
            tree.visit(device, Some(&self.omap), &compare, &mut |key, value| {
                if u64_at(key, 0)? != private_id {
                    return Ok(Visit::Stop);
                }
                extents.push(Extent {
                    offset: u64_at(key, 8)?,
                    length: u64_at(value, 0)? & J_FILE_EXTENT_LEN_MASK,
                    block: u64_at(value, 8)?,
                });
                Ok(Visit::Continue)
            })?;
        } else {
            self.records(
                device,
                private_id,
                APFS_TYPE_FILE_EXTENT,
                &mut |key, value| {
                    if u64_at(value, 16)? != 0 {
                        return Err(ApfsError::Encrypted);
                    }
                    extents.push(Extent {
                        offset: u64_at(key, 8)?,
                        length: u64_at(value, 0)? & J_FILE_EXTENT_LEN_MASK,
                        block: u64_at(value, 8)?,
                    });
                    Ok(Visit::Continue)
                },
            )?;
        }
        Ok(extents)
    }

    fn read_stream<R: ReadAt>(
        &self,
        device: &mut Device<R>,
        private_id: u64,
        size: u64,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<()> {
        let end = offset
            .checked_add(buffer.len() as u64)
            .filter(|&end| end <= size)
            .ok_or(ApfsError::Malformed("read past the end of the stream"))?;
        // Holes and the space past the last extent read as zeros.
        buffer.fill(0);
        let block_size = u64::from(device.block_size());
        for extent in self.extents(device, private_id)? {
            let start = extent.offset.max(offset);
            let stop = (extent.offset + extent.length).min(end);
            if start >= stop || extent.block == 0 {
                continue;
            }
            let into = (start - offset) as usize..(stop - offset) as usize;
            let from = extent.block * block_size + (start - extent.offset);
            device.read_bytes(from, &mut buffer[into])?;
        }
        Ok(())
    }

    /// Read `buffer.len()` bytes of a regular file from `offset`.
    pub fn read_at<R: ReadAt>(
        &self,
        device: &mut Device<R>,
        inode: &Inode,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<()> {
        if inode.kind != FileKind::Regular {
            return Err(ApfsError::NotFound(format!(
                "inode {} is not a regular file",
                inode.oid
            )));
        }
        if inode.bsd_flags & UF_COMPRESSED != 0 {
            return Err(ApfsError::Unsupported("transparently compressed files"));
        }
        self.read_stream(device, inode.private_id, inode.size, offset, buffer)
    }

    /// A whole regular file.
    pub fn read<R: ReadAt>(&self, device: &mut Device<R>, inode: &Inode) -> Result<Vec<u8>> {
        let mut bytes =
            vec![0; usize::try_from(inode.size).map_err(|_| ApfsError::Malformed("file size"))?];
        self.read_at(device, inode, 0, &mut bytes)?;
        Ok(bytes)
    }

    /// The volume's snapshots, oldest first.
    pub fn snapshots<R: ReadAt>(&self, device: &mut Device<R>) -> Result<Vec<Snapshot>> {
        if self.snapshot_tree_oid == 0 {
            return Ok(Vec::new());
        }
        let tree = self.tree(
            device,
            self.snapshot_tree_type,
            self.snapshot_tree_oid,
            false,
        )?;
        let mut snapshots = Vec::new();
        // Metadata keys are `(xid, SNAP_METADATA)`; name keys sort after
        // them under the all-ones identifier. Visit from the start.
        let compare = |_: &[u8]| -> Result<Ordering> { Ok(Ordering::Greater) };
        tree.visit(device, Some(&self.omap), &compare, &mut |key, value| {
            let (xid, kind) = key_id_and_type(key)?;
            if kind != APFS_TYPE_SNAP_METADATA {
                return Ok(Visit::Continue);
            }
            let length = u16_at(value, 48)? as usize;
            snapshots.push(Snapshot {
                name: c_string(
                    value
                        .get(50..50 + length)
                        .ok_or(ApfsError::Malformed("snapshot name"))?,
                )?,
                xid,
                superblock: u64_at(value, 8)?,
            });
            Ok(Visit::Continue)
        })?;
        Ok(snapshots)
    }

    /// The seal of the file system the volume roots from: the snapshot
    /// `apfs_root_to_xid` names, or the live volume when it is zero. `None`
    /// when that file system is not sealed.
    pub fn root_seal<R: ReadAt>(&self, device: &mut Device<R>) -> Result<Option<Seal>> {
        if self.root_to_xid == 0 {
            return self.seal(device);
        }
        let snapshot = self
            .snapshots(device)?
            .into_iter()
            .find(|snapshot| snapshot.xid == self.root_to_xid)
            .ok_or(ApfsError::Malformed(
                "no snapshot has the volume's root_to_xid",
            ))?;
        self.snapshot(device, &snapshot)?.seal(device)
    }

    /// The volume as it was when `snapshot` was taken.
    pub fn snapshot<R: ReadAt>(&self, device: &mut Device<R>, snapshot: &Snapshot) -> Result<Self> {
        let mut volume = Self::open(device, snapshot.superblock)?;
        volume.xid = snapshot.xid;
        Ok(volume)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apfs::{
        Container,
        tests::{fixture, sealed_fixture},
    };

    const GROUP: &str = "A304C51B-D22F-4CDD-829D-3E30CB5BD87B";

    fn pattern(length: usize) -> Vec<u8> {
        (0..length)
            .map(|i| ((i * 7 + i / 251) & 0xff) as u8)
            .collect()
    }

    #[test]
    fn reads_the_preboot_fixture() -> Result<()> {
        let mut container = Container::open(fixture(), 0)?;
        let volume = container.volume_with_role(APFS_VOL_ROLE_PREBOOT)?;
        assert!(!volume.encrypted && !volume.sealed);
        let device = &mut container.device;
        let root: Vec<String> = volume
            .entries(device, ROOT_DIR_INO_NUM)?
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(root.iter().any(|n| n == GROUP) && root.iter().any(|n| n == "sparse"));
        let raw = volume.lookup(device, "pattern.bin", true)?;
        assert_eq!(raw.size, 300_000);
        assert_eq!(volume.read(device, &raw)?, pattern(300_000));
        let mut middle = [0u8; 16];
        volume.read_at(device, &raw, 123_456, &mut middle)?;
        assert_eq!(&middle[..], &pattern(300_000)[123_456..123_472]);
        // Case-insensitive lookup through a symbolic link to a directory.
        let link = volume.lookup(device, &format!("{GROUP}/current"), false)?;
        assert_eq!(link.kind, FileKind::Symlink);
        let target = volume.symlink_target(device, &link)?;
        assert!(target.starts_with("boot/") && target.len() == 5 + 96);
        let lower = GROUP.to_ascii_lowercase();
        let tree = volume.lookup(
            device,
            &format!("{lower}/CURRENT/usr/standalone/firmware/devicetree.img4"),
            true,
        )?;
        let bytes = volume.read(device, &tree)?;
        assert!(bytes.windows(17).any(|w| w == b"device tree bytes"));
        // A sparse file reads its hole as zeros.
        let sparse = volume.lookup(device, "sparse", true)?;
        let data = volume.read(device, &sparse)?;
        assert_eq!(data.len(), 200_004);
        assert!(data[..200_000].iter().all(|&b| b == 0));
        assert_eq!(&data[200_000..], b"tail");
        let empty = volume.lookup(device, "empty", true)?;
        assert_eq!(
            volume
                .xattr(device, empty.oid, "com.stela.test")?
                .as_deref(),
            Some(&b"hello"[..])
        );
        assert_eq!(volume.xattr(device, empty.oid, "absent")?, None);
        assert!(matches!(
            volume.lookup(device, &format!("{GROUP}/missing"), true),
            Err(ApfsError::NotFound(_))
        ));
        Ok(())
    }

    #[test]
    fn encrypted_volumes_list_but_refuse_their_files() -> Result<()> {
        let mut container = Container::open(fixture(), 0)?;
        let mut volume = container.volume_with_role(APFS_VOL_ROLE_PREBOOT)?;
        volume.encrypted = true;
        assert_eq!(volume.name, "Stela");
        assert_eq!(
            volume.lookup(&mut container.device, "empty", true),
            Err(ApfsError::Encrypted)
        );
        Ok(())
    }

    #[test]
    fn the_root_seal_is_the_hash_apples_sealer_recorded() -> Result<()> {
        // The 208-byte record: version 2, 0, hash type, hash length, hash.
        let record = include_bytes!("../../tests/fixtures/apfs/sealed.root_hash");
        let mut container = Container::open(sealed_fixture(), 0)?;
        let [volume] = &container.volumes()?[..] else {
            panic!("one volume expected");
        };
        assert!(volume.sealed);
        assert_eq!(volume.root_to_xid, 0);
        let seal = volume.root_seal(&mut container.device)?.expect("a seal");
        assert_eq!(u32::from_le_bytes(record[8..12].try_into().unwrap()), 1);
        assert_eq!(seal.hash, Hash::Sha256);
        assert_eq!(seal.root, record[16..48]);
        // Every file system object still reads under the seal's checks.
        let inode = volume.lookup(
            &mut container.device,
            "System/Library/CoreServices/stela.txt",
            false,
        )?;
        assert_eq!(
            volume.read(&mut container.device, &inode)?,
            b"sealed by apfs_prepare_cryptex\n"
        );
        Ok(())
    }
}
