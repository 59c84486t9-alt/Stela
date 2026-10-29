//! APFS B-trees and object maps (Apple File System Reference, "B-Trees",
//! "Object Maps" and "Sealed Volumes").
//!
//! A node is `btree_node_phys_t`: a table of contents of `kvloc_t` (or
//! `kvoff_t` for fixed-size entries), keys counted from the start of the key
//! area after the table, values counted back from the end of the value area,
//! which ends before the `btree_info_t` of a root node. Nonleaf values are
//! child object identifiers; in hashed trees they are `btn_index_node_val_t`,
//! whose first field is the identifier and whose hash every child must match.
//! Header-less nodes (`BTREE_NOHEADER`) carry a zero `btn_o` and no checksum;
//! sealed volumes protect them by those hashes instead.
use super::{
    ApfsError, Device, Result,
    object::{self, Header, OBJECT_TYPE_BTREE, OBJECT_TYPE_BTREE_NODE, OBJECT_TYPE_OMAP, Storage},
    u16_at, u32_at, u64_at,
};
use crate::payload::ReadAt;
use alloc::vec::Vec;
use core::cmp::Ordering;
use sha2::{Digest, Sha384, Sha512, Sha512_256};
use stela_crypto::Sha256;

pub const BTNODE_ROOT: u16 = 0x0001;
pub const BTNODE_LEAF: u16 = 0x0002;
pub const BTNODE_FIXED_KV_SIZE: u16 = 0x0004;
pub const BTNODE_NOHEADER: u16 = 0x0010;
pub const BTREE_PHYSICAL: u32 = 0x0000_0010;
pub const BTREE_EPHEMERAL: u32 = 0x0000_0008;
pub const BTREE_HASHED: u32 = 0x0000_0080;
pub const BTREE_NOHEADER: u32 = 0x0000_0100;
const BTREE_INFO_BYTES: usize = 40;
const NODE_HEADER_BYTES: usize = 56;
const OID_BYTES: usize = 8;
/// Deeper trees are refused rather than recursed into.
const MAX_DEPTH: usize = 16;

pub const OMAP_VAL_DELETED: u32 = 0x0000_0001;
pub const OMAP_VAL_ENCRYPTED: u32 = 0x0000_0004;
pub const OMAP_VAL_NOHEADER: u32 = 0x0000_0008;

/// `apfs_hash_type_t`: how a sealed volume hashes its B-tree nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha256,
    Sha512_256,
    Sha384,
    Sha512,
}

impl Hash {
    pub fn from_type(value: u32) -> Result<Self> {
        Ok(match value {
            1 => Self::Sha256,
            2 => Self::Sha512_256,
            3 => Self::Sha384,
            4 => Self::Sha512,
            _ => return Err(ApfsError::Unsupported("an unknown seal hash type")),
        })
    }

    pub fn size(self) -> usize {
        match self {
            Self::Sha256 | Self::Sha512_256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha512_256 => Sha512_256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// The seal of a volume's hashed trees: the hash type and the expected hash
/// of the file-system tree's root node (`integrity_meta_phys_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seal {
    pub hash: Hash,
    pub root: Vec<u8>,
}

/// Where a virtual object lives (`omap_val_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    pub paddr: u64,
    /// `OMAP_VAL_NOHEADER`: stored without an `obj_phys_t`.
    pub headerless: bool,
}

/// `btree_info_fixed_t` and counts, from the tail of a root node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Info {
    pub flags: u32,
    pub node_size: u32,
    pub key_size: u32,
    pub val_size: u32,
    pub key_count: u64,
    pub node_count: u64,
}

/// Orders a key against the visit's target.
pub type Compare<'a> = dyn Fn(&[u8]) -> Result<Ordering> + 'a;
/// Receives each visited key and value.
pub type Callback<'a> = dyn FnMut(&[u8], &[u8]) -> Result<Visit> + 'a;

/// What [`Tree::visit`]'s callback asks for next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visit {
    Continue,
    Stop,
}

/// A block holding a B-tree node: a checksummed object, or a header-less
/// node whose `btn_o` must be zero.
fn read_node<R: ReadAt>(device: &mut Device<R>, paddr: u64, headerless: bool) -> Result<Vec<u8>> {
    if headerless {
        let block = device.read_block(paddr)?;
        if block[..object::HEADER_BYTES].iter().any(|&b| b != 0) {
            return Err(ApfsError::Malformed("a header-less node has a header"));
        }
        Ok(block)
    } else {
        device.read_object(paddr)
    }
}

pub struct Node {
    block: Vec<u8>,
    pub flags: u16,
    pub level: u16,
    pub keys: usize,
    toc: usize,
    key_area: usize,
    value_end: usize,
    fixed: bool,
}

impl Node {
    fn parse(block: Vec<u8>, headerless: bool) -> Result<Self> {
        let flags = u16_at(&block, 32)?;
        if headerless {
            if flags & BTNODE_NOHEADER == 0 {
                return Err(ApfsError::Malformed(
                    "a header-less node lacks BTNODE_NOHEADER",
                ));
            }
        } else {
            let header = Header::parse(&block)?;
            if !matches!(
                header.object_type(),
                OBJECT_TYPE_BTREE | OBJECT_TYPE_BTREE_NODE
            ) {
                return Err(ApfsError::Malformed("expected a B-tree node"));
            }
            if header.encrypted() {
                return Err(ApfsError::Encrypted);
            }
        }
        let level = u16_at(&block, 34)?;
        let keys = u32_at(&block, 36)? as usize;
        let table_offset = u16_at(&block, 40)? as usize;
        let table_length = u16_at(&block, 42)? as usize;
        let toc = NODE_HEADER_BYTES + table_offset;
        let key_area = toc + table_length;
        let value_end = if flags & BTNODE_ROOT != 0 {
            block.len().checked_sub(BTREE_INFO_BYTES)
        } else {
            Some(block.len())
        }
        .ok_or(ApfsError::Malformed("B-tree node is too small"))?;
        let fixed = flags & BTNODE_FIXED_KV_SIZE != 0;
        let entry = if fixed { 4 } else { 8 };
        if key_area > value_end || keys.saturating_mul(entry) > table_length {
            return Err(ApfsError::Malformed("B-tree table of contents overflows"));
        }
        Ok(Self {
            block,
            flags,
            level,
            keys,
            toc,
            key_area,
            value_end,
            fixed,
        })
    }

    pub fn is_leaf(&self) -> bool {
        self.flags & BTNODE_LEAF != 0
    }

    fn info(&self) -> Result<Info> {
        if self.flags & BTNODE_ROOT == 0 {
            return Err(ApfsError::Malformed("B-tree info outside a root node"));
        }
        let at = self.block.len() - BTREE_INFO_BYTES;
        Ok(Info {
            flags: u32_at(&self.block, at)?,
            node_size: u32_at(&self.block, at + 4)?,
            key_size: u32_at(&self.block, at + 8)?,
            val_size: u32_at(&self.block, at + 12)?,
            key_count: u64_at(&self.block, at + 24)?,
            node_count: u64_at(&self.block, at + 32)?,
        })
    }

    /// Key and value of entry `index`; `info` gives fixed sizes.
    fn entry(&self, index: usize, info: &Info) -> Result<(&[u8], &[u8])> {
        let range = |start: usize, length: usize| self.block.get(start..start.checked_add(length)?);
        let (key, value) = if self.fixed {
            let at = self.toc + index * 4;
            let key_offset = u16_at(&self.block, at)? as usize;
            let value_offset = u16_at(&self.block, at + 2)? as usize;
            let value_size = if self.is_leaf() {
                info.val_size as usize
            } else {
                OID_BYTES
            };
            let key = range(self.key_area + key_offset, info.key_size as usize);
            let value = self
                .value_end
                .checked_sub(value_offset)
                .and_then(|start| range(start, value_size));
            (key, value)
        } else {
            let at = self.toc + index * 8;
            let key_offset = u16_at(&self.block, at)? as usize;
            let key_length = u16_at(&self.block, at + 2)? as usize;
            let value_offset = u16_at(&self.block, at + 4)? as usize;
            let value_length = u16_at(&self.block, at + 6)? as usize;
            let key = range(self.key_area + key_offset, key_length);
            let value = self
                .value_end
                .checked_sub(value_offset)
                .and_then(|start| range(start, value_length));
            (key, value)
        };
        match (key, value) {
            (Some(key), Some(value)) => Ok((key, value)),
            _ => Err(ApfsError::Malformed("B-tree entry lies outside its node")),
        }
    }
}

/// One B-tree: its root block, its fixed sizes and how its children resolve.
#[derive(Debug, Clone)]
pub struct Tree {
    pub root: u64,
    pub info: Info,
    /// How child identifiers resolve: physical addresses, or through the
    /// object map passed to [`Tree::visit`] at `xid`.
    pub children: Storage,
    pub xid: u64,
    /// Nodes are stored without object headers (`BTREE_NOHEADER`).
    pub headerless: bool,
    /// The hash every child must match (`BTREE_HASHED`).
    pub hash: Option<Hash>,
    /// The root's virtual identifier, when children are stored relative to
    /// it (see [`Tree::relative_to`]).
    pub base_oid: Option<u64>,
}

/// One node and its position while seeking through a B-tree.
struct VisitNode {
    block: Vec<u8>,
    /// Only the first branch compares keys with the requested lower bound.
    first: bool,
    depth: usize,
}

impl Tree {
    /// Open the tree whose root node is at physical address `root`. A
    /// hashed tree needs its `seal`; `seal_root` asks for the root node to
    /// be checked against the seal's root hash (only the file-system tree's
    /// root is named there).
    pub fn open<R: ReadAt>(
        device: &mut Device<R>,
        root: u64,
        xid: u64,
        headerless: bool,
        seal: Option<&Seal>,
        seal_root: bool,
    ) -> Result<Self> {
        let block = read_node(device, root, headerless)?;
        let digest = seal.map(|seal| seal.hash.digest(&block));
        let node = Node::parse(block, headerless)?;
        let info = node.info()?;
        if info.flags & BTREE_EPHEMERAL != 0 {
            return Err(ApfsError::Unsupported("ephemeral B-trees"));
        }
        if info.node_size != device.block_size() {
            return Err(ApfsError::Unsupported("B-tree nodes larger than a block"));
        }
        if (info.flags & BTREE_NOHEADER != 0) != headerless {
            return Err(ApfsError::Malformed(
                "B-tree header storage disagrees with its root",
            ));
        }
        let hash = if info.flags & BTREE_HASHED != 0 {
            let seal = seal.ok_or(ApfsError::Malformed(
                "a hashed B-tree outside a sealed volume",
            ))?;
            if seal_root && digest.as_deref() != Some(seal.root.as_slice()) {
                return Err(ApfsError::Malformed(
                    "the sealed root node fails its root hash",
                ));
            }
            Some(seal.hash)
        } else {
            None
        };
        let children = if info.flags & BTREE_PHYSICAL != 0 {
            Storage::Physical
        } else {
            Storage::Virtual
        };
        Ok(Self {
            root,
            info,
            children,
            xid,
            headerless,
            hash,
            base_oid: None,
        })
    }

    /// Resolve this hashed virtual tree's child identifiers relative to its
    /// root's virtual identifier `root_oid`. The 2020-06-22 reference does
    /// not describe this; it is observed in the 26A434 BaseSystem's sealed
    /// file-system tree, where at every level `root_oid` plus the stored
    /// identifier is the child whose hash the index entry records, and no
    /// object map entry exists for the stored value itself. The child hash
    /// check keeps a wrong resolution from going unnoticed.
    pub fn relative_to(&mut self, root_oid: u64) {
        if self.hash.is_some() && self.children == Storage::Virtual {
            self.base_oid = Some(root_oid);
        }
    }

    /// The block of the child an index entry names, checked against its
    /// hash in a hashed tree.
    fn child<R: ReadAt>(
        &self,
        device: &mut Device<R>,
        omap: Option<&Omap>,
        value: &[u8],
    ) -> Result<Vec<u8>> {
        let stored = u64_at(value, 0)?;
        let oid = match self.base_oid {
            Some(base) => base
                .checked_add(stored)
                .ok_or(ApfsError::Malformed("relative child identifier overflows"))?,
            None => stored,
        };
        let paddr = match self.children {
            Storage::Physical => oid,
            Storage::Virtual => {
                let mapping = omap
                    .ok_or(ApfsError::Malformed("a virtual B-tree needs an object map"))?
                    .lookup(device, oid, self.xid)?;
                if mapping.headerless != self.headerless {
                    return Err(ApfsError::Malformed(
                        "node header storage disagrees with its tree",
                    ));
                }
                mapping.paddr
            }
            Storage::Ephemeral => {
                return Err(ApfsError::Unsupported("ephemeral B-tree children"));
            }
        };
        let block = read_node(device, paddr, self.headerless)?;
        if let Some(hash) = self.hash {
            let expected = value
                .get(OID_BYTES..OID_BYTES + hash.size())
                .ok_or(ApfsError::Malformed("hashed index entry is short"))?;
            if hash.digest(&block) != expected {
                return Err(ApfsError::Malformed("a sealed B-tree node fails its hash"));
            }
        }
        Ok(block)
    }

    /// Visit entries in key order, starting with the first whose key is not
    /// less than the target. `compare(key)` orders a key against the target.
    pub fn visit<R: ReadAt>(
        &self,
        device: &mut Device<R>,
        omap: Option<&Omap>,
        compare: &Compare<'_>,
        callback: &mut Callback<'_>,
    ) -> Result<()> {
        let root = read_node(device, self.root, self.headerless)?;
        self.visit_node(
            device,
            omap,
            VisitNode {
                block: root,
                first: true,
                depth: 0,
            },
            compare,
            callback,
        )
        .map(|_| ())
    }

    fn visit_node<R: ReadAt>(
        &self,
        device: &mut Device<R>,
        omap: Option<&Omap>,
        visit: VisitNode,
        compare: &Compare<'_>,
        callback: &mut Callback<'_>,
    ) -> Result<Visit> {
        let VisitNode {
            block,
            first,
            depth,
        } = visit;
        if depth > MAX_DEPTH {
            return Err(ApfsError::Malformed("B-tree is deeper than 16 levels"));
        }
        let node = Node::parse(block, self.headerless)?;
        if node.is_leaf() {
            for index in 0..node.keys {
                let (key, value) = node.entry(index, &self.info)?;
                if first && compare(key)? == Ordering::Less {
                    continue;
                }
                if callback(key, value)? == Visit::Stop {
                    return Ok(Visit::Stop);
                }
            }
            return Ok(Visit::Continue);
        }
        // Start in the last child whose first key is below the target: an
        // equal key can also end the previous child.
        let mut start = 0;
        if first {
            for index in 0..node.keys {
                let (key, _) = node.entry(index, &self.info)?;
                if compare(key)? == Ordering::Less {
                    start = index;
                } else {
                    break;
                }
            }
        }
        for index in start..node.keys {
            let (_, value) = node.entry(index, &self.info)?;
            let child = self.child(device, omap, value)?;
            let first = first && index == start;
            if self.visit_node(
                device,
                omap,
                VisitNode {
                    block: child,
                    first,
                    depth: depth + 1,
                },
                compare,
                callback,
            )? == Visit::Stop
            {
                return Ok(Visit::Stop);
            }
        }
        Ok(Visit::Continue)
    }
}

/// An object map: `omap_phys_t` and its tree of `omap_key_t` to `omap_val_t`.
#[derive(Debug, Clone)]
pub struct Omap {
    pub tree: Tree,
}

impl Omap {
    pub fn open<R: ReadAt>(device: &mut Device<R>, paddr: u64) -> Result<Self> {
        let block = device.read_object(paddr)?;
        if Header::parse(&block)?.object_type() != OBJECT_TYPE_OMAP {
            return Err(ApfsError::Malformed("expected an object map"));
        }
        let tree_type = u32_at(&block, 40)?;
        if object::Storage::of(tree_type) != Storage::Physical {
            return Err(ApfsError::Malformed("object map trees are physical"));
        }
        let tree_oid = u64_at(&block, 48)?;
        let mut tree = Tree::open(device, tree_oid, u64::MAX, false, None, false)?;
        tree.children = Storage::Physical;
        if tree.info.key_size != 16 || tree.info.val_size != 16 {
            return Err(ApfsError::Malformed("object map entries are 16 bytes"));
        }
        Ok(Self { tree })
    }

    /// Where virtual object `oid` lives as of transaction `xid`: the mapping
    /// with the largest transaction identifier not above `xid`.
    pub fn lookup<R: ReadAt>(&self, device: &mut Device<R>, oid: u64, xid: u64) -> Result<Mapping> {
        let mut found: Option<(u32, u64)> = None;
        let compare = |key: &[u8]| -> Result<Ordering> { Ok(u64_at(key, 0)?.cmp(&oid)) };
        self.tree.visit(device, None, &compare, &mut |key, value| {
            if u64_at(key, 0)? != oid {
                return Ok(Visit::Stop);
            }
            if u64_at(key, 8)? <= xid {
                found = Some((u32_at(value, 0)?, u64_at(value, 8)?));
                Ok(Visit::Continue)
            } else {
                Ok(Visit::Stop)
            }
        })?;
        match found {
            None => Err(ApfsError::NotFound(alloc::format!("object {oid:#x}"))),
            Some((flags, _)) if flags & OMAP_VAL_DELETED != 0 => Err(ApfsError::NotFound(
                alloc::format!("deleted object {oid:#x}"),
            )),
            Some((flags, _)) if flags & OMAP_VAL_ENCRYPTED != 0 => Err(ApfsError::Encrypted),
            Some((flags, paddr)) => Ok(Mapping {
                paddr,
                headerless: flags & OMAP_VAL_NOHEADER != 0,
            }),
        }
    }
}
