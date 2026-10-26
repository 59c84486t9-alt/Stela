//! An APFS container of one unencrypted, case-insensitive volume holding one
//! file below its directories, written directly so any host can make it.
//!
//! The layout is the one checkpoint `mkapfs` (apfsprogs, GPL-2.0, read for
//! its structure only) writes at transaction 1: the container superblock at
//! block zero, the checkpoint descriptor area (the checkpoint map, then the
//! superblock's copy), the checkpoint data area (reaper, space manager and
//! the two free-queue roots), the container object map, the volume
//! superblock and its object map, file-system, extent-reference and
//! snapshot-metadata roots, the sixteen internal-pool bitmaps and the
//! internal pool (one allocation bitmap per chunk, then the chunk-info
//! block). The file's data follows as one extent, and free space after it
//! leaves room for the checkpoints a read-write mount writes. Field layouts
//! are Apple's File System Reference.
use anyhow::{Result, bail, ensure};
use std::io::Read;
use stela_runtime::apfs::object::fletcher64;

const BLOCK: usize = 4096;
const BLOCKS_PER_CHUNK: u64 = 8 * BLOCK as u64;
/// Chunk-info entries after a chunk-info block's 40-byte header.
const CHUNKS_PER_CIB: u64 = (BLOCK as u64 - 40) / 32;
/// Chunk-info-block addresses after an address block's 40-byte header.
const CIBS_PER_CAB: u32 = (BLOCK as u32 - 40) / 8;
/// Free blocks after the file, for the checkpoints and object-map nodes a
/// read-write mount writes.
const SLACK_BLOCKS: u64 = 8192;
const XID: u64 = 1;

const OBJ_VIRTUAL: u32 = 0;
const OBJ_EPHEMERAL: u32 = 0x8000_0000;
const OBJ_PHYSICAL: u32 = 0x4000_0000;
const TYPE_NX_SUPERBLOCK: u32 = 0x01;
const TYPE_BTREE: u32 = 0x02;
const TYPE_SPACEMAN: u32 = 0x05;
const TYPE_SPACEMAN_CIB: u32 = 0x07;
const TYPE_FREE_QUEUE: u32 = 0x09;
const TYPE_OMAP: u32 = 0x0b;
const TYPE_CHECKPOINT_MAP: u32 = 0x0c;
const TYPE_FS: u32 = 0x0d;
const TYPE_FSTREE: u32 = 0x0e;
const TYPE_BLOCKREFTREE: u32 = 0x0f;
const TYPE_SNAPMETATREE: u32 = 0x10;
const TYPE_NX_REAPER: u32 = 0x11;

/// Ephemeral and virtual object identifiers, after the reserved range.
const SPACEMAN_OID: u64 = 1024;
const REAPER_OID: u64 = SPACEMAN_OID + 1;
const VOLUME_OID: u64 = SPACEMAN_OID + 2;
const FS_ROOT_OID: u64 = SPACEMAN_OID + 3;
const IP_FREE_QUEUE_OID: u64 = SPACEMAN_OID + 4;
const MAIN_FREE_QUEUE_OID: u64 = SPACEMAN_OID + 5;

const BTNODE_ROOT: u16 = 1;
const BTNODE_LEAF: u16 = 2;
const BTNODE_FIXED_KV_SIZE: u16 = 4;
const BTREE_ALLOW_GHOSTS: u32 = 0x04;
const BTREE_EPHEMERAL: u32 = 0x08;
const BTREE_PHYSICAL: u32 = 0x10;
const BTREE_KV_NONALIGNED: u32 = 0x40;
const BTOFF_INVALID: u16 = 0xffff;
const NODE_HEADER_BYTES: usize = 56;
const INFO_BYTES: usize = 40;

/// File-system record types, in a key's top four bits.
const TYPE_EXTENT: u64 = 2;
const TYPE_INODE: u64 = 3;
const TYPE_DSTREAM_ID: u64 = 6;
const TYPE_FILE_EXTENT: u64 = 8;
const TYPE_DIR_REC: u64 = 9;
const ROOT_DIR_PARENT: u64 = 1;
const ROOT_DIR_INO: u64 = 2;
const PRIVATE_DIR_INO: u64 = 3;
const MIN_USER_INO: u64 = 16;
const INODE_NO_RSRC_FORK: u64 = 0x8000;
const INO_EXT_TYPE_NAME: u8 = 4;
const INO_EXT_TYPE_DSTREAM: u8 = 8;
const XF_DO_NOT_COPY: u8 = 0x02;
const XF_SYSTEM_FIELD: u8 = 0x20;
const DT_DIR: u16 = 4;
const DT_REG: u16 = 8;
const MODE_DIR: u16 = 0o040755;
const MODE_FILE: u16 = 0o100644;
const EXTENT_KIND_NEW: u64 = 1;

/// The volume's UUID, the container's and the format time in nanoseconds
/// since 1970.
pub struct Identity {
    pub volume_uuid: [u8; 16],
    pub container_uuid: [u8; 16],
    pub time: u64,
}

/// A container whose volume, `volume_name`, holds the `bytes` read from
/// `file` at `path` (slash-separated, with directories made for its parent
/// components). At most `limit` bytes.
pub fn container(
    volume_name: &str,
    path: &str,
    file: &mut impl Read,
    bytes: u64,
    identity: &Identity,
    limit: u64,
) -> Result<Vec<u8>> {
    ensure!(bytes > 0, "the volume's file is empty");
    ensure!(
        volume_name.len() < 256 && !volume_name.contains('\0'),
        "the volume name must be under 256 bytes"
    );
    let file_blocks = bytes.div_ceil(BLOCK as u64);
    let layout = Layout::new(file_blocks)?;
    let total = layout.blocks * BLOCK as u64;
    ensure!(
        total <= limit,
        "the volume is {total} bytes, more than {limit}"
    );
    let mut image = vec![0u8; usize::try_from(total)?];
    let data = layout.file_start as usize * BLOCK;
    file.read_exact(&mut image[data..data + bytes as usize])?;

    let tree = FileTree::new(path, layout.file_start, bytes, identity.time)?;
    layout.write_container(&mut image, identity);
    layout.write_spaceman(&mut image);
    layout.write_volume(&mut image, volume_name, &tree, identity);
    Ok(image)
}

/// Block numbers and counts of everything the container holds.
struct Layout {
    blocks: u64,
    chunks: u64,
    desc_blocks: u64,
    data_blocks: u64,
    ip_blocks: u64,
    ip_bm_size: u64,
    file_start: u64,
    file_blocks: u64,
}

impl Layout {
    /// The layout for `file_blocks` of data. The checkpoint areas and the
    /// internal pool grow with the container, so the size is iterated to its
    /// fixed point; each step only grows it.
    fn new(file_blocks: u64) -> Result<Self> {
        let mut blocks = file_blocks + SLACK_BLOCKS;
        for _ in 0..64 {
            let chunks = blocks.div_ceil(BLOCKS_PER_CHUNK);
            if chunks > CHUNKS_PER_CIB {
                bail!(
                    "UNSUPPORTED APFS container of {blocks} blocks: more than one chunk-info block"
                );
            }
            let ip_blocks = (chunks + 1) * 3;
            let ip_bm_size = ip_blocks.div_ceil(BLOCKS_PER_CHUNK);
            let layout = Self {
                blocks,
                chunks,
                desc_blocks: checkpoint_desc_blocks(blocks),
                data_blocks: checkpoint_data_blocks(blocks),
                ip_blocks,
                ip_bm_size,
                file_start: 0,
                file_blocks,
            };
            let file_start = layout.ip_base() + ip_blocks;
            let needed = file_start + file_blocks + SLACK_BLOCKS;
            if needed == blocks {
                return Ok(Self {
                    file_start,
                    ..layout
                });
            }
            blocks = needed;
        }
        bail!("the APFS layout for {file_blocks} blocks does not settle")
    }

    fn data_base(&self) -> u64 {
        1 + self.desc_blocks
    }
    fn reaper(&self) -> u64 {
        self.data_base()
    }
    fn spaceman(&self) -> u64 {
        self.data_base() + 1
    }
    fn ip_free_queue(&self) -> u64 {
        self.data_base() + 2
    }
    fn main_free_queue(&self) -> u64 {
        self.data_base() + 3
    }
    /// The checkpoint data area's used blocks: reaper, space manager and
    /// the two free-queue roots.
    const EPHEMERAL_BLOCKS: u32 = 4;
    fn data_end(&self) -> u64 {
        self.data_base() + self.data_blocks
    }
    fn container_omap(&self) -> u64 {
        self.data_end()
    }
    fn volume(&self) -> u64 {
        self.data_end() + 2
    }
    fn volume_omap(&self) -> u64 {
        self.data_end() + 3
    }
    fn fs_root(&self) -> u64 {
        self.data_end() + 5
    }
    fn extentref_root(&self) -> u64 {
        self.data_end() + 6
    }
    fn snap_meta_root(&self) -> u64 {
        self.data_end() + 7
    }
    fn ip_bm_base(&self) -> u64 {
        self.data_end() + 8
    }
    fn ip_bm_blocks(&self) -> u64 {
        16 * self.ip_bm_size
    }
    fn ip_base(&self) -> u64 {
        self.ip_bm_base() + self.ip_bm_blocks()
    }
    /// The chunks' allocation bitmaps open the internal pool, then the
    /// chunk-info block.
    fn chunk_bitmap(&self, chunk: u64) -> u64 {
        self.ip_base() + chunk
    }
    fn cib(&self) -> u64 {
        self.ip_base() + self.chunks
    }
    /// Every block before the file's end is used: the metadata is packed
    /// from block zero and the file follows the internal pool.
    fn used_end(&self) -> u64 {
        self.file_start + self.file_blocks
    }

    fn write_container(&self, image: &mut [u8], identity: &Identity) {
        let mut sb = [0u8; BLOCK];
        put32(&mut sb, 0x20, 0x4253_584e); // NXSB
        put32(&mut sb, 0x24, BLOCK as u32);
        put64(&mut sb, 0x28, self.blocks);
        put64(&mut sb, 0x40, 2); // NX_INCOMPAT_VERSION2
        sb[0x48..0x58].copy_from_slice(&identity.container_uuid);
        put64(&mut sb, 0x58, SPACEMAN_OID + 100);
        put64(&mut sb, 0x60, XID + 1);
        put32(&mut sb, 0x68, self.desc_blocks as u32);
        put32(&mut sb, 0x6c, self.data_blocks as u32);
        put64(&mut sb, 0x70, 1);
        put64(&mut sb, 0x78, self.data_base());
        // The descriptor area holds the map and the superblock's copy.
        put32(&mut sb, 0x80, 2);
        put32(&mut sb, 0x84, Self::EPHEMERAL_BLOCKS);
        put32(&mut sb, 0x8c, 2);
        put32(&mut sb, 0x94, Self::EPHEMERAL_BLOCKS);
        put64(&mut sb, 0x98, SPACEMAN_OID);
        put64(&mut sb, 0xa0, self.container_omap());
        put64(&mut sb, 0xa8, REAPER_OID);
        let bytes = self.blocks * BLOCK as u64;
        put32(
            &mut sb,
            0xb4,
            bytes.div_ceil(512 << 20).clamp(1, 100) as u32,
        );
        put64(&mut sb, 0xb8, VOLUME_OID);
        let min_block_count = if bytes < 128 << 20 {
            u64::from(main_fq_node_limit(self.blocks))
        } else {
            8
        };
        put64(&mut sb, 0x520, (min_block_count << 32) | (4 << 16) | 1);
        seal(&mut sb, 1, OBJ_EPHEMERAL | TYPE_NX_SUPERBLOCK, 0);
        block(image, 0).copy_from_slice(&sb);
        block(image, 2).copy_from_slice(&sb);

        let map = block(image, 1);
        put32(map, 0x20, 1); // CHECKPOINT_MAP_LAST
        put32(map, 0x24, Self::EPHEMERAL_BLOCKS);
        let mappings = [
            (OBJ_EPHEMERAL | TYPE_NX_REAPER, 0, REAPER_OID, self.reaper()),
            (
                OBJ_EPHEMERAL | TYPE_SPACEMAN,
                0,
                SPACEMAN_OID,
                self.spaceman(),
            ),
            (
                OBJ_EPHEMERAL | TYPE_BTREE,
                TYPE_FREE_QUEUE,
                IP_FREE_QUEUE_OID,
                self.ip_free_queue(),
            ),
            (
                OBJ_EPHEMERAL | TYPE_BTREE,
                TYPE_FREE_QUEUE,
                MAIN_FREE_QUEUE_OID,
                self.main_free_queue(),
            ),
        ];
        for (index, (kind, subtype, oid, paddr)) in mappings.into_iter().enumerate() {
            let at = 0x28 + 40 * index;
            put32(map, at, kind);
            put32(map, at + 4, subtype);
            put32(map, at + 8, BLOCK as u32);
            put64(map, at + 24, oid);
            put64(map, at + 32, paddr);
        }
        seal(map, 1, OBJ_PHYSICAL | TYPE_CHECKPOINT_MAP, 0);

        let reaper = block(image, self.reaper());
        put64(reaper, 0x20, 1); // next reap id
        put32(reaper, 0x40, 1); // NR_BHM_FLAG
        put32(reaper, 0x6c, BLOCK as u32 - 0x70);
        seal(reaper, REAPER_OID, OBJ_EPHEMERAL | TYPE_NX_REAPER, 0);

        let free_queue = |oid| {
            let mut node = root_node(
                &[],
                Toc::Fixed { key: 16, value: 8 },
                BTREE_EPHEMERAL | BTREE_ALLOW_GHOSTS,
            );
            seal(&mut node, oid, OBJ_EPHEMERAL | TYPE_BTREE, TYPE_FREE_QUEUE);
            node
        };
        block(image, self.ip_free_queue()).copy_from_slice(&free_queue(IP_FREE_QUEUE_OID));
        block(image, self.main_free_queue()).copy_from_slice(&free_queue(MAIN_FREE_QUEUE_OID));

        write_omap(
            image,
            self.container_omap(),
            true,
            VOLUME_OID,
            self.volume(),
        );
    }

    fn write_spaceman(&self, image: &mut [u8]) {
        // Chunk allocation bitmaps and the chunk-info block.
        let mut chunk_infos = Vec::new();
        for chunk in 0..self.chunks {
            let first = chunk * BLOCKS_PER_CHUNK;
            let count = BLOCKS_PER_CHUNK.min(self.blocks - first);
            let used = self.used_end().clamp(first, first + count) - first;
            mark_used(block(image, self.chunk_bitmap(chunk)), 0, used);
            chunk_infos.push((first, count, count - used));
        }
        let cib = block(image, self.cib());
        put32(cib, 0x24, self.chunks as u32);
        for (index, (first, count, free)) in chunk_infos.into_iter().enumerate() {
            let at = 40 + 32 * index;
            put64(cib, at, XID);
            put64(cib, at + 8, first);
            put32(cib, at + 16, count as u32);
            put32(cib, at + 20, free as u32);
            put64(cib, at + 24, self.chunk_bitmap(index as u64));
        }
        let cib_oid = self.cib();
        seal(cib, cib_oid, OBJ_PHYSICAL | TYPE_SPACEMAN_CIB, 0);

        // The internal pool's current bitmap marks the chunk bitmaps and
        // the chunk-info block; the other fifteen are free.
        mark_used(block(image, self.ip_bm_base()), 0, self.chunks + 1);

        // `mkapfs`'s unversioned space manager: the bitmaps' transaction
        // identifiers, their ring offsets, the free list, then the
        // chunk-info block's address.
        const BITMAP_XID_OFFSET: usize = 0x150;
        let ip_bm_size = self.ip_bm_size as usize;
        let ip_bm_blocks = self.ip_bm_blocks() as usize;
        let bitmap_offset = BITMAP_XID_OFFSET + 8 * ip_bm_size;
        let free_next_offset = bitmap_offset + (2 * ip_bm_size).next_multiple_of(8);
        let cib_address_offset = free_next_offset + 2 * ip_bm_blocks;
        assert!(cib_address_offset + 16 <= BLOCK);

        let sm = block(image, self.spaceman());
        put32(sm, 0x20, BLOCK as u32);
        put32(sm, 0x24, BLOCKS_PER_CHUNK as u32);
        put32(sm, 0x28, CHUNKS_PER_CIB as u32);
        put32(sm, 0x2c, CIBS_PER_CAB);
        put64(sm, 0x30, self.blocks);
        put64(sm, 0x38, self.chunks);
        put32(sm, 0x40, 1); // chunk-info blocks
        put64(sm, 0x48, self.blocks - self.used_end());
        put32(sm, 0x50, cib_address_offset as u32);
        put32(sm, 0x80, cib_address_offset as u32 + 8); // tier 2, empty
        put32(sm, 0x94, 16); // SPACEMAN_IP_BM_TX_MULTIPLIER
        put64(sm, 0x98, self.ip_blocks);
        put32(sm, 0xa0, ip_bm_size as u32);
        put32(sm, 0xa4, ip_bm_blocks as u32);
        put64(sm, 0xa8, self.ip_bm_base());
        put64(sm, 0xb0, self.ip_base());
        put64(sm, 0xc8 + 8, IP_FREE_QUEUE_OID);
        put16(sm, 0xc8 + 24, ip_fq_node_limit(self.chunks));
        put64(sm, 0xf0 + 8, MAIN_FREE_QUEUE_OID);
        put16(sm, 0xf0 + 24, main_fq_node_limit(self.blocks));
        put16(sm, 0x140, ip_bm_size as u16);
        put16(sm, 0x142, ip_bm_blocks as u16 - 1);
        put32(sm, 0x144, BITMAP_XID_OFFSET as u32);
        put32(sm, 0x148, bitmap_offset as u32);
        put32(sm, 0x14c, free_next_offset as u32);
        for index in 0..ip_bm_size {
            put64(sm, BITMAP_XID_OFFSET + 8 * index, XID);
            put16(sm, bitmap_offset + 2 * index, index as u16);
        }
        // Free bitmap blocks link to the next; the in-use ones and the tail
        // hold the invalid index.
        for index in 0..ip_bm_blocks {
            let next = if index < ip_bm_size || index + 1 == ip_bm_blocks {
                0xffff
            } else {
                index as u16 + 1
            };
            put16(sm, free_next_offset + 2 * index, next);
        }
        put64(sm, cib_address_offset, self.cib());
        seal(sm, SPACEMAN_OID, OBJ_EPHEMERAL | TYPE_SPACEMAN, 0);
    }

    fn write_volume(&self, image: &mut [u8], name: &str, tree: &FileTree, identity: &Identity) {
        write_omap(
            image,
            self.volume_omap(),
            false,
            FS_ROOT_OID,
            self.fs_root(),
        );

        let mut fs_root = root_node(&tree.records, Toc::Variable, BTREE_KV_NONALIGNED);
        seal(
            &mut fs_root,
            FS_ROOT_OID,
            OBJ_VIRTUAL | TYPE_BTREE,
            TYPE_FSTREE,
        );
        block(image, self.fs_root()).copy_from_slice(&fs_root);

        // The one physical extent, owned by the file's data stream.
        let mut key = Vec::new();
        key.extend((TYPE_EXTENT << 60 | self.file_start).to_le_bytes());
        let mut value = Vec::new();
        value.extend((EXTENT_KIND_NEW << 60 | self.file_blocks).to_le_bytes());
        value.extend(tree.file_ino.to_le_bytes());
        value.extend(1u32.to_le_bytes());
        let flags = BTREE_PHYSICAL | BTREE_KV_NONALIGNED;
        let mut extentref = root_node(&[(key, value)], Toc::Variable, flags);
        let oid = self.extentref_root();
        seal(
            &mut extentref,
            oid,
            OBJ_PHYSICAL | TYPE_BTREE,
            TYPE_BLOCKREFTREE,
        );
        block(image, oid).copy_from_slice(&extentref);

        let mut snap_meta = root_node(&[], Toc::Variable, flags);
        let oid = self.snap_meta_root();
        seal(
            &mut snap_meta,
            oid,
            OBJ_PHYSICAL | TYPE_BTREE,
            TYPE_SNAPMETATREE,
        );
        block(image, oid).copy_from_slice(&snap_meta);

        let vsb = block(image, self.volume());
        put32(vsb, 0x20, 0x4253_5041); // APSB
        put64(vsb, 0x28, 2); // FEATURE_HARDLINK_MAP_RECORDS
        put64(vsb, 0x38, 1); // INCOMPAT_CASE_INSENSITIVE
        // The volume's object map and its four tree roots, then the data.
        put64(vsb, 0x58, 5 + self.file_blocks);
        // Wrapped meta-crypto state: version 5.0, protection class F,
        // key revision 1, as an unencrypted volume records it.
        put16(vsb, 0x60, 5);
        put32(vsb, 0x68, 6);
        put16(vsb, 0x70, 1);
        put32(vsb, 0x74, OBJ_VIRTUAL | TYPE_BTREE);
        put32(vsb, 0x78, OBJ_PHYSICAL | TYPE_BTREE);
        put32(vsb, 0x7c, OBJ_PHYSICAL | TYPE_BTREE);
        put64(vsb, 0x80, self.volume_omap());
        put64(vsb, 0x88, FS_ROOT_OID);
        put64(vsb, 0x90, self.extentref_root());
        put64(vsb, 0x98, self.snap_meta_root());
        put64(vsb, 0xb0, tree.next_ino);
        put64(vsb, 0xb8, 1);
        put64(vsb, 0xc0, tree.directories);
        put64(vsb, 0xe0, self.file_blocks);
        vsb[0xf0..0x100].copy_from_slice(&identity.volume_uuid);
        put64(vsb, 0x100, identity.time);
        put64(vsb, 0x108, 1); // FS_UNENCRYPTED
        let formatter = concat!("stela ", env!("CARGO_PKG_VERSION"));
        vsb[0x110..0x110 + formatter.len()].copy_from_slice(formatter.as_bytes());
        put64(vsb, 0x130, identity.time);
        put64(vsb, 0x138, XID);
        vsb[0x2c0..0x2c0 + name.len()].copy_from_slice(name.as_bytes());
        put32(vsb, 0x3c0, 3); // MIN_DOC_ID
        seal(vsb, VOLUME_OID, OBJ_VIRTUAL | TYPE_FS, 0);
    }
}

/// `mkapfs`'s checkpoint descriptor area size, after `newfs_apfs`'s.
fn checkpoint_desc_blocks(blocks: u64) -> u64 {
    match blocks {
        ..131_072 => 8,
        131_072..262_144 => 12,
        262_144..13_107_200 => 20 + 60 * ((blocks - 262_144) / 131_072) / 23,
        _ => 280,
    }
}

/// `mkapfs`'s checkpoint data area size, after `newfs_apfs`'s.
fn checkpoint_data_blocks(blocks: u64) -> u64 {
    let b = blocks as i64;
    let data = match b {
        ..4545 => 52,
        4545..13_633 => 124,
        13_633..36_353 => 160 + 36 * ((b - 13_633) / 4544),
        36_353..131_777 => 308 + 4 * ((b - 36_353) / 4544),
        131_777..262_144 => 648 + 4 * ((b - 131_777) / 4544),
        262_144 => 992,
        262_145..1_048_576 => {
            let off = (b - 262_144) / 131_072;
            1248 + 488 * off + 4 * ((b - (261_280 + off * 131_776)) / 2272)
        }
        1_048_576..4_063_232 => 4112 + 256 * ((b - 1_048_576) / 131_072),
        4_063_232..13_107_200 => 10_000 + 256 * ((b - 4_063_232) / 131_072),
        _ => 27_672,
    };
    data as u64
}

fn ip_fq_node_limit(chunks: u64) -> u16 {
    match (3 * (chunks + 751) / 1127 - 1) as u16 {
        2 => 3,
        limit => limit,
    }
}

fn main_fq_node_limit(blocks: u64) -> u16 {
    let limit = match blocks {
        ..0x4_0000 => 1 + (blocks - 1) / 4544,
        0x4_0000..0x10_0000 => 116 + (blocks - 261_281) / 2272,
        _ => 512,
    };
    match limit as u16 {
        2 => 3,
        limit => limit,
    }
}

/// An object map at `paddr` whose root, the next block, maps `oid` at
/// transaction 1 to `target`.
fn write_omap(image: &mut [u8], paddr: u64, manually_managed: bool, oid: u64, target: u64) {
    let omap = block(image, paddr);
    put32(omap, 0x20, u32::from(manually_managed));
    put32(omap, 0x28, OBJ_PHYSICAL | TYPE_BTREE);
    put32(omap, 0x2c, OBJ_PHYSICAL | TYPE_BTREE);
    put64(omap, 0x30, paddr + 1);
    seal(omap, paddr, OBJ_PHYSICAL | TYPE_OMAP, 0);

    let key = [oid.to_le_bytes(), XID.to_le_bytes()].concat();
    let value = [0u32.to_le_bytes(), (BLOCK as u32).to_le_bytes()]
        .concat()
        .into_iter()
        .chain(target.to_le_bytes())
        .collect();
    let mut root = root_node(
        &[(key, value)],
        Toc::Fixed { key: 16, value: 16 },
        BTREE_PHYSICAL,
    );
    seal(&mut root, paddr + 1, OBJ_PHYSICAL | TYPE_BTREE, TYPE_OMAP);
    block(image, paddr + 1).copy_from_slice(&root);
}

enum Toc {
    Fixed { key: usize, value: usize },
    Variable,
}

/// A root leaf of sorted `records` with its info footer; the caller seals
/// it. A fixed-size tree's table is preallocated for a full node, as
/// `newfs_apfs` does; a variable one has room for sixteen entries or more.
fn root_node(records: &[(Vec<u8>, Vec<u8>)], toc: Toc, tree_flags: u32) -> [u8; BLOCK] {
    let mut node = [0u8; BLOCK];
    let (toc_len, entry, fixed) = match toc {
        Toc::Fixed { key, value } => {
            let count = (BLOCK - NODE_HEADER_BYTES) / (key + value + 4);
            (count * 4, 4, Some((key, value)))
        }
        Toc::Variable => (records.len().max(16).next_multiple_of(8) * 8, 8, None),
    };
    assert!(records.len() * entry <= toc_len);
    let key_area = NODE_HEADER_BYTES + toc_len;
    let value_end = BLOCK - INFO_BYTES;
    let (mut key_at, mut value_at) = (0, 0);
    for (index, (key, value)) in records.iter().enumerate() {
        node[key_area + key_at..][..key.len()].copy_from_slice(key);
        value_at += value.len();
        node[value_end - value_at..][..value.len()].copy_from_slice(value);
        let toc_at = NODE_HEADER_BYTES + entry * index;
        if fixed.is_some() {
            put16(&mut node, toc_at, key_at as u16);
            put16(&mut node, toc_at + 2, value_at as u16);
        } else {
            put16(&mut node, toc_at, key_at as u16);
            put16(&mut node, toc_at + 2, key.len() as u16);
            put16(&mut node, toc_at + 4, value_at as u16);
            put16(&mut node, toc_at + 6, value.len() as u16);
        }
        key_at += key.len();
    }
    let free = BLOCK - key_area - key_at - value_at - INFO_BYTES;
    assert!(key_area + key_at <= value_end - value_at);
    let mut flags = BTNODE_ROOT | BTNODE_LEAF;
    if fixed.is_some() {
        flags |= BTNODE_FIXED_KV_SIZE;
    }
    put16(&mut node, 0x20, flags);
    put32(&mut node, 0x24, records.len() as u32);
    put16(&mut node, 0x2a, toc_len as u16);
    put16(&mut node, 0x2c, key_at as u16);
    put16(&mut node, 0x2e, free as u16);
    put16(&mut node, 0x30, BTOFF_INVALID);
    put16(&mut node, 0x34, BTOFF_INVALID);

    let (key_size, value_size) = fixed.unwrap_or((0, 0));
    let longest = |pick: fn(&(Vec<u8>, Vec<u8>)) -> usize, size| {
        records.iter().map(pick).max().unwrap_or(0).max(size)
    };
    let info = BLOCK - INFO_BYTES;
    put32(&mut node, info, tree_flags);
    put32(&mut node, info + 4, BLOCK as u32);
    put32(&mut node, info + 8, key_size as u32);
    put32(&mut node, info + 12, value_size as u32);
    put32(
        &mut node,
        info + 16,
        longest(|r| r.0.len(), key_size) as u32,
    );
    put32(
        &mut node,
        info + 20,
        longest(|r| r.1.len(), value_size) as u32,
    );
    put64(&mut node, info + 24, records.len() as u64);
    put64(&mut node, info + 32, 1);
    node
}

/// The file-system tree's records, sorted as APFS compares their keys.
struct FileTree {
    records: Vec<(Vec<u8>, Vec<u8>)>,
    file_ino: u64,
    next_ino: u64,
    directories: u64,
}

impl FileTree {
    fn new(path: &str, file_start: u64, bytes: u64, time: u64) -> Result<Self> {
        let names: Vec<&str> = path.split('/').collect();
        ensure!(
            names
                .iter()
                .all(|name| !name.is_empty() && name.len() < 256 && name.is_ascii()),
            "UNSUPPORTED volume path {path:?}: components must be non-empty ASCII names"
        );
        // Records under their order: identifier, type, then a directory
        // entry's name hash and name.
        type Order = (u64, u64, u32, Vec<u8>);
        let mut records: Vec<(Order, Vec<u8>, Vec<u8>)> = Vec::new();
        let mut entry = |parent: u64, name: &str, ino: u64, kind: u16| {
            let (key, hash) = directory_key(parent, name);
            let value = [
                &ino.to_le_bytes()[..],
                &time.to_le_bytes(),
                &kind.to_le_bytes(),
            ]
            .concat();
            let sort = (parent, TYPE_DIR_REC, hash, name.as_bytes().to_vec());
            records.push((sort, key, value));
        };
        entry(ROOT_DIR_PARENT, "root", ROOT_DIR_INO, DT_DIR);
        entry(ROOT_DIR_PARENT, "private-dir", PRIVATE_DIR_INO, DT_DIR);
        let (directories, file) = names.split_at(names.len() - 1);
        let mut parent = ROOT_DIR_INO;
        let mut inodes = vec![(ROOT_DIR_INO, ROOT_DIR_PARENT, "root", 1)];
        for (index, name) in directories.iter().enumerate() {
            let ino = MIN_USER_INO + index as u64;
            entry(parent, name, ino, DT_DIR);
            inodes.push((ino, parent, *name, 1));
            parent = ino;
        }
        let file_ino = MIN_USER_INO + directories.len() as u64;
        entry(parent, file[0], file_ino, DT_REG);
        inodes.push((PRIVATE_DIR_INO, ROOT_DIR_PARENT, "private-dir", 0));

        let inode_key = |ino: u64| (TYPE_INODE << 60 | ino).to_le_bytes().to_vec();
        for (ino, parent, name, children) in inodes {
            let value = inode_value(parent, ino, name, MODE_DIR, children, time, None);
            records.push(((ino, TYPE_INODE, 0, vec![]), inode_key(ino), value));
        }
        let allocated = bytes.next_multiple_of(BLOCK as u64);
        let value = inode_value(parent, file_ino, file[0], MODE_FILE, 1, time, Some(bytes));
        records.push((
            (file_ino, TYPE_INODE, 0, vec![]),
            inode_key(file_ino),
            value,
        ));
        records.push((
            (file_ino, TYPE_DSTREAM_ID, 0, vec![]),
            (TYPE_DSTREAM_ID << 60 | file_ino).to_le_bytes().to_vec(),
            1u32.to_le_bytes().to_vec(),
        ));
        let extent_key = [
            (TYPE_FILE_EXTENT << 60 | file_ino).to_le_bytes(),
            0u64.to_le_bytes(),
        ]
        .concat();
        let extent_value = [allocated.to_le_bytes(), file_start.to_le_bytes(), [0; 8]].concat();
        records.push((
            (file_ino, TYPE_FILE_EXTENT, 0, vec![]),
            extent_key,
            extent_value,
        ));
        records.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(Self {
            records: records.into_iter().map(|(_, k, v)| (k, v)).collect(),
            file_ino,
            next_ino: file_ino + 1,
            directories: directories.len() as u64,
        })
    }
}

/// A hashed directory-entry key, `j_drec_hashed_key_t`, and its hash. A
/// case-insensitive volume hashes the case-folded name's UTF-32 code points
/// with CRC-32C, from all ones and without the final inversion; the key
/// keeps 22 bits of it above the name's length with its terminator.
fn directory_key(parent: u64, name: &str) -> (Vec<u8>, u32) {
    let folded = name.to_ascii_lowercase();
    let code_points: Vec<u8> = folded
        .chars()
        .flat_map(|c| (c as u32).to_le_bytes())
        .collect();
    let hash = crc32c_update(!0, &code_points) & 0x3f_ffff;
    let length = name.len() as u32 + 1;
    let mut key = (TYPE_DIR_REC << 60 | parent).to_le_bytes().to_vec();
    key.extend((hash << 10 | length).to_le_bytes());
    key.extend(name.as_bytes());
    key.push(0);
    (key, hash)
}

fn crc32c_update(mut state: u32, data: &[u8]) -> u32 {
    for &byte in data {
        state ^= u32::from(byte);
        for _ in 0..8 {
            state = (state >> 1) ^ (0x82f6_3b78 & (state & 1).wrapping_neg());
        }
    }
    state
}

/// `j_inode_val_t` with its name and, for a file of `size` bytes, its data
/// stream in extended fields.
fn inode_value(
    parent: u64,
    ino: u64,
    name: &str,
    mode: u16,
    links: u32,
    time: u64,
    size: Option<u64>,
) -> Vec<u8> {
    let mut value = Vec::new();
    value.extend(parent.to_le_bytes());
    value.extend(ino.to_le_bytes()); // private id: the data stream's
    for _ in 0..4 {
        value.extend(time.to_le_bytes());
    }
    value.extend(INODE_NO_RSRC_FORK.to_le_bytes());
    value.extend(links.to_le_bytes()); // children or links
    value.extend([0u8; 4 * 5]); // protection class, write generation, BSD flags, owner, group
    value.extend(mode.to_le_bytes());
    value.extend([0u8; 2 + 8]); // pad, uncompressed size
    let mut fields = vec![(INO_EXT_TYPE_NAME, XF_DO_NOT_COPY, {
        let mut bytes = name.as_bytes().to_vec();
        bytes.push(0);
        bytes
    })];
    if let Some(size) = size {
        let allocated = size.next_multiple_of(BLOCK as u64);
        let stream = [size, allocated, 0, size, 0]
            .iter()
            .flat_map(|field| field.to_le_bytes())
            .collect();
        fields.push((INO_EXT_TYPE_DSTREAM, XF_SYSTEM_FIELD, stream));
    }
    let used: usize = fields.iter().map(|f| f.2.len().next_multiple_of(8)).sum();
    value.extend((fields.len() as u16).to_le_bytes());
    value.extend((used as u16).to_le_bytes());
    for (kind, flags, data) in &fields {
        value.extend([*kind, *flags]);
        value.extend((data.len() as u16).to_le_bytes());
    }
    // Each field's data is padded to eight bytes of its own length.
    for (_, _, data) in &fields {
        value.extend(data);
        value.extend(vec![0; data.len().next_multiple_of(8) - data.len()]);
    }
    value
}

fn block(image: &mut [u8], number: u64) -> &mut [u8] {
    let start = number as usize * BLOCK;
    &mut image[start..start + BLOCK]
}

fn mark_used(bitmap: &mut [u8], first: u64, count: u64) {
    for bit in first..first + count {
        bitmap[(bit / 8) as usize] |= 1 << (bit % 8);
    }
}

/// Set an object's header at transaction 1 and its checksum, last.
fn seal(object: &mut [u8], oid: u64, kind: u32, subtype: u32) {
    put64(object, 8, oid);
    put64(object, 16, XID);
    put32(object, 24, kind);
    put32(object, 28, subtype);
    let checksum = fletcher64(object);
    put64(object, 0, checksum);
}

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_keys_hash_the_case_folded_name_as_apple_does() {
        // The key `hdiutil` wrote for the image in the recovery-volume
        // fixture (parent 0x12).
        let (key, _) = directory_key(0x12, "arm64eBaseSystem.dmg");
        let expected = "1200000000000090157ceb0761726d3634654261736553797374656d2e646d6700";
        assert_eq!(hex::encode(key), expected);
        let (key, _) = directory_key(1, "private-dir");
        assert_eq!(&key[8..12], &0xaca6_8c0cu32.to_le_bytes());
    }

    #[test]
    fn the_layout_settles_with_the_file_after_the_internal_pool() {
        for file_blocks in [1, 4096, 300_000, 700_000] {
            let layout = Layout::new(file_blocks).unwrap();
            assert_eq!(
                layout.blocks,
                layout.file_start + file_blocks + SLACK_BLOCKS
            );
            assert_eq!(
                layout.file_start,
                layout.cib() + 1 + 2 * (layout.chunks + 1)
            );
            assert!(layout.chunks <= CHUNKS_PER_CIB);
        }
        assert!(Layout::new(126 * BLOCKS_PER_CHUNK).is_err());
    }
}
