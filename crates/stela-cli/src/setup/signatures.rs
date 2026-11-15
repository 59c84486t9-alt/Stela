//! What a partition holds, read from the signatures that file systems,
//! encryption, volume managers, RAID and partition tables write at their
//! documented offsets: near the start of the partition, at copies of their
//! superblocks past it, and near its end.
//!
//! A partition is blank only when no signature is found and its first
//! [`HEAD_BYTES`] are zero. That MiB is what Stela's own erases clear:
//! 0.4.1's `--erase-target` zeroed it and nothing else, and Install macOS's
//! disk step in `stela.efi` zeroes it and the machine state after the
//! guest's bytes. Both leave the old data between, the guest's last bytes
//! included, so bytes that no signature names are not data of their own: a
//! backup GPT whose primary table at the start is gone is the same. A copy
//! a format keeps past that MiB or at its end (VMFS's headers, NTFS's
//! backup boot sector, ext's and btrfs's backup superblocks, LUKS2's second
//! header, HFS+'s alternate header, Linux RAID and ZFS's back labels) is
//! that format's data and never blank. Every byte probed is in [`probed`],
//! which an erase zeroes, so a partition erased now is blank later. A
//! partition that cannot be read is never blank; the caller refuses it.
use anyhow::{Context, Result};
use std::ops::Range;

/// The bytes from the start that must be zero for blank: the MiB Stela's
/// erases clear, past btrfs's and ReiserFS's superblocks at 64 KiB, ZFS's
/// two front labels (512 KiB) and a primary GPT's entries.
const HEAD_BYTES: u64 = 1 << 20;
/// The bytes read from the end: ZFS's two back labels (512 KiB), MD RAID
/// 0.90 and 1.0 superblocks (within 128 KiB), the backup GPT header, NTFS's
/// backup boot sector and HFS+'s alternate volume header.
const TAIL_BYTES: u64 = 1 << 20;
/// A ZFS label's size: the labels sit at the device's size aligned down to
/// it, two at the start and two at the end.
const ZFS_LABEL: u64 = 256 << 10;
/// The unit [`probed`] reads and an erase writes in: whole 4 KiB blocks,
/// which every disk's block size divides.
const BLOCK: u64 = 4096;

/// Where a signature sits in a partition of a given size.
#[derive(Clone, Copy, Debug)]
enum At {
    /// Bytes from the start.
    Start(u64),
    /// Bytes before the end.
    End(u64),
    /// An MD RAID 0.90 superblock: the last 64 KiB-aligned 64 KiB.
    Md090,
    /// An MD RAID 1.0 superblock: 8 KiB before the end, 4 KiB aligned.
    Md10,
    /// A ZFS uberblock: any 1 KiB slot of the ring at 128 KiB of the first
    /// label.
    ZfsRing,
    /// A ZFS uberblock in either back label's ring (`vdev_label_offset`).
    ZfsBackRing,
}

impl At {
    /// The offsets it names in a partition of `bytes`.
    fn offsets(self, bytes: u64) -> Vec<u64> {
        match self {
            Self::Start(offset) => vec![offset],
            Self::End(back) => bytes.checked_sub(back).into_iter().collect(),
            Self::Md090 => (bytes & !0xffff)
                .checked_sub(0x1_0000)
                .into_iter()
                .collect(),
            Self::Md10 => (bytes >> 9)
                .checked_sub(16)
                .map(|sector| (sector & !7) << 9)
                .into_iter()
                .collect(),
            Self::ZfsRing => (0..128).map(|slot| (128 << 10) + slot * 1024).collect(),
            Self::ZfsBackRing => [2, 1]
                .into_iter()
                .filter_map(|back| (bytes & !(ZFS_LABEL - 1)).checked_sub(back * ZFS_LABEL))
                .flat_map(|label| (0..128).map(move |slot| label + (128 << 10) + slot * 1024))
                .collect(),
        }
    }
}

/// One signature: what it marks and its bytes.
#[derive(Clone, Copy, Debug)]
pub(super) struct Signature {
    /// How a message names what holds it.
    pub(super) name: &'static str,
    at: At,
    magic: &'static [u8],
    /// Bytes that must match as well, each at its distance past the
    /// magic's offset.
    also: &'static [(u64, &'static [u8])],
    /// Whether it marks data only beside the start it belongs to: a backup
    /// GPT whose primary table at the start is gone is what an erase left.
    with_start: bool,
}

impl Signature {
    /// Every run of bytes it needs, with the magic at `offset`.
    fn fields(&self, offset: u64) -> impl Iterator<Item = (u64, &'static [u8])> {
        let magic = self.magic;
        std::iter::once((offset, magic)).chain(
            self.also
                .iter()
                .map(move |&(past, bytes)| (offset.saturating_add(past), bytes)),
        )
    }
}

const fn sig(name: &'static str, at: At, magic: &'static [u8]) -> Signature {
    Signature {
        name,
        at,
        magic,
        also: &[],
        with_start: false,
    }
}

/// A backup GPT header `back` bytes before the end.
const fn backup_gpt(back: u64) -> Signature {
    Signature {
        with_start: true,
        ..sig("a backup GPT", At::End(back), GPT_HEADER)
    }
}

/// The backup superblock of ext2, ext3 or ext4 at block group 1, which
/// starts at byte `superblock`: its magic at 0x38, and the group's number
/// (1) at 0x5a, which only a backup holds (e2fsprogs' `write_backup_super`).
const fn ext_backup(superblock: u64) -> Signature {
    Signature {
        also: &[(0x5a - 0x38, &[1, 0])],
        ..sig(
            "ext2, ext3 or ext4",
            At::Start(superblock + 0x38),
            &[0x53, 0xef],
        )
    }
}

/// A GUID partition table's header, at block 1 of 512- or 4096-byte blocks:
/// at a partition's start, the guest disk an install wrote.
pub(super) const GPT_HEADER: &[u8] = b"EFI PART";
pub(super) const GPT_HEADER_OFFSETS: [u64; 2] = [512, 4096];

/// Every signature probed, most specific first.
pub(super) const SIGNATURES: &[Signature] = &[
    sig("APFS", At::Start(32), b"NXSB"),
    sig("HFS+", At::Start(1024), b"H+\x00\x04"),
    sig("HFS+", At::Start(1024), b"HX\x00\x05"),
    // The alternate volume header, 1 KiB before the end (TN1150).
    sig("HFS+", At::End(1024), b"H+\x00\x04"),
    sig("HFS+", At::End(1024), b"HX\x00\x05"),
    sig("XFS", At::Start(0), b"XFSB"),
    sig("btrfs", At::Start(0x1_0040), b"_BHRfS_M"),
    // Its mirror superblocks at 64 MiB and 256 GiB.
    sig("btrfs", At::Start((64 << 20) + 0x40), b"_BHRfS_M"),
    sig("btrfs", At::Start((256 << 30) + 0x40), b"_BHRfS_M"),
    sig("F2FS", At::Start(1024), &[0x10, 0x20, 0xf5, 0xf2]),
    sig(
        "bcachefs",
        At::Start(4096 + 24),
        &[
            0xc6, 0x85, 0x73, 0xf6, 0x4e, 0x1a, 0x45, 0xca, 0x82, 0x65, 0xf5, 0x7f, 0x48, 0xba,
            0x6d, 0x81,
        ],
    ),
    sig("ZFS", At::ZfsRing, &[0x0c, 0xb1, 0xba, 0, 0, 0, 0, 0]),
    sig("ZFS", At::ZfsRing, &[0, 0, 0, 0, 0, 0xba, 0xb1, 0x0c]),
    sig("ZFS", At::ZfsBackRing, &[0x0c, 0xb1, 0xba, 0, 0, 0, 0, 0]),
    sig("ZFS", At::ZfsBackRing, &[0, 0, 0, 0, 0, 0xba, 0xb1, 0x0c]),
    // VMFS keeps its first MiB zero: its LVM header (0xc001d00d) at 1 MiB,
    // its file system's (0x2fabf15e) at 2 MiB.
    sig("VMFS", At::Start(1 << 20), &[0x0d, 0xd0, 0x01, 0xc0]),
    sig("VMFS", At::Start(2 << 20), &[0x5e, 0xf1, 0xab, 0x2f]),
    sig("ReiserFS", At::Start(0x1_0034), b"ReIsEr"),
    sig("ReiserFS", At::Start(0x2034), b"ReIsEr"),
    sig("JFS", At::Start(0x8000), b"JFS1"),
    sig("NTFS", At::Start(3), b"NTFS    "),
    // Its backup boot sector, in the last sector of 512 or 4096 bytes.
    sig("NTFS", At::End(512 - 3), b"NTFS    "),
    sig("NTFS", At::End(4096 - 3), b"NTFS    "),
    sig("exFAT", At::Start(3), b"EXFAT   "),
    sig("BitLocker", At::Start(3), b"-FVE-FS-"),
    sig("ReFS", At::Start(3), b"ReFS\x00\x00\x00\x00"),
    sig("FAT", At::Start(54), b"FAT1"),
    sig("FAT", At::Start(82), b"FAT32   "),
    sig("LUKS encryption", At::Start(0), b"LUKS\xba\xbe"),
    sig("LUKS encryption", At::Start(16384), b"SKUL\xba\xbe"),
    // LUKS2's second header after a larger first one, past the first MiB.
    sig("LUKS encryption", At::Start(1 << 20), b"SKUL\xba\xbe"),
    sig("LUKS encryption", At::Start(2 << 20), b"SKUL\xba\xbe"),
    sig("LUKS encryption", At::Start(4 << 20), b"SKUL\xba\xbe"),
    sig("an LVM volume", At::Start(0), b"LABELONE"),
    sig("an LVM volume", At::Start(512), b"LABELONE"),
    sig("an LVM volume", At::Start(1024), b"LABELONE"),
    sig("an LVM volume", At::Start(1536), b"LABELONE"),
    sig("Linux RAID", At::Start(0), &[0xfc, 0x4e, 0x2b, 0xa9]),
    sig("Linux RAID", At::Start(4096), &[0xfc, 0x4e, 0x2b, 0xa9]),
    sig("Linux RAID", At::Md090, &[0xfc, 0x4e, 0x2b, 0xa9]),
    sig("Linux RAID", At::Md10, &[0xfc, 0x4e, 0x2b, 0xa9]),
    sig("Linux swap", At::Start(4086), b"SWAPSPACE2"),
    sig("Linux swap", At::Start(65526), b"SWAPSPACE2"),
    sig("ISO 9660", At::Start(32769), b"CD001"),
    sig("UDF", At::Start(32769), b"BEA01"),
    sig("ext2, ext3 or ext4", At::Start(1080), &[0x53, 0xef]),
    // Group 1's backup superblock for 1, 2 and 4 KiB blocks.
    ext_backup((8192 + 1) * 1024),
    ext_backup(16384 * 2048),
    ext_backup(32768 * 4096),
    backup_gpt(512),
    backup_gpt(4096),
    sig("a boot sector", At::Start(510), &[0x55, 0xaa]),
];

/// What a partition holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Found {
    /// No signature, and zeros in its first [`HEAD_BYTES`].
    Blank,
    /// A GUID partition table at its start: a disk of its own.
    Gpt,
    /// A known signature: what it marks.
    Known(&'static str),
    /// Bytes that are not zero, of no known kind.
    Unknown,
}

/// The bytes of a partition of `bytes` that [`probe`] reads, in whole
/// [`BLOCK`]s, sorted and apart: its first [`HEAD_BYTES`], its last
/// [`TAIL_BYTES`] and every signature's bytes between. Zeroing them all
/// leaves it blank.
pub(super) fn probed(bytes: u64) -> Vec<Range<u64>> {
    let signatures = SIGNATURES.iter().flat_map(|signature| {
        signature
            .at
            .offsets(bytes)
            .into_iter()
            .flat_map(|offset| signature.fields(offset))
            .filter_map(|(offset, run)| Some(offset..offset.checked_add(run.len() as u64)?))
    });
    let mut ranges: Vec<Range<u64>> = [
        0..bytes.min(HEAD_BYTES),
        bytes.saturating_sub(TAIL_BYTES)..bytes,
    ]
    .into_iter()
    .chain(signatures)
    .filter(|range| range.end <= bytes)
    .map(|range| {
        range.start / BLOCK * BLOCK..range.end.div_ceil(BLOCK).saturating_mul(BLOCK).min(bytes)
    })
    .filter(|range| range.start < range.end)
    .collect();
    ranges.sort_by_key(|range| range.start);
    let mut apart: Vec<Range<u64>> = Vec::new();
    for range in ranges {
        match apart.last_mut() {
            Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
            _ => apart.push(range),
        }
    }
    apart
}

/// What the partition of `bytes` holds; `read(offset, length)` reads it.
pub(super) fn probe(
    bytes: u64,
    read: &mut dyn FnMut(u64, usize) -> Result<Vec<u8>>,
) -> Result<Found> {
    let mut held = Vec::new();
    for range in probed(bytes) {
        let data = read(range.start, usize::try_from(range.end - range.start)?)
            .with_context(|| format!("reading its bytes from {:#x}", range.start))?;
        held.push((range.start, data));
    }
    // The bytes at `offset`, when read.
    let at = |offset: u64, length: usize| -> Option<&[u8]> {
        let end = offset.checked_add(length as u64)?;
        let (start, data) = held
            .iter()
            .find(|(start, data)| *start <= offset && end <= start + data.len() as u64)?;
        data.get((offset - start) as usize..(end - start) as usize)
    };
    if GPT_HEADER_OFFSETS
        .iter()
        .any(|&offset| at(offset, GPT_HEADER.len()) == Some(GPT_HEADER))
    {
        return Ok(Found::Gpt);
    }
    let cleared = at(0, usize::try_from(bytes.min(HEAD_BYTES))?)
        .is_some_and(|head| head.iter().all(|&byte| byte == 0));
    for signature in SIGNATURES {
        if signature.with_start && cleared {
            continue;
        }
        if signature.at.offsets(bytes).into_iter().any(|offset| {
            signature
                .fields(offset)
                .all(|(offset, run)| at(offset, run.len()) == Some(run))
        }) {
            return Ok(Found::Known(signature.name));
        }
    }
    Ok(match cleared {
        true => Found::Blank,
        false => Found::Unknown,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BYTES: u64 = 16 << 20;
    /// A partition past every offset a signature names from the start.
    const LARGE: u64 = 300 << 30;
    const NTFS_BOOT: &[u8] = b"NTFS    ";
    const VMFS_LVM: &[u8] = &[0x0d, 0xd0, 0x01, 0xc0];

    /// A partition of `bytes`, zeros but for `writes` laid over them in
    /// order, read as a host reads one.
    struct Image {
        bytes: u64,
        writes: Vec<(u64, Vec<u8>)>,
    }

    impl Image {
        fn new(bytes: u64, writes: &[(u64, &[u8])]) -> Self {
            let writes = writes.iter().map(|&(at, data)| (at, data.to_vec()));
            Self {
                bytes,
                writes: writes.collect(),
            }
        }

        /// What the first `span` bytes hold, the bytes a guest disk spans.
        fn probe(&self, span: u64) -> Result<Found> {
            assert!(span <= self.bytes);
            probe(span, &mut |offset, length| {
                let end = offset + length as u64;
                anyhow::ensure!(end <= span, "read past the partition");
                let mut bytes = vec![0u8; length];
                for (at, data) in &self.writes {
                    let (from, to) = (offset.max(*at), end.min(at + data.len() as u64));
                    if from < to {
                        bytes[(from - offset) as usize..(to - offset) as usize]
                            .copy_from_slice(&data[(from - at) as usize..(to - at) as usize]);
                    }
                }
                Ok(bytes)
            })
        }

        /// Zeros over `range`.
        fn zero(&mut self, range: Range<u64>) {
            self.writes
                .push((range.start, vec![0; (range.end - range.start) as usize]));
        }

        /// Erased as `installed::erase_foreign` erases a guest disk's first
        /// `span` bytes.
        fn erase(&mut self, span: u64) {
            for range in probed(span) {
                self.zero(range);
            }
        }
    }

    fn found(bytes: u64, writes: &[(u64, &[u8])]) -> Result<Found> {
        Image::new(bytes, writes).probe(bytes)
    }

    /// `signature`'s bytes with its magic at `offset`.
    fn writes(signature: &Signature, offset: u64) -> Vec<(u64, &'static [u8])> {
        signature.fields(offset).collect()
    }

    #[test]
    fn every_signature_is_found_at_its_offset_and_named() {
        for signature in SIGNATURES {
            for offset in signature.at.offsets(LARGE) {
                // One that marks data only beside its start is found with
                // bytes there.
                let start: &[(u64, &[u8])] = match signature.with_start {
                    true => &[(100, b"x")],
                    false => &[],
                };
                assert_eq!(
                    found(LARGE, &[start, &writes(signature, offset)].concat()).unwrap(),
                    Found::Known(signature.name),
                    "{signature:?} at {offset:#x}"
                );
            }
        }
    }

    /// What `installed::erase_foreign` zeroes, every byte probed, leaves
    /// blank, whatever signature was there: a partition erased now is
    /// taken for blank later.
    #[test]
    fn an_erased_partition_is_blank() {
        for signature in SIGNATURES {
            for offset in signature.at.offsets(LARGE) {
                let mut image = Image::new(LARGE, &writes(signature, offset));
                image.writes.push((100, b"x".to_vec()));
                image.writes.push((LARGE / 3, vec![0xa5; 4096]));
                image.erase(LARGE);
                assert_eq!(
                    image.probe(LARGE).unwrap(),
                    Found::Blank,
                    "{signature:?} at {offset:#x}"
                );
            }
        }
        // The ranges are whole blocks, apart, within the partition.
        for bytes in [BYTES, LARGE, (1 << 20) + 512, 3 * 512] {
            let ranges = probed(bytes);
            assert_eq!(ranges[0].start, 0);
            assert!(ranges.windows(2).all(|pair| pair[0].end < pair[1].start));
            assert!(ranges.iter().all(|range| range.start % BLOCK == 0));
            assert_eq!(ranges.last().unwrap().end, bytes);
        }
    }

    #[test]
    fn signatures_past_the_first_8_kib_are_found() {
        for (offset, magic, name) in [
            (0x1_0040, &b"_BHRfS_M"[..], "btrfs"),
            (0x1_0034, b"ReIsEr2Fs", "ReiserFS"),
            (0x8000, b"JFS1", "JFS"),
            // ZFS's first label starts with 8 KiB of zeros; its uberblocks
            // sit at 128 KiB, any slot of the ring.
            (
                (128 << 10) + 5 * 1024,
                &[0x0c, 0xb1, 0xba, 0, 0, 0, 0, 0],
                "ZFS",
            ),
            (16384, b"SKUL\xba\xbe", "LUKS encryption"),
            (32769, b"CD001", "ISO 9660"),
            (65526, b"SWAPSPACE2", "Linux swap"),
        ] {
            assert_eq!(
                found(BYTES, &[(offset, magic)]).unwrap(),
                Found::Known(name)
            );
        }
    }

    #[test]
    fn metadata_at_the_end_is_found() {
        // MD RAID 0.90 and 1.0 keep their superblock at the end, and a
        // partition that was once a whole disk keeps its backup GPT there.
        let md = [0xfc, 0x4e, 0x2b, 0xa9];
        let odd = BYTES + 3 * 4096 + 512;
        let md090 = (odd & !0xffff) - 0x1_0000;
        assert_eq!(
            found(odd, &[(md090, &md)]).unwrap(),
            Found::Known("Linux RAID")
        );
        let md10 = (((odd >> 9) - 16) & !7) << 9;
        assert_eq!(
            found(odd, &[(md10, &md)]).unwrap(),
            Found::Known("Linux RAID")
        );
        assert_eq!(
            found(BYTES, &[(0, b"x"), (BYTES - 512, GPT_HEADER)]).unwrap(),
            Found::Known("a backup GPT")
        );
        // ZFS's back labels, the front ones gone.
        let aligned = BYTES + (100 << 10);
        let l3 = (aligned & !(ZFS_LABEL - 1)) - ZFS_LABEL + (128 << 10) + 7 * 1024;
        assert_eq!(
            found(aligned, &[(l3, &[0x0c, 0xb1, 0xba, 0, 0, 0, 0, 0])]).unwrap(),
            Found::Known("ZFS")
        );
        // A byte at the end beside data at the start is data too.
        assert_eq!(
            found(BYTES, &[(100, b"x"), (BYTES - 100, b"x")]).unwrap(),
            Found::Unknown
        );
    }

    /// A partition that held NTFS, as Stela 0.4.1's `--erase-target` left
    /// it: its first MiB zeroed, files past it to the guest's last bytes,
    /// and the backup boot sector in the partition's last sector.
    #[test]
    fn a_partition_erased_by_0_4_1_is_blank() {
        let mut boot = [0u8; 512];
        boot[3..11].copy_from_slice(NTFS_BOOT);
        boot[510..].copy_from_slice(&[0x55, 0xaa]);
        let files = [0xa5; 4096];
        // The guest disk spans `BYTES`; the machine state follows, to the
        // partition's end.
        let partition = BYTES + (17 << 20);
        let writes: &[(u64, &[u8])] = &[
            (0, &boot),
            (HEAD_BYTES - 4096, &files),
            (HEAD_BYTES, &files),
            (BYTES / 2, &files),
            (BYTES - (64 << 10), &files),
            (BYTES - 512, &files),
            (partition - 512, &boot),
        ];
        let mut image = Image::new(partition, writes);
        assert_eq!(image.probe(partition).unwrap(), Found::Known("NTFS"));
        // 0.4.1's FOREIGN_HEAD_BYTES.
        image.zero(0..1 << 20);
        // The machine state in the partition's tail: the guest's bytes hold
        // no signature of their own.
        assert_eq!(image.probe(BYTES).unwrap(), Found::Blank);
        // The machine state on a partition of its own: the guest spans the
        // whole partition and the backup boot sector is NTFS's, until
        // --erase-target erases it.
        assert_eq!(image.probe(partition).unwrap(), Found::Known("NTFS"));
        image.erase(partition);
        assert_eq!(image.probe(partition).unwrap(), Found::Blank);
        // A guest disk an install wrote, so erased: the backup GPT at its
        // end is left, its primary table gone.
        let mut primary = [0u8; 92];
        primary[..8].copy_from_slice(GPT_HEADER);
        let guest: &[(u64, &[u8])] = &[
            (512, &primary),
            (40 * 512, &files),
            (HEAD_BYTES + 4096, &files),
            (BYTES - 33 * 512, &files),
            (BYTES - 512, &primary),
        ];
        let mut image = Image::new(BYTES, guest);
        assert_eq!(image.probe(BYTES).unwrap(), Found::Gpt);
        image.zero(0..1 << 20);
        assert_eq!(image.probe(BYTES).unwrap(), Found::Blank);
    }

    /// Zeros at the start do not make a partition blank where its end holds
    /// a format's own data: NTFS's backup boot sector, HFS+'s alternate
    /// header, a Linux RAID member's superblock or ZFS's back labels. Bytes
    /// there that no signature names are what Stela's erases leave.
    #[test]
    fn a_format_at_the_end_behind_a_zeroed_start_is_not_blank() {
        let mut boot = [0u8; 512];
        boot[3..11].copy_from_slice(NTFS_BOOT);
        boot[510..].copy_from_slice(&[0x55, 0xaa]);
        assert_eq!(
            found(BYTES, &[(BYTES - 512, &boot)]).unwrap(),
            Found::Known("NTFS")
        );
        assert_eq!(
            found(BYTES, &[(BYTES - 4096, &boot)]).unwrap(),
            Found::Known("NTFS")
        );
        assert_eq!(
            found(BYTES, &[(BYTES - 1024, b"H+\x00\x04")]).unwrap(),
            Found::Known("HFS+")
        );
        let md10 = (((BYTES >> 9) - 16) & !7) << 9;
        assert_eq!(
            found(BYTES, &[(md10, &[0xfc, 0x4e, 0x2b, 0xa9])]).unwrap(),
            Found::Known("Linux RAID")
        );
        let l2 = BYTES - 2 * ZFS_LABEL + (128 << 10);
        assert_eq!(
            found(BYTES, &[(l2, &[0, 0, 0, 0, 0, 0xba, 0xb1, 0x0c])]).unwrap(),
            Found::Known("ZFS")
        );
        // With the GPT too, the RAID superblock names it.
        assert_eq!(
            found(
                BYTES,
                &[(BYTES - 512, GPT_HEADER), (md10, &[0xfc, 0x4e, 0x2b, 0xa9])]
            )
            .unwrap(),
            Found::Known("Linux RAID")
        );
        assert_eq!(found(BYTES, &[(BYTES - 100, b"x")]).unwrap(), Found::Blank);
    }

    /// VMFS keeps its first MiB zero and its LVM header at 1 MiB.
    #[test]
    fn vmfs_is_not_blank() {
        assert_eq!(
            found(BYTES, &[(1 << 20, VMFS_LVM)]).unwrap(),
            Found::Known("VMFS")
        );
        assert_eq!(
            found(BYTES, &[(2 << 20, &[0x5e, 0xf1, 0xab, 0x2f])]).unwrap(),
            Found::Known("VMFS")
        );
        // Bytes just past the first MiB that no format names are not.
        assert_eq!(
            found(BYTES, &[((1 << 20) + 8, VMFS_LVM)]).unwrap(),
            Found::Blank
        );
    }

    /// ext4 with its first MiB zeroed keeps group 1's backup superblock,
    /// at 128 MiB for 4 KiB blocks; the magic alone, without the group's
    /// number a backup holds, is not one.
    #[test]
    fn ext4_behind_a_zeroed_start_is_not_blank() {
        let superblock = 128 << 20;
        let bytes = 1 << 30;
        assert_eq!(
            found(
                bytes,
                &[
                    (superblock + 0x38, &[0x53, 0xef]),
                    (superblock + 0x5a, &[1, 0])
                ]
            )
            .unwrap(),
            Found::Known("ext2, ext3 or ext4")
        );
        assert_eq!(
            found(bytes, &[(superblock + 0x38, &[0x53, 0xef])]).unwrap(),
            Found::Blank
        );
        // A 1 KiB-block ext2 keeps it at block 8193.
        let superblock = 8193 * 1024;
        assert_eq!(
            found(
                bytes,
                &[
                    (superblock + 0x38, &[0x53, 0xef]),
                    (superblock + 0x5a, &[1, 0])
                ]
            )
            .unwrap(),
            Found::Known("ext2, ext3 or ext4")
        );
    }

    #[test]
    fn a_gpt_at_the_start_is_a_disk_of_its_own() {
        for offset in GPT_HEADER_OFFSETS {
            assert_eq!(found(BYTES, &[(offset, GPT_HEADER)]).unwrap(), Found::Gpt);
        }
    }

    #[test]
    fn only_zeros_where_signatures_sit_are_blank() {
        assert_eq!(found(BYTES, &[]).unwrap(), Found::Blank);
        // Within the bytes read and of no known kind: data.
        assert_eq!(
            found(BYTES, &[(HEAD_BYTES - 1, b"x")]).unwrap(),
            Found::Unknown
        );
        // A partition smaller than the bytes probed is read whole.
        assert_eq!(found(1 << 20, &[]).unwrap(), Found::Blank);
        assert_eq!(
            found(1 << 20, &[(0x8000, b"JFS1")]).unwrap(),
            Found::Known("JFS")
        );
    }

    #[test]
    fn a_partition_that_cannot_be_read_is_not_blank() {
        let error = probe(BYTES, &mut |_, _| anyhow::bail!("no medium")).unwrap_err();
        assert!(format!("{error:#}").contains("no medium"), "{error:#}");
    }
}
