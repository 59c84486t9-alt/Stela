//! What a partition holds, read from the signatures that file systems,
//! encryption, volume managers, RAID and partition tables write at their
//! documented offsets, near the start of the partition or its end. A
//! partition is blank only when no signature is found and its first
//! [`HEAD_BYTES`], where every format probed starts, are zero. Bytes past
//! them, and in its last [`TAIL_BYTES`], that no signature names are what an
//! erase that cleared the start left: Stela 0.4.1's `--erase-target`
//! cleared only the first MiB. A backup GPT whose primary table at the
//! start is gone is the same. A signature that marks data on its own at
//! the end, Linux RAID or ZFS's back labels, is never taken for blank. A
//! partition that cannot be read is never blank; the caller refuses it.
use anyhow::{Context, Result};

/// The bytes read from the start, which must be zero for blank: past
/// btrfs's and ReiserFS's superblocks at 64 KiB, ZFS's two front labels
/// (512 KiB) and a primary GPT's entries, the bytes an erase clears.
pub(super) const HEAD_BYTES: u64 = 1 << 20;
/// The bytes read from the end: ZFS's two back labels (512 KiB), MD RAID
/// 0.90 and 1.0 superblocks (within 128 KiB) and the backup GPT header.
pub(super) const TAIL_BYTES: u64 = 1 << 20;
/// A ZFS label's size: the labels sit at the device's size aligned down to
/// it, two at the start and two at the end.
const ZFS_LABEL: u64 = 256 << 10;

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
    /// Whether it marks data only beside the start it belongs to: a backup
    /// GPT whose primary table at the start is gone is what an erase left.
    with_start: bool,
}

const fn sig(name: &'static str, at: At, magic: &'static [u8]) -> Signature {
    Signature {
        name,
        at,
        magic,
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

/// A GUID partition table's header, at block 1 of 512- or 4096-byte blocks:
/// at a partition's start, the guest disk an install wrote.
pub(super) const GPT_HEADER: &[u8] = b"EFI PART";
pub(super) const GPT_HEADER_OFFSETS: [u64; 2] = [512, 4096];

/// Every signature probed, most specific first.
pub(super) const SIGNATURES: &[Signature] = &[
    sig("APFS", At::Start(32), b"NXSB"),
    sig("HFS+", At::Start(1024), b"H+\x00\x04"),
    sig("HFS+", At::Start(1024), b"HX\x00\x05"),
    sig("XFS", At::Start(0), b"XFSB"),
    sig("btrfs", At::Start(0x1_0040), b"_BHRfS_M"),
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
    sig("ReiserFS", At::Start(0x1_0034), b"ReIsEr"),
    sig("ReiserFS", At::Start(0x2034), b"ReIsEr"),
    sig("JFS", At::Start(0x8000), b"JFS1"),
    sig("NTFS", At::Start(3), b"NTFS    "),
    sig("exFAT", At::Start(3), b"EXFAT   "),
    sig("BitLocker", At::Start(3), b"-FVE-FS-"),
    sig("ReFS", At::Start(3), b"ReFS\x00\x00\x00\x00"),
    sig("FAT", At::Start(54), b"FAT1"),
    sig("FAT", At::Start(82), b"FAT32   "),
    sig("LUKS encryption", At::Start(0), b"LUKS\xba\xbe"),
    sig("LUKS encryption", At::Start(16384), b"SKUL\xba\xbe"),
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
    backup_gpt(512),
    backup_gpt(4096),
    sig("a boot sector", At::Start(510), &[0x55, 0xaa]),
];

/// What a partition holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Found {
    /// No signature, and zeros where every format probed starts.
    Blank,
    /// A GUID partition table at its start: a disk of its own.
    Gpt,
    /// A known signature: what it marks.
    Known(&'static str),
    /// Bytes that are not zero, of no known kind.
    Unknown,
}

/// What the partition of `bytes` holds; `read(offset, length)` reads it.
pub(super) fn probe(
    bytes: u64,
    read: &mut dyn FnMut(u64, usize) -> Result<Vec<u8>>,
) -> Result<Found> {
    let head_end = bytes.min(HEAD_BYTES);
    let head = read(0, usize::try_from(head_end)?).context("reading its start")?;
    let tail_start = bytes.saturating_sub(TAIL_BYTES).max(head_end);
    let tail = read(tail_start, usize::try_from(bytes - tail_start)?).context("reading its end")?;
    // The bytes at `offset`, when read.
    let at = |offset: u64, length: usize| -> Option<&[u8]> {
        let end = offset.checked_add(length as u64)?;
        if end <= head_end {
            head.get(offset as usize..end as usize)
        } else if offset >= tail_start && end <= bytes {
            tail.get((offset - tail_start) as usize..(end - tail_start) as usize)
        } else {
            None
        }
    };
    if GPT_HEADER_OFFSETS
        .iter()
        .any(|&offset| at(offset, GPT_HEADER.len()) == Some(GPT_HEADER))
    {
        return Ok(Found::Gpt);
    }
    let cleared = head.iter().all(|&byte| byte == 0);
    for signature in SIGNATURES {
        if signature.with_start && cleared {
            continue;
        }
        let length = signature.magic.len();
        if signature
            .at
            .offsets(bytes)
            .into_iter()
            .any(|offset| at(offset, length) == Some(signature.magic))
        {
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

    /// A partition of `bytes` that holds `writes`, read as a host reads
    /// one, with every read recorded.
    fn found(bytes: u64, writes: &[(u64, &[u8])]) -> Result<Found> {
        let mut image = vec![0u8; bytes as usize];
        for &(offset, data) in writes {
            image[offset as usize..offset as usize + data.len()].copy_from_slice(data);
        }
        probe(bytes, &mut |offset, length| {
            let end = offset as usize + length;
            anyhow::ensure!(end <= image.len(), "read past the partition");
            Ok(image[offset as usize..end].to_vec())
        })
    }

    #[test]
    fn every_signature_is_found_at_its_offset_and_named() {
        for signature in SIGNATURES {
            for offset in signature.at.offsets(BYTES) {
                // One that marks data only beside its start is found with
                // bytes there.
                let start: &[(u64, &[u8])] = match signature.with_start {
                    true => &[(100, b"x")],
                    false => &[],
                };
                assert_eq!(
                    found(BYTES, &[start, &[(offset, signature.magic)]].concat()).unwrap(),
                    Found::Known(signature.name),
                    "{signature:?} at {offset:#x}"
                );
            }
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

    /// A partition that held NTFS, files past its first MiB and the backup
    /// boot sector in its last sector, as Stela 0.4.1's `--erase-target`
    /// left it, its first MiB zeroed: blank, as 0.4.1 took it.
    #[test]
    fn a_partition_erased_by_0_4_1_is_blank() {
        let mut boot = [0u8; 512];
        boot[3..11].copy_from_slice(b"NTFS    ");
        boot[510..].copy_from_slice(&[0x55, 0xaa]);
        let files = [0xa5; 4096];
        let writes: &[(u64, &[u8])] = &[
            (0, &boot),
            (HEAD_BYTES - 4096, &files),
            (HEAD_BYTES, &files),
            (BYTES / 2, &files),
            (BYTES - (64 << 10), &files),
            (BYTES - 512, &boot),
        ];
        assert_eq!(found(BYTES, writes).unwrap(), Found::Known("NTFS"));
        let erased = |writes: &[(u64, &[u8])]| {
            let mut image = vec![0u8; BYTES as usize];
            for &(offset, data) in writes {
                image[offset as usize..offset as usize + data.len()].copy_from_slice(data);
            }
            // 0.4.1's FOREIGN_HEAD_BYTES.
            image[..1 << 20].fill(0);
            probe(BYTES, &mut |offset, length| {
                Ok(image[offset as usize..offset as usize + length].to_vec())
            })
            .unwrap()
        };
        assert_eq!(erased(writes), Found::Blank);
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
        assert_eq!(found(BYTES, guest).unwrap(), Found::Gpt);
        assert_eq!(erased(guest), Found::Blank);
    }

    /// Zeros at the start alone do not make a partition blank where a
    /// signature at its end marks data of its own: a Linux RAID member's
    /// superblock, or ZFS's back labels.
    #[test]
    fn a_foreign_end_behind_a_zeroed_start_is_not_blank() {
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
