//! Durable translation-pack writes through an owned block-device adapter.
use alloc::vec::Vec;
use stela_engine::translations::pack::Layout;

/// Why a pack was not written in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteError {
    /// The file holds fewer bytes than the pack.
    Small { file: u64, pack: u64 },
    /// An extent does not start on a device block.
    Misaligned,
    #[cfg(target_arch = "x86_64")]
    Device(stela_drivers::block::BlockError),
}

/// The bytes written to the device at a time.
#[cfg(target_arch = "x86_64")]
const TRANSFER_BYTES: usize = 1 << 20;

/// Write `layout` over the file whose device extents (its cluster chain,
/// cut to its size) are `extents`, whole device blocks at a time with the
/// last padded with zeros, which lie past the pack and inside the file's
/// last cluster; then make it durable. The file is never grown, and a pack
/// larger than it is refused before anything is written.
#[cfg(target_arch = "x86_64")]
pub fn write_in_place(
    device: &mut dyn stela_drivers::block::BlockDevice,
    extents: &[stela_formats::payload::pieces::Extent],
    layout: &Layout,
) -> Result<(), WriteError> {
    let block = u64::from(device.identity().block_size);
    let file: u64 = extents.iter().map(|extent| extent.bytes).sum();
    let pack = layout.bytes();
    if pack > file {
        return Err(WriteError::Small { file, pack });
    }
    if extents.iter().any(|extent| extent.offset % block != 0) {
        return Err(WriteError::Misaligned);
    }
    let mut chunks = layout.chunks();
    let mut chunk: &[u8] = &[];
    let mut left = pack;
    let mut buffer = Vec::with_capacity(TRANSFER_BYTES);
    for extent in extents {
        let mut written = 0;
        while written < extent.bytes && left > 0 {
            let take = (extent.bytes - written)
                .min(TRANSFER_BYTES as u64)
                .min(left);
            buffer.clear();
            while buffer.len() < take as usize {
                if chunk.is_empty() {
                    chunk = chunks.next().expect("the layout holds `pack` bytes");
                    continue;
                }
                let (now, later) = chunk.split_at(chunk.len().min(take as usize - buffer.len()));
                buffer.extend_from_slice(now);
                chunk = later;
            }
            buffer.resize(buffer.len().next_multiple_of(block as usize), 0);
            device
                .write((extent.offset + written) / block, &buffer)
                .map_err(WriteError::Device)?;
            written += take;
            left -= take;
        }
    }
    device.flush().map_err(WriteError::Device)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_engine::translations::{
        Digest,
        pack::{Pack, Piece},
    };
    #[test]
    fn a_pack_is_written_over_its_files_extents_and_never_past_them() {
        use stela_drivers::block::RamDisk;
        use stela_formats::payload::pieces::Extent;
        const BLOCK: u32 = 512;
        let translator = Digest::of(b"translator");
        let records: Vec<(Digest, Piece)> = (0u8..40)
            .map(|index| (Digest::of(&[index]), Piece::New(vec![index; 300])))
            .collect();
        let layout = Layout::new(&translator, records);
        let pack = layout.bytes();
        let mut disk = RamDisk::new("pack", 128, BLOCK);
        disk.identity.features.write_cache = true;
        disk.bytes.fill(0xee);
        // Two clusters of 8 blocks, out of order, the file cut to its size.
        let cluster = 8 * u64::from(BLOCK);
        let extents = [
            Extent {
                offset: 64 * u64::from(BLOCK),
                bytes: cluster,
            },
            Extent {
                offset: 16 * u64::from(BLOCK),
                bytes: pack - cluster + 100,
            },
        ];
        write_in_place(&mut disk, &extents, &layout).unwrap();
        let mut read = disk.bytes[64 * BLOCK as usize..][..cluster as usize].to_vec();
        read.extend(&disk.bytes[16 * BLOCK as usize..][..(pack - cluster) as usize]);
        assert_eq!(read, layout.to_vec());
        assert!(Pack::parse(&read, &translator).is_ok());
        let after = 16 * BLOCK as usize + (pack - cluster) as usize;
        let padded = after.next_multiple_of(BLOCK as usize);
        assert!(disk.bytes[after..padded].iter().all(|&byte| byte == 0));
        assert!(
            disk.bytes[padded..64 * BLOCK as usize]
                .iter()
                .all(|&byte| byte == 0xee)
        );
        assert_eq!(disk.flushes, 1);
        let small = [Extent {
            offset: 0,
            bytes: pack - 1,
        }];
        assert_eq!(
            write_in_place(&mut disk, &small, &layout),
            Err(WriteError::Small {
                file: pack - 1,
                pack
            })
        );
        let misaligned = [Extent {
            offset: 1,
            bytes: pack,
        }];
        assert_eq!(
            write_in_place(&mut disk, &misaligned, &layout),
            Err(WriteError::Misaligned)
        );
    }
}
