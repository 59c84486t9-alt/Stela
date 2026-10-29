//! The install medium's pieces joined into one seekable IPSW.
//!
//! Each piece is a file on the medium, given as the extents that hold its
//! bytes on one device (a FAT32 partition's cluster runs,
//! `pc::fat32::File::extents`). Every read is checked block by block: the
//! manifest names a file of each piece block's SHA-256 (`Layout::Pieces`
//! `block_hashes`), which the host that wrote the pieces computed from the
//! IPSW, and each block a read touches is read whole, through the piece's
//! extents, and compared with its hash before any of its bytes are
//! returned. No piece is hashed whole first, so nothing scans the medium
//! before the restore starts. A block that differs is refused with its
//! piece's name.
use super::{Layout, PayloadError, PayloadManifest, ReadAt, piece_name};
use alloc::{format, vec, vec::Vec};
use sha2::Digest;
use stela_crypto::Sha256;

/// A run of a piece's bytes on the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    /// The device offset of its first byte.
    pub offset: u64,
    pub bytes: u64,
}

struct Part {
    /// The IPSW offset of its first byte.
    start: u64,
    bytes: u64,
    /// Its extents, each with the piece offset of its first byte.
    extents: Vec<(u64, Extent)>,
    /// The index of its first block in the hash list.
    first_block: usize,
}

pub struct Joined<R> {
    device: R,
    parts: Vec<Part>,
    total: u64,
    block_bytes: u64,
    hashes: Vec<[u8; 32]>,
    /// The last block read and verified: its piece, block and bytes.
    cached: Option<(usize, u64, Vec<u8>)>,
}

impl<R: ReadAt> Joined<R> {
    /// Join the manifest's pieces, `extents[i]` holding piece `i`, checked
    /// against `hashes`, the contents of the piece hash file the manifest
    /// names. Each piece's extents must hold exactly its bytes, inside the
    /// device.
    pub fn new(
        device: R,
        manifest: &PayloadManifest,
        extents: Vec<Vec<Extent>>,
        hashes: &[u8],
    ) -> Result<Self, PayloadError> {
        let Layout::Pieces {
            pieces,
            block_hashes,
            ..
        } = &manifest.layout
        else {
            return Err(PayloadError::Manifest("the payload is not in pieces"));
        };
        if crate::sha256(hashes) != block_hashes.sha256 {
            return Err(PayloadError::Verification {
                member: block_hashes.file.clone(),
                reason: "its SHA-256 differs from payload.json",
            });
        }
        let count = manifest.piece_hash_blocks();
        if hashes.len() as u64 != count * 32 {
            return Err(PayloadError::Verification {
                member: block_hashes.file.clone(),
                reason: "it lists another number of blocks than the pieces have",
            });
        }
        if extents.len() != pieces.len() {
            return Err(PayloadError::Manifest("a piece has no extents"));
        }
        let mut parts = Vec::with_capacity(pieces.len());
        let mut start = 0u64;
        let mut first_block = 0usize;
        for (index, (piece, runs)) in pieces.iter().zip(extents).enumerate() {
            let mut at = 0u64;
            let mut placed = Vec::with_capacity(runs.len());
            for run in runs {
                if run.bytes == 0
                    || run
                        .offset
                        .checked_add(run.bytes)
                        .is_none_or(|end| end > device.len())
                {
                    return Err(PayloadError::Verification {
                        member: piece_name(index),
                        reason: "an extent lies outside the medium",
                    });
                }
                placed.push((at, run));
                at += run.bytes;
            }
            if at != piece.bytes {
                return Err(PayloadError::Verification {
                    member: piece_name(index),
                    reason: "its size differs from payload.json",
                });
            }
            parts.push(Part {
                start,
                bytes: piece.bytes,
                extents: placed,
                first_block,
            });
            start += piece.bytes;
            first_block += piece.bytes.div_ceil(block_hashes.block_bytes) as usize;
        }
        if start != manifest.source.bytes {
            return Err(PayloadError::Manifest("the pieces do not hold the IPSW"));
        }
        Ok(Self {
            device,
            parts,
            total: start,
            block_bytes: block_hashes.block_bytes,
            hashes: hashes.as_chunks::<32>().0.to_vec(),
            cached: None,
        })
    }

    /// Read from piece `index` at its own offset, through its extents.
    fn read_part(
        &mut self,
        index: usize,
        mut offset: u64,
        mut buffer: &mut [u8],
    ) -> Result<(), PayloadError> {
        let part = &self.parts[index];
        let mut at = part
            .extents
            .partition_point(|(start, _)| *start <= offset)
            .saturating_sub(1);
        while !buffer.is_empty() {
            let (start, extent) = part.extents[at];
            let within = offset - start;
            let count = (extent.bytes - within).min(buffer.len() as u64) as usize;
            self.device
                .read_at(extent.offset + within, &mut buffer[..count])
                .map_err(|error| PayloadError::Io(format!("{}: {error:?}", piece_name(index))))?;
            buffer = &mut buffer[count..];
            offset += count as u64;
            at += 1;
        }
        Ok(())
    }

    /// Block `block` of piece `index`, read whole and verified.
    fn block(&mut self, index: usize, block: u64) -> Result<&[u8], PayloadError> {
        if self
            .cached
            .as_ref()
            .is_none_or(|(piece, cached, _)| (*piece, *cached) != (index, block))
        {
            let part = &self.parts[index];
            let start = block * self.block_bytes;
            let bytes = (part.bytes - start).min(self.block_bytes) as usize;
            let hash = self.hashes[part.first_block + block as usize];
            let mut data = match self.cached.take() {
                Some((_, _, mut data)) => {
                    data.resize(bytes, 0);
                    data
                }
                None => vec![0; bytes],
            };
            self.read_part(index, start, &mut data)?;
            if <[u8; 32]>::from(Sha256::digest(&data)) != hash {
                return Err(PayloadError::Verification {
                    member: format!("{} block {block}", piece_name(index)),
                    reason: "its bytes differ from the piece's block hash",
                });
            }
            self.cached = Some((index, block, data));
        }
        Ok(&self.cached.as_ref().expect("cached above").2)
    }
}

impl<R: ReadAt> ReadAt for Joined<R> {
    type Error = PayloadError;

    fn len(&self) -> u64 {
        self.total
    }

    fn read_at(&mut self, mut offset: u64, mut buffer: &mut [u8]) -> Result<(), PayloadError> {
        if offset
            .checked_add(buffer.len() as u64)
            .is_none_or(|end| end > self.total)
        {
            return Err(PayloadError::Archive("read past the IPSW's end"));
        }
        while !buffer.is_empty() {
            let index = self
                .parts
                .partition_point(|part| part.start <= offset)
                .saturating_sub(1);
            let within = offset - self.parts[index].start;
            let block = within / self.block_bytes;
            let skip = (within - block * self.block_bytes) as usize;
            let data = self.block(index, block)?;
            let count = (data.len() - skip).min(buffer.len());
            buffer[..count].copy_from_slice(&data[skip..skip + count]);
            buffer = &mut buffer[count..];
            offset += count as u64;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::{
        BlockHashes, PIECE_HASHES_FILE, Piece, piece_sizes, test_support::Memory,
    };

    const BLOCK: u64 = 512;

    /// A medium holding `ipsw` as pieces of `piece_bytes`, each scattered
    /// over two extents in reverse order, its manifest and its piece hash
    /// file.
    fn medium(
        ipsw: &[u8],
        piece_bytes: u64,
    ) -> (Memory, PayloadManifest, Vec<Vec<Extent>>, Vec<u8>) {
        let (mut manifest, _) = crate::payload::test_support::manifest();
        manifest.source.bytes = ipsw.len() as u64;
        let mut device = vec![0xeeu8; 64];
        let mut pieces = Vec::new();
        let mut extents = Vec::new();
        let mut hashes = Vec::new();
        let mut at = 0usize;
        for size in piece_sizes(ipsw.len() as u64, piece_bytes) {
            let bytes = &ipsw[at..at + size as usize];
            for block in bytes.chunks(BLOCK as usize) {
                hashes.extend_from_slice(&Sha256::digest(block));
            }
            // Split off the middle of a block, so a block spans extents.
            let half = (bytes.len() / 2) | 1;
            let (head, tail) = bytes.split_at(half.min(bytes.len()));
            let tail_offset = device.len() as u64;
            device.extend_from_slice(tail);
            device.extend_from_slice(&[0xee; 7]);
            let head_offset = device.len() as u64;
            device.extend_from_slice(head);
            let mut runs = vec![Extent {
                offset: head_offset,
                bytes: head.len() as u64,
            }];
            if !tail.is_empty() {
                runs.push(Extent {
                    offset: tail_offset,
                    bytes: tail.len() as u64,
                });
            }
            extents.push(runs);
            pieces.push(Piece {
                bytes: size,
                sha256: crate::sha256(bytes),
            });
            at += size as usize;
        }
        manifest.layout = Layout::Pieces {
            piece_bytes,
            pieces,
            block_hashes: BlockHashes {
                file: PIECE_HASHES_FILE.into(),
                block_bytes: BLOCK,
                sha256: crate::sha256(&hashes),
            },
        };
        manifest.validate().unwrap();
        (Memory(device), manifest, extents, hashes)
    }

    fn ipsw() -> Vec<u8> {
        (0..10_000u32).map(|i| ((i * 7) ^ (i >> 5)) as u8).collect()
    }

    #[test]
    fn joined_pieces_read_as_the_ipsw_checking_every_block_read() {
        let ipsw = ipsw();
        let (device, manifest, extents, hashes) = medium(&ipsw, 3072);
        let mut joined = Joined::new(device, &manifest, extents, &hashes).unwrap();
        assert_eq!(joined.len(), ipsw.len() as u64);
        // Within one block, across blocks and extents, then across all
        // four pieces.
        let mut buffer = vec![0; 100];
        joined.read_at(3100, &mut buffer).unwrap();
        assert_eq!(buffer, ipsw[3100..3200]);
        let mut whole = vec![0; ipsw.len()];
        joined.read_at(0, &mut whole).unwrap();
        assert_eq!(whole, ipsw);
        let mut odd = vec![0; 4000];
        joined.read_at(1001, &mut odd).unwrap();
        assert_eq!(odd, ipsw[1001..5001]);
        let mut tail = vec![0; 1];
        assert!(joined.read_at(ipsw.len() as u64, &mut tail).is_err());
        joined.read_at(ipsw.len() as u64, &mut []).unwrap();
    }

    #[test]
    fn an_altered_short_or_misplaced_piece_is_refused_by_name() {
        let ipsw = ipsw();
        let (mut device, manifest, extents, hashes) = medium(&ipsw, 3072);
        // Alter the first byte of the third piece's head: its block 0.
        device.0[extents[2][0].offset as usize] ^= 1;
        let mut joined = Joined::new(device, &manifest, extents, &hashes).unwrap();
        let mut buffer = vec![0; 10];
        joined.read_at(0, &mut buffer).unwrap();
        // Its second block reads.
        joined.read_at(6144 + 600, &mut buffer).unwrap();
        let error = joined
            .read_at(6144 + 5, &mut buffer)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "ipsw.002 block 0: its bytes differ from the piece's block hash"
        );
        // A read spanning into it fails too.
        let error = joined.read_at(6140, &mut buffer).unwrap_err().to_string();
        assert!(error.starts_with("ipsw.002 block 0"), "{error}");

        let (device, manifest, mut short, hashes) = medium(&ipsw, 3072);
        short[3][0].bytes -= 1;
        let error = Joined::new(device, &manifest, short, &hashes)
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            "ipsw.003: its size differs from payload.json"
        );
        let (device, manifest, mut outside, hashes) = medium(&ipsw, 3072);
        outside[0][0].offset = device.len();
        let error = Joined::new(device, &manifest, outside, &hashes)
            .err()
            .unwrap();
        assert!(error.to_string().starts_with("ipsw.000"), "{error}");
        let (device, manifest, mut missing, hashes) = medium(&ipsw, 3072);
        missing.pop();
        assert!(Joined::new(device, &manifest, missing, &hashes).is_err());
        let (device, manifest, extents, mut hashes) = medium(&ipsw, 3072);
        hashes[0] ^= 1;
        let error = Joined::new(device, &manifest, extents, &hashes)
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            "pieces.bin: its SHA-256 differs from payload.json"
        );
    }
}
