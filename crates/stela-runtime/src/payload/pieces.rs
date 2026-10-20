//! The install medium's pieces joined into one seekable IPSW.
//!
//! Each piece is a file on the medium, given as the extents that hold its
//! bytes on one device (a FAT32 partition's cluster runs,
//! `pc::fat32::File::extents`). A read is served only from pieces whose
//! SHA-256 matched the manifest: the first read that touches a piece hashes
//! all of it, through the same extents, before any of its bytes are
//! returned. A piece that differs is refused by name, and stays refused.
use super::{Layout, PayloadError, PayloadManifest, ReadAt, piece_name};
use alloc::{format, string::String, vec, vec::Vec};
use sha2::{Digest, Sha256};

/// A run of a piece's bytes on the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    /// The device offset of its first byte.
    pub offset: u64,
    pub bytes: u64,
}

/// Bytes hashed per device read.
const HASH_CHUNK: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Unverified,
    Verified,
    Refused(&'static str),
}

struct Part {
    name: String,
    /// The IPSW offset of its first byte.
    start: u64,
    bytes: u64,
    sha256: String,
    /// Its extents, each with the piece offset of its first byte.
    extents: Vec<(u64, Extent)>,
    state: State,
}

pub struct Joined<R> {
    device: R,
    parts: Vec<Part>,
    total: u64,
}

impl<R: ReadAt> Joined<R> {
    /// Join the manifest's pieces, `extents[i]` holding piece `i`. Each
    /// piece's extents must hold exactly its bytes, inside the device.
    pub fn new(
        device: R,
        manifest: &PayloadManifest,
        extents: Vec<Vec<Extent>>,
    ) -> Result<Self, PayloadError> {
        let Layout::Pieces { pieces, .. } = &manifest.layout else {
            return Err(PayloadError::Manifest("the payload is not in pieces"));
        };
        if extents.len() != pieces.len() {
            return Err(PayloadError::Manifest("a piece has no extents"));
        }
        let mut parts = Vec::with_capacity(pieces.len());
        let mut start = 0u64;
        for (index, (piece, runs)) in pieces.iter().zip(extents).enumerate() {
            let name = piece_name(index);
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
                        member: name,
                        reason: "an extent lies outside the medium",
                    });
                }
                placed.push((at, run));
                at += run.bytes;
            }
            if at != piece.bytes {
                return Err(PayloadError::Verification {
                    member: name,
                    reason: "its size differs from payload.json",
                });
            }
            parts.push(Part {
                name,
                start,
                bytes: piece.bytes,
                sha256: piece.sha256.clone(),
                extents: placed,
                state: State::Unverified,
            });
            start += piece.bytes;
        }
        if start != manifest.source.bytes {
            return Err(PayloadError::Manifest("the pieces do not hold the IPSW"));
        }
        Ok(Self {
            device,
            parts,
            total: start,
        })
    }

    /// Hash every piece now, refusing the first that differs.
    pub fn verify_all(&mut self) -> Result<(), PayloadError> {
        (0..self.parts.len()).try_for_each(|index| self.verify(index))
    }

    /// Whether piece `index` has been verified.
    pub fn verified(&self, index: usize) -> bool {
        self.parts[index].state == State::Verified
    }

    fn verify(&mut self, index: usize) -> Result<(), PayloadError> {
        let refused = |part: &Part, reason| PayloadError::Verification {
            member: part.name.clone(),
            reason,
        };
        match self.parts[index].state {
            State::Verified => return Ok(()),
            State::Refused(reason) => return Err(refused(&self.parts[index], reason)),
            State::Unverified => {}
        }
        let mut hash = Sha256::new();
        let mut buffer = vec![0u8; HASH_CHUNK];
        let mut offset = 0u64;
        let bytes = self.parts[index].bytes;
        while offset < bytes {
            let count = (bytes - offset).min(HASH_CHUNK as u64) as usize;
            if let Err(error) = self.read_part(index, offset, &mut buffer[..count]) {
                return Err(match error {
                    PayloadError::Io(what) => {
                        PayloadError::Io(format!("{}: {what}", self.parts[index].name))
                    }
                    other => other,
                });
            }
            hash.update(&buffer[..count]);
            offset += count as u64;
        }
        let part = &mut self.parts[index];
        if hex::encode(hash.finalize()) != part.sha256 {
            part.state = State::Refused("its SHA-256 differs from payload.json");
            return Err(refused(part, "its SHA-256 differs from payload.json"));
        }
        part.state = State::Verified;
        Ok(())
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
                .map_err(PayloadError::io)?;
            buffer = &mut buffer[count..];
            offset += count as u64;
            at += 1;
        }
        Ok(())
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
            self.verify(index)?;
            let part = &self.parts[index];
            let within = offset - part.start;
            let count = (part.bytes - within).min(buffer.len() as u64) as usize;
            self.read_part(index, within, &mut buffer[..count])?;
            buffer = &mut buffer[count..];
            offset += count as u64;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::{Piece, piece_sizes, tests::Memory};

    /// A medium holding `ipsw` as pieces of `piece_bytes`, each scattered
    /// over two extents in reverse order, and its manifest.
    fn medium(ipsw: &[u8], piece_bytes: u64) -> (Memory, PayloadManifest, Vec<Vec<Extent>>) {
        let (mut manifest, _) = crate::payload::tests::manifest();
        manifest.source.bytes = ipsw.len() as u64;
        let mut device = vec![0xeeu8; 64];
        let mut pieces = Vec::new();
        let mut extents = Vec::new();
        let mut at = 0usize;
        for size in piece_sizes(ipsw.len() as u64, piece_bytes) {
            let bytes = &ipsw[at..at + size as usize];
            let half = bytes.len() / 2;
            let (head, tail) = bytes.split_at(half);
            let tail_offset = device.len() as u64;
            device.extend_from_slice(tail);
            device.extend_from_slice(&[0xee; 7]);
            let head_offset = device.len() as u64;
            device.extend_from_slice(head);
            let mut runs = Vec::new();
            if !head.is_empty() {
                runs.push(Extent {
                    offset: head_offset,
                    bytes: head.len() as u64,
                });
            }
            runs.push(Extent {
                offset: tail_offset,
                bytes: tail.len() as u64,
            });
            extents.push(runs);
            pieces.push(Piece {
                bytes: size,
                sha256: crate::sha256(bytes),
            });
            at += size as usize;
        }
        manifest.layout = Layout::Pieces { piece_bytes, pieces };
        manifest.validate().unwrap();
        (Memory(device), manifest, extents)
    }

    fn ipsw() -> Vec<u8> {
        (0..10_000u32).map(|i| (i * 7 ^ i >> 5) as u8).collect()
    }

    #[test]
    fn joined_pieces_read_as_the_ipsw_and_verify_each_piece_before_use() {
        let ipsw = ipsw();
        let (device, manifest, extents) = medium(&ipsw, 3000);
        let mut joined = Joined::new(device, &manifest, extents).unwrap();
        assert_eq!(joined.len(), ipsw.len() as u64);
        // Within one piece, then across all four.
        let mut buffer = vec![0; 100];
        joined.read_at(3100, &mut buffer).unwrap();
        assert_eq!(buffer, ipsw[3100..3200]);
        assert!(joined.verified(1));
        assert!(!joined.verified(0) && !joined.verified(2));
        let mut whole = vec![0; ipsw.len()];
        joined.read_at(0, &mut whole).unwrap();
        assert_eq!(whole, ipsw);
        let mut tail = vec![0; 1];
        assert!(joined.read_at(ipsw.len() as u64, &mut tail).is_err());
        joined.read_at(ipsw.len() as u64, &mut []).unwrap();
        joined.verify_all().unwrap();
    }

    #[test]
    fn an_altered_short_or_misplaced_piece_is_refused_by_name() {
        let ipsw = ipsw();
        let (mut device, manifest, extents) = medium(&ipsw, 3000);
        // Alter one byte of the third piece's head.
        device.0[extents[2][0].offset as usize] ^= 1;
        let mut joined = Joined::new(device, &manifest, extents.clone()).unwrap();
        let mut buffer = vec![0; 10];
        joined.read_at(0, &mut buffer).unwrap();
        let error = joined.read_at(6500, &mut buffer).unwrap_err().to_string();
        assert_eq!(error, "ipsw.002: its SHA-256 differs from payload.json");
        // The refusal stays, and a read spanning into it fails too.
        let error = joined.read_at(5995, &mut buffer).unwrap_err().to_string();
        assert!(error.starts_with("ipsw.002"), "{error}");
        assert!(joined.verify_all().is_err());

        let (device, manifest, mut short) = medium(&ipsw, 3000);
        short[3][0].bytes -= 1;
        let error = Joined::new(device, &manifest, short).err().unwrap();
        assert_eq!(
            error.to_string(),
            "ipsw.003: its size differs from payload.json"
        );
        let (device, manifest, mut outside) = medium(&ipsw, 3000);
        outside[0][0].offset = device.len();
        let error = Joined::new(device, &manifest, outside).err().unwrap();
        assert!(error.to_string().starts_with("ipsw.000"), "{error}");
        let (device, manifest, mut missing) = medium(&ipsw, 3000);
        missing.pop();
        assert!(Joined::new(device, &manifest, missing).is_err());
    }
}
