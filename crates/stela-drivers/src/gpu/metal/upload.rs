//! Upload memory of one command buffer: argument tables, `set*Bytes` data
//! and small transfer sources, placed in host-visible chunks the GPU reads
//! by device address.
//!
//! Encoding needs each upload's address immediately, so space is
//! suballocated from chunks as commands are encoded and the bytes are kept
//! per chunk until commit, when the device copies them into the chunks'
//! mapped memory. Chunks return to the device's pool once the command
//! buffer completes.
use super::{
    error::{Error, Result},
    vulkan::object::Buffer,
};
use alloc::vec::Vec;

/// Chunks are at least this large; bigger uploads get a chunk of their own.
pub const CHUNK_BYTES: u64 = 64 << 10;

/// A host-visible buffer with a device address, from the device's pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Chunk {
    pub buffer: Buffer,
    pub address: u64,
    pub size: u64,
}

/// The device's chunk pool.
pub trait ChunkSource {
    /// A free chunk of at least `bytes`.
    fn acquire(&mut self, bytes: u64) -> Result<Chunk>;
}

/// Where an upload landed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Upload {
    pub buffer: Buffer,
    pub offset: u64,
    pub address: u64,
}

#[derive(Debug, Default)]
pub struct UploadArena {
    /// Chunks in use, each with the bytes written so far.
    chunks: Vec<(Chunk, Vec<u8>)>,
}

impl UploadArena {
    pub fn write(
        &mut self,
        source: &mut dyn ChunkSource,
        bytes: &[u8],
        alignment: u64,
    ) -> Result<Upload> {
        debug_assert!(alignment.is_power_of_two());
        let length = bytes.len() as u64;
        let fits = |(chunk, data): &(Chunk, Vec<u8>)| {
            let offset = (data.len() as u64).next_multiple_of(alignment);
            (offset + length <= chunk.size).then_some(offset)
        };
        let offset = match self.chunks.last().and_then(fits) {
            Some(offset) => offset,
            None => {
                let chunk = source.acquire(length.max(CHUNK_BYTES))?;
                if chunk.size < length || !chunk.address.is_multiple_of(alignment) {
                    return Err(Error::OutOfMemory);
                }
                self.chunks.push((chunk, Vec::new()));
                0
            }
        };
        let (chunk, data) = self.chunks.last_mut().expect("a chunk was just ensured");
        data.resize(offset as usize, 0);
        data.extend_from_slice(bytes);
        Ok(Upload {
            buffer: chunk.buffer,
            offset,
            address: chunk.address + offset,
        })
    }

    /// The chunks and the bytes to copy into each before submission.
    pub fn finish(self) -> Vec<(Chunk, Vec<u8>)> {
        self.chunks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Pool {
        next: u64,
    }

    impl ChunkSource for Pool {
        fn acquire(&mut self, bytes: u64) -> Result<Chunk> {
            self.next += 1;
            Ok(Chunk {
                buffer: Buffer(self.next),
                address: self.next << 32,
                size: bytes,
            })
        }
    }

    #[test]
    fn uploads_suballocate_aligned_and_spill_to_new_chunks() {
        let mut pool = Pool::default();
        let mut arena = UploadArena::default();
        let first = arena.write(&mut pool, &[1; 10], 16).unwrap();
        let second = arena.write(&mut pool, &[2; 4], 16).unwrap();
        assert_eq!((first.offset, second.offset), (0, 16));
        assert_eq!(second.address, (1 << 32) + 16);
        let big = arena
            .write(&mut pool, &alloc::vec![3; CHUNK_BYTES as usize + 1], 16)
            .unwrap();
        assert_eq!((big.buffer, big.offset), (Buffer(2), 0));
        let after = arena.write(&mut pool, &[4], 4).unwrap();
        assert_eq!(after.buffer, Buffer(3), "a full chunk is not reused");
        let chunks = arena.finish();
        assert_eq!(chunks.len(), 3);
        assert_eq!(
            &chunks[0].1[..],
            &[[1; 10].as_slice(), &[0; 6], &[2; 4]].concat()[..]
        );
    }
}
