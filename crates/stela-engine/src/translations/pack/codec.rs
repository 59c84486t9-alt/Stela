use alloc::vec::Vec;
use miniz_oxide::inflate::{
    TINFLStatus,
    core::{
        DecompressorOxide, decompress, inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    },
};

use super::super::{HEADER_BYTES as RECORD_HEADER, TRAILER_BYTES};

/// A versioned envelope for raw DEFLATE of a complete page record.
pub(super) const MAGIC: &[u8; 8] = b"STLTPZF1";
pub(super) const HEADER_BYTES: usize = MAGIC.len() + 4;
pub(super) const MAX_EXPANDED_BYTES: usize = 512 << 10;
const MAX_RETAINED_BYTES: usize = 128 << 10;

#[derive(Debug, Default)]
pub struct DecodeScratch(Vec<u8>);

impl DecodeScratch {
    /// Keep one bounded buffer. The caller can release the displaced storage
    /// outside the store lock.
    pub(super) fn retain(&mut self, returned: &mut Self) {
        let capacity = returned.0.capacity();
        if capacity > self.0.capacity() && capacity <= MAX_RETAINED_BYTES {
            core::mem::swap(self, returned);
        }
    }

    pub(super) fn inflate(&mut self, stored: &[u8]) -> Result<&[u8], DecodeError> {
        let (header, input) = stored
            .split_at_checked(HEADER_BYTES)
            .ok_or(DecodeError::Invalid)?;
        let size = u32::from_le_bytes(header[MAGIC.len()..].try_into().expect("a length")) as usize;
        if !(RECORD_HEADER + TRAILER_BYTES..=MAX_EXPANDED_BYTES).contains(&size)
            || stored.len() >= size
        {
            return Err(DecodeError::Invalid);
        }
        self.0.clear();
        self.0
            .try_reserve_exact(size)
            .map_err(|_| DecodeError::Capacity)?;
        self.0.resize(size, 0);
        inflate(input, &mut self.0)?;
        Ok(&self.0)
    }
}

/// Keep the inflater's stack frame off the raw record path.
#[inline(never)]
fn inflate(input: &[u8], output: &mut [u8]) -> Result<(), DecodeError> {
    let mut decoder = DecompressorOxide::new();
    let (status, consumed, produced) = decompress(
        &mut decoder,
        input,
        output,
        0,
        TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    );
    if status != TINFLStatus::Done || consumed != input.len() || produced != output.len() {
        return Err(DecodeError::Invalid);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Invalid,
    Capacity,
}

#[cfg(test)]
pub(super) fn test_envelope(raw: &[u8]) -> Vec<u8> {
    let mut stored = MAGIC.to_vec();
    stored.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    stored.extend(miniz_oxide::deflate::compress_to_vec(raw, 1));
    stored
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn compressed_framing_requires_exact_input_output_and_bounded_scratch() {
        let raw = vec![0; 8192];
        let mut stored = test_envelope(&raw);
        let mut scratch = DecodeScratch::default();
        assert_eq!(scratch.inflate(&stored).unwrap(), raw);
        assert_eq!(
            scratch.inflate(&stored[..stored.len() - 1]),
            Err(DecodeError::Invalid)
        );
        stored.push(0);
        assert_eq!(scratch.inflate(&stored), Err(DecodeError::Invalid));
        stored.pop();
        for size in [8191, 8193, u32::MAX] {
            stored[MAGIC.len()..HEADER_BYTES].copy_from_slice(&size.to_le_bytes());
            assert_eq!(scratch.inflate(&stored), Err(DecodeError::Invalid));
        }
        let capacity = scratch.0.capacity();
        assert_eq!(scratch.inflate(&stored), Err(DecodeError::Invalid));
        assert_eq!(scratch.0.capacity(), capacity);
    }

    #[test]
    fn scratch_recycler_does_not_keep_oversized_buffers() {
        let mut kept = DecodeScratch::default();
        let mut normal = DecodeScratch(Vec::with_capacity(4096));
        kept.retain(&mut normal);
        assert_eq!(normal.0.capacity(), 0);
        let mut oversized = DecodeScratch(Vec::with_capacity(MAX_RETAINED_BYTES + 1));
        kept.retain(&mut oversized);
        assert_eq!(kept.0.capacity(), 4096);
        assert!(oversized.0.capacity() > MAX_RETAINED_BYTES);
    }
}
