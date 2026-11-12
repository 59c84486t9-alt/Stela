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

    /// An LZ4-class block codec, for measuring only: greedy matches of at
    /// least four bytes found by a hash of the next four, a token of literal
    /// and match lengths, a 16-bit offset.
    fn lz_compress(input: &[u8]) -> Vec<u8> {
        const HASH_BITS: u32 = 13;
        let mut table = vec![0u32; 1 << HASH_BITS];
        let mut out = Vec::with_capacity(input.len() / 2);
        let hash = |at: usize| {
            let word = u32::from_le_bytes(input[at..at + 4].try_into().unwrap());
            (word.wrapping_mul(2_654_435_761) >> (32 - HASH_BITS)) as usize
        };
        let length = |out: &mut Vec<u8>, mut rest: usize| {
            while rest >= 255 {
                out.push(255);
                rest -= 255;
            }
            out.push(rest as u8);
        };
        let (mut at, mut anchor) = (0, 0);
        while at + 12 <= input.len() {
            let slot = hash(at);
            let candidate = table[slot] as usize;
            table[slot] = at as u32;
            if candidate >= at
                || at - candidate > 0xffff
                || input[candidate..candidate + 4] != input[at..at + 4]
            {
                at += 1;
                continue;
            }
            let mut matched = 4;
            while at + matched < input.len() - 5
                && input[candidate + matched] == input[at + matched]
            {
                matched += 1;
            }
            let literals = at - anchor;
            let token_lit = literals.min(15) as u8;
            let token_match = (matched - 4).min(15) as u8;
            out.push(token_lit << 4 | token_match);
            if literals >= 15 {
                length(&mut out, literals - 15);
            }
            out.extend_from_slice(&input[anchor..at]);
            out.extend_from_slice(&((at - candidate) as u16).to_le_bytes());
            if matched - 4 >= 15 {
                length(&mut out, matched - 4 - 15);
            }
            at += matched;
            anchor = at;
        }
        let literals = input.len() - anchor;
        out.push((literals.min(15) as u8) << 4);
        if literals >= 15 {
            length(&mut out, literals - 15);
        }
        out.extend_from_slice(&input[anchor..]);
        out
    }

    fn lz_decompress(input: &[u8], out: &mut Vec<u8>) {
        out.clear();
        let mut at = 0;
        let length = |at: &mut usize| {
            let mut total = 0;
            loop {
                let byte = input[*at];
                *at += 1;
                total += usize::from(byte);
                if byte != 255 {
                    return total;
                }
            }
        };
        loop {
            let token = input[at];
            at += 1;
            let mut literals = usize::from(token >> 4);
            if literals == 15 {
                literals += length(&mut at);
            }
            out.extend_from_slice(&input[at..at + literals]);
            at += literals;
            if at == input.len() {
                return;
            }
            let offset = usize::from(u16::from_le_bytes([input[at], input[at + 1]]));
            at += 2;
            let mut matched = usize::from(token & 15);
            if matched == 15 {
                matched += length(&mut at);
            }
            matched += 4;
            let start = out.len() - offset;
            if offset >= matched {
                out.extend_from_within(start..start + matched);
            } else {
                for index in 0..matched {
                    out.push(out[start + index]);
                }
            }
        }
    }

    #[test]
    fn the_measuring_codec_round_trips() {
        let mut raw = Vec::new();
        for n in 0u32..5000 {
            raw.extend_from_slice(&(n % 97).to_le_bytes());
            raw.extend_from_slice(b"mov rax, [rbp+8]");
        }
        let packed = lz_compress(&raw);
        assert!(packed.len() < raw.len() / 4);
        let mut out = Vec::new();
        lz_decompress(&packed, &mut out);
        assert_eq!(out, raw);
        for raw in [&b""[..], b"abc", &[7u8; 100][..]] {
            lz_decompress(&lz_compress(raw), &mut out);
            assert_eq!(out, raw);
        }
    }

    /// Records of a pack file named by `STELA_PACK_SAMPLE` (a single pack:
    /// header, index of key, offset and length, records), compressed with
    /// the measuring LZ codec and with DEFLATE level 1: sizes, and decode
    /// time against the record's raw parse.
    #[test]
    #[ignore = "manual: opt-in"]
    fn codec_costs() {
        let Ok(path) = std::env::var("STELA_PACK_SAMPLE") else {
            std::println!("STELA_PACK_SAMPLE names no pack");
            return;
        };
        use std::io::{Read, Seek, SeekFrom};
        let mut file = std::fs::File::open(path).unwrap();
        let mut header = [0u8; 48];
        file.read_exact(&mut header).unwrap();
        let count = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
        let mut index = vec![0u8; count * 48];
        file.read_exact(&mut index).unwrap();
        let field = |at: usize| u64::from_le_bytes(index[at..at + 8].try_into().unwrap());
        // Every 8th record, read one at a time: a few hundred MB stay on disk.
        let records: Vec<Vec<u8>> = (0..count)
            .step_by(8)
            .map(|entry| {
                let at = entry * 48;
                let (offset, length) = (field(at + 32), field(at + 40) & ((1 << 56) - 1));
                let mut record = vec![0u8; length as usize];
                file.seek(SeekFrom::Start(offset)).unwrap();
                file.read_exact(&mut record).unwrap();
                record
            })
            .collect();
        let count = records.len();
        let raw: usize = records.iter().map(Vec::len).sum();
        let mut out = Vec::new();
        let (mut lz, mut deflate, mut lz_ns, mut inflate_ns, mut copy_ns) =
            (0, 0, 0u128, 0u128, 0u128);
        let mut scratch = DecodeScratch::default();
        for record in &records {
            let packed = lz_compress(record);
            lz += packed.len();
            let started = std::time::Instant::now();
            lz_decompress(&packed, &mut out);
            lz_ns += started.elapsed().as_nanos();
            assert_eq!(out, record.as_slice());
            let started = std::time::Instant::now();
            out.clear();
            out.extend_from_slice(record);
            copy_ns += started.elapsed().as_nanos();
            let mut stored = MAGIC.to_vec();
            stored.extend_from_slice(&(record.len() as u32).to_le_bytes());
            stored.extend(miniz_oxide::deflate::compress_to_vec(record, 1));
            deflate += stored.len();
            if record.len() <= MAX_EXPANDED_BYTES && stored.len() < record.len() {
                let started = std::time::Instant::now();
                assert_eq!(scratch.inflate(&stored).unwrap(), record.as_slice());
                inflate_ns += started.elapsed().as_nanos();
            }
        }
        let per = |ns: u128| ns / count as u128;
        std::println!(
            "{count} records, {raw} bytes ({} per record): LZ {lz} bytes ({}%), decode {} ns a \
             record; DEFLATE-1 {deflate} bytes ({}%), decode {} ns; copy {} ns",
            raw / count,
            lz * 100 / raw,
            per(lz_ns),
            deflate * 100 / raw,
            per(inflate_ns),
            per(copy_ns)
        );
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
