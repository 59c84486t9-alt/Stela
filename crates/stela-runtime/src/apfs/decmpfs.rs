//! Transparent file compression (decmpfs), as APFS stores it for files
//! with `UF_COMPRESSED`: a `com.apple.decmpfs` attribute holding a header
//! (`fpmc`, the compression type, the uncompressed size) and either the
//! compressed data itself or, for the resource-fork types, a
//! `com.apple.ResourceFork` attribute holding it in 64 KiB chunks.
//!
//! Types, after Apple's open-source `decmpfs.h` and the `hfs` and `apfs`
//! readers that implement them:
//!
//! | type | data | codec |
//! | --- | --- | --- |
//! | 1 | attribute | none |
//! | 3, 4 | attribute, resource fork | zlib |
//! | 7, 8 | attribute, resource fork | LZVN |
//! | 11, 12 | attribute, resource fork | LZFSE |
//!
//! A zlib resource fork is a classic resource fork whose one `cmpf`
//! resource lists each chunk's offset and size; LZVN and LZFSE forks start
//! with a table of chunk offsets. A chunk whose first byte is the codec's
//! stored marker (`0x0f` in a zlib header's low nibble, `0x06` for LZVN,
//! `0xff` for LZFSE) holds its bytes after that byte. Every chunk but the
//! last decodes to exactly 64 KiB, and the whole to exactly the header's
//! size. Other types are refused by number.
use super::{ApfsError, Result};
use alloc::{vec, vec::Vec};

/// The attribute holding the header.
pub const ATTRIBUTE: &str = "com.apple.decmpfs";
/// The attribute holding a resource-fork type's data.
pub const RESOURCE_FORK: &str = "com.apple.ResourceFork";
const MAGIC: &[u8; 4] = b"fpmc";
const HEADER_BYTES: usize = 16;
const CHUNK_BYTES: usize = 64 * 1024;
/// The largest file this reader inflates.
pub const MAX_BYTES: u64 = 1 << 32;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Codec {
    None,
    Zlib,
    Lzvn,
    Lzfse,
}

/// The codec and whether the data is in the resource fork.
fn kind(header: &[u8]) -> Result<(Codec, bool, usize)> {
    if header.len() < HEADER_BYTES || &header[..4] != MAGIC {
        return Err(ApfsError::Malformed("decmpfs header"));
    }
    let kind = u32::from_le_bytes(header[4..8].try_into().expect("4 bytes"));
    let size = u64::from_le_bytes(header[8..16].try_into().expect("8 bytes"));
    if size > MAX_BYTES {
        return Err(ApfsError::Unsupported("decmpfs files above 4 GiB"));
    }
    let (codec, fork) = match kind {
        1 => (Codec::None, false),
        3 => (Codec::Zlib, false),
        4 => (Codec::Zlib, true),
        7 => (Codec::Lzvn, false),
        8 => (Codec::Lzvn, true),
        11 => (Codec::Lzfse, false),
        12 => (Codec::Lzfse, true),
        _ => return Err(ApfsError::Unsupported("this decmpfs compression type")),
    };
    Ok((codec, fork, size as usize))
}

/// Whether the header's data is in the resource fork.
pub fn in_resource_fork(header: &[u8]) -> Result<bool> {
    kind(header).map(|(_, fork, _)| fork)
}

/// One chunk, decoding to exactly `bytes`.
fn chunk(codec: Codec, data: &[u8], bytes: usize) -> Result<Vec<u8>> {
    let stored = match codec {
        Codec::None => Some(data),
        Codec::Zlib => (data.first().is_some_and(|b| b & 0x0f == 0x0f)).then(|| &data[1..]),
        Codec::Lzvn => (data.first() == Some(&0x06)).then(|| &data[1..]),
        Codec::Lzfse => (data.first() == Some(&0xff)).then(|| &data[1..]),
    };
    let decoded = match (stored, codec) {
        (Some(stored), _) => stored.get(..bytes).map(<[u8]>::to_vec),
        (None, Codec::Zlib) => {
            miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(data, bytes).ok()
        }
        (None, Codec::Lzvn) => crate::lzfse::decode_lzvn(data, bytes).ok(),
        (None, Codec::Lzfse) => crate::lzfse::decode(data, bytes).ok(),
        (None, Codec::None) => unreachable!("stored above"),
    };
    match decoded {
        Some(decoded) if decoded.len() == bytes => Ok(decoded),
        _ => Err(ApfsError::Malformed(
            "decmpfs chunk does not decode to its size",
        )),
    }
}

fn u32_le(bytes: &[u8], at: usize) -> Result<u32> {
    bytes
        .get(at..at + 4)
        .map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")))
        .ok_or(ApfsError::Malformed("decmpfs resource fork"))
}

fn u32_be(bytes: &[u8], at: usize) -> Result<u32> {
    bytes
        .get(at..at + 4)
        .map(|b| u32::from_be_bytes(b.try_into().expect("4 bytes")))
        .ok_or(ApfsError::Malformed("decmpfs resource fork"))
}

/// The resource fork's chunks, as byte ranges of `fork`.
fn chunks(codec: Codec, fork: &[u8], count: usize) -> Result<Vec<(usize, usize)>> {
    let mut ranges = Vec::with_capacity(count);
    if codec == Codec::Zlib {
        // A resource fork header (big-endian data offset), the resource's
        // length, then the `cmpf` block table, little-endian, its offsets
        // from the table's start.
        let table = (u32_be(fork, 0)? as usize)
            .checked_add(4)
            .ok_or(ApfsError::Malformed("decmpfs resource fork"))?;
        if u32_le(fork, table)? as usize != count {
            return Err(ApfsError::Malformed("decmpfs chunk count"));
        }
        for i in 0..count {
            let offset = u32_le(fork, table + 4 + 8 * i)? as usize;
            let size = u32_le(fork, table + 8 + 8 * i)? as usize;
            ranges.push((table + offset, table + offset + size));
        }
    } else {
        // `count + 1` little-endian offsets from the fork's start.
        if u32_le(fork, 0)? as usize != (count + 1) * 4 {
            return Err(ApfsError::Malformed("decmpfs chunk count"));
        }
        for i in 0..count {
            ranges.push((
                u32_le(fork, 4 * i)? as usize,
                u32_le(fork, 4 * (i + 1))? as usize,
            ));
        }
    }
    if ranges
        .iter()
        .any(|&(start, end)| start > end || end > fork.len())
    {
        return Err(ApfsError::Malformed(
            "decmpfs chunk outside the resource fork",
        ));
    }
    Ok(ranges)
}

/// The file's bytes from its decmpfs `header` and, for a resource-fork
/// type, its resource `fork`.
pub fn decode(header: &[u8], fork: Option<&[u8]>) -> Result<Vec<u8>> {
    let (codec, in_fork, size) = kind(header)?;
    if !in_fork {
        if size == 0 {
            return Ok(Vec::new());
        }
        return chunk(codec, &header[HEADER_BYTES..], size);
    }
    let fork = fork.ok_or(ApfsError::Malformed("decmpfs resource fork missing"))?;
    let count = size.div_ceil(CHUNK_BYTES);
    let mut bytes = vec![];
    bytes
        .try_reserve_exact(size)
        .map_err(|_| ApfsError::Unsupported("decmpfs file larger than memory"))?;
    for (i, (start, end)) in chunks(codec, fork, count)?.into_iter().enumerate() {
        let want = (size - i * CHUNK_BYTES).min(CHUNK_BYTES);
        bytes.extend(chunk(codec, &fork[start..end], want)?);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(kind: u32, size: u64) -> Vec<u8> {
        [MAGIC.as_slice(), &kind.to_le_bytes(), &size.to_le_bytes()].concat()
    }

    /// A stored LZVN chunk of `bytes`.
    fn lzvn_stored(bytes: &[u8]) -> Vec<u8> {
        [&[0x06][..], bytes].concat()
    }

    #[test]
    fn attribute_types_inflate_to_their_size() {
        let text = b"stela decmpfs".repeat(50);
        let zlib = miniz_oxide::deflate::compress_to_vec_zlib(&text, 6);
        let mut attribute = header(3, text.len() as u64);
        attribute.extend(&zlib);
        assert!(!in_resource_fork(&attribute).unwrap());
        assert_eq!(decode(&attribute, None).unwrap(), text);
        // Stored zlib: the low nibble marker, then the bytes.
        let attribute = [header(3, 5), vec![0xff], b"stela".to_vec()].concat();
        assert_eq!(decode(&attribute, None).unwrap(), b"stela");
        let attribute = [header(1, 5), b"stela".to_vec()].concat();
        assert_eq!(decode(&attribute, None).unwrap(), b"stela");
        // A size the data does not reach, or an unknown type, is refused.
        let attribute = [header(1, 6), b"stela".to_vec()].concat();
        assert!(decode(&attribute, None).is_err());
        let error = decode(&header(5, 1), None).unwrap_err();
        assert_eq!(
            error,
            ApfsError::Unsupported("this decmpfs compression type")
        );
        assert!(decode(b"fpmx\0\0\0\0\0\0\0\0\0\0\0\0", None).is_err());
    }

    #[test]
    fn resource_forks_inflate_chunk_by_chunk() {
        let data: Vec<u8> = (0..CHUNK_BYTES + 100).map(|i| (i % 251) as u8).collect();
        let (first, second) = data.split_at(CHUNK_BYTES);

        // LZVN: an offset table from the fork's start.
        let chunks = [lzvn_stored(first), lzvn_stored(second)];
        let table = 12u32;
        let fork = [
            &table.to_le_bytes()[..],
            &(table + chunks[0].len() as u32).to_le_bytes(),
            &(table + (chunks[0].len() + chunks[1].len()) as u32).to_le_bytes(),
            &chunks[0],
            &chunks[1],
        ]
        .concat();
        let attribute = header(8, data.len() as u64);
        assert!(in_resource_fork(&attribute).unwrap());
        assert_eq!(decode(&attribute, Some(&fork)).unwrap(), data);
        assert!(decode(&attribute, None).is_err());
        assert!(decode(&attribute, Some(&fork[..fork.len() - 1])).is_err());

        // zlib: a resource fork header, then the `cmpf` table.
        let compressed = [
            miniz_oxide::deflate::compress_to_vec_zlib(first, 6),
            miniz_oxide::deflate::compress_to_vec_zlib(second, 6),
        ];
        let data_offset = 0x100usize;
        let table_bytes = 4 + 8 * 2;
        let mut fork = vec![0u8; data_offset];
        fork[..4].copy_from_slice(&(data_offset as u32).to_be_bytes());
        let length = table_bytes + compressed[0].len() + compressed[1].len();
        fork.extend((length as u32).to_be_bytes());
        fork.extend(2u32.to_le_bytes());
        fork.extend((table_bytes as u32).to_le_bytes());
        fork.extend((compressed[0].len() as u32).to_le_bytes());
        fork.extend(((table_bytes + compressed[0].len()) as u32).to_le_bytes());
        fork.extend((compressed[1].len() as u32).to_le_bytes());
        fork.extend(&compressed[0]);
        fork.extend(&compressed[1]);
        let attribute = header(4, data.len() as u64);
        assert_eq!(decode(&attribute, Some(&fork)).unwrap(), data);
        // A chunk short of 64 KiB is refused.
        let attribute = header(4, data.len() as u64 + 1);
        assert!(decode(&attribute, Some(&fork)).is_err());
    }
}
