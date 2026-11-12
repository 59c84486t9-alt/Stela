//! A page record as the pack holds it, whose entries decode one at a time:
//! installing a block from the pack decodes that block's entry, not every
//! entry of its page.

use super::{
    Digest, ENTRY_MIN_BYTES, EXIT_BYTES, Entry, FormatError, HEADER_BYTES, RECORD_MAGIC,
    RECOVERY_BINDING_BYTES, RECOVERY_ROW_BYTES, RELOCATION_BYTES, Reader, Record, SCHEMA,
    SOURCE_MAP_BYTES, TRAILER_BYTES,
};
use alloc::{boxed::Box, vec::Vec};
use stela_crypto::Sha256;
use stela_crypto::digest::Digest as _;

/// The encoded records of one page key, earliest segment first, and the
/// index of their entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecord {
    pub translator: Digest,
    pub key: Digest,
    parts: Vec<Box<[u8]>>,
    /// Sorted by offset and context; of a pair two parts or one part twice
    /// hold, the first, as [`Record::merge`] and [`Record::decode`] keep.
    index: Vec<Indexed>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Indexed {
    offset: u16,
    context: Digest,
    part: u32,
    start: u32,
}

impl StoredRecord {
    pub fn new(translator: Digest, key: Digest) -> Self {
        Self {
            translator,
            key,
            parts: Vec::new(),
            index: Vec::new(),
        }
    }

    /// The record `record` holds, encoded.
    pub fn of(record: &Record) -> Self {
        let mut stored = Self::new(record.translator, record.key);
        stored
            .add(&record.encode(), false)
            .expect("an encoded record indexes");
        stored
    }

    /// Add the encoded record `bytes`, a later segment's than those added:
    /// its header checked as [`Record::decode_checked`] checks it and its
    /// entries indexed. With `check`, its hash and each entry are checked
    /// whole, as a first decode does; without, the entries' bounds.
    pub fn add(&mut self, bytes: &[u8], check: bool) -> Result<(), FormatError> {
        if bytes.len() < HEADER_BYTES + TRAILER_BYTES {
            return Err(FormatError::Truncated);
        }
        let (body, trailer) = bytes.split_at(bytes.len() - TRAILER_BYTES);
        let mut reader = Reader(body);
        if reader.take(8)? != RECORD_MAGIC {
            return Err(FormatError::Magic);
        }
        if reader.u32()? != SCHEMA {
            return Err(FormatError::Schema);
        }
        let count = reader.u32()? as usize;
        if reader.digest()? != self.translator {
            return Err(FormatError::Translator);
        }
        if reader.digest()? != self.key {
            return Err(FormatError::Key);
        }
        if reader.u64()? != bytes.len() as u64 {
            return Err(FormatError::Truncated);
        }
        if check && Sha256::digest(body).as_slice() != trailer {
            return Err(FormatError::Checksum);
        }
        if count > reader.0.len() / ENTRY_MIN_BYTES {
            return Err(FormatError::Truncated);
        }
        let part = u32::try_from(self.parts.len()).map_err(|_| FormatError::Capacity)?;
        let mut added = Vec::new();
        added
            .try_reserve_exact(count)
            .map_err(|_| FormatError::Capacity)?;
        for _ in 0..count {
            let start =
                u32::try_from(body.len() - reader.0.len()).map_err(|_| FormatError::Entry)?;
            let (offset, context) = if check {
                let entry = reader.entry()?;
                if !entry.consistent() {
                    return Err(FormatError::Entry);
                }
                (entry.offset, entry.context)
            } else {
                reader.skip_entry()?
            };
            added.push(Indexed {
                offset,
                context,
                part,
                start,
            });
        }
        if !reader.0.is_empty() {
            return Err(FormatError::Entry);
        }
        self.parts.push(Box::from(body));
        // Stable: the first of a pair stays first, and dedup keeps it.
        self.index.extend(added);
        self.index
            .sort_by_key(|entry| (entry.offset, entry.context, entry.part, entry.start));
        self.index
            .dedup_by_key(|entry| (entry.offset, entry.context));
        Ok(())
    }

    /// The entry at `offset` in `context`, decoded: `None` when the record
    /// holds none, or its bytes do not decode.
    pub fn find(&self, offset: u16, context: &Digest) -> Option<Entry> {
        let at = self
            .index
            .binary_search_by(|entry| (entry.offset, &entry.context).cmp(&(offset, context)))
            .ok()?;
        let Indexed { part, start, .. } = self.index[at];
        let body = self.parts.get(part as usize)?;
        Reader(body.get(start as usize..)?).entry().ok()
    }

    /// The entries it holds.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Every entry, decoded, in offset and context order.
    pub fn record(&self) -> Result<Record, FormatError> {
        let mut record = Record::new(self.translator, self.key);
        for indexed in &self.index {
            let body = self
                .parts
                .get(indexed.part as usize)
                .ok_or(FormatError::Entry)?;
            let entry = Reader(
                body.get(indexed.start as usize..)
                    .ok_or(FormatError::Entry)?,
            )
            .entry()?;
            record.entries.push(entry);
        }
        Ok(record)
    }

    /// The heap bytes it holds.
    pub fn retained_bytes(&self) -> usize {
        let parts: usize = self.parts.iter().map(|part| part.len()).sum();
        core::mem::size_of::<Self>()
            + parts
            + self.parts.capacity() * core::mem::size_of::<Box<[u8]>>()
            + self.index.capacity() * core::mem::size_of::<Indexed>()
    }
}

impl Reader<'_> {
    /// Pass over an entry as [`Reader::entry`] reads it, allocating
    /// nothing: its offset and context.
    pub(super) fn skip_entry(&mut self) -> Result<(u16, Digest), FormatError> {
        let context = self.digest()?;
        let offset = self.u16()?;
        let _source_bytes = self.u16()?;
        let input_bytes = usize::from(self.u16()?);
        if input_bytes > super::PAGE_BYTES {
            return Err(FormatError::Entry);
        }
        self.take(input_bytes)?;
        let code_bytes = self.u32()? as usize;
        for item in [RELOCATION_BYTES, SOURCE_MAP_BYTES, EXIT_BYTES] {
            let count = self.count(item)?;
            self.take(count * item)?;
        }
        let rows = self.count(RECOVERY_ROW_BYTES)?;
        for _ in 0..rows {
            self.take(RECOVERY_ROW_BYTES - 4)?;
            let bindings = self.count(RECOVERY_BINDING_BYTES)?;
            self.take(bindings * RECOVERY_BINDING_BYTES)?;
        }
        self.take(code_bytes)?;
        Ok((offset, context))
    }
}
