//! The part of a pack segment a boot reads when its RAM holds less than
//! all of it.
use sha2::{Digest as _, Sha256};
use stela_engine::translations::{
    Digest,
    pack::{self, HEADER_BYTES, Pack, PackError},
};

/// A pack index entry's bytes: page key, offset from the pack's start and
/// length.
const INDEX_ENTRY_BYTES: usize = 32 + 8 + 8;
/// The SHA-256 of the header and index that follows the index.
const CHECKSUM_BYTES: usize = 32;
/// Where the header holds the record count: after the magic and schema.
const COUNT_AT: usize = 12;

/// What a reader that holds at most a budget's bytes reads of a pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Within {
    /// The pack's first bytes to read: its index and every record that ends
    /// within the budget.
    pub length: u64,
    /// The records that end within the budget, and the others.
    pub records: usize,
    pub omitted: usize,
}

/// What to read of the pack whose header, index and index checksum are
/// `prefix` (`pack::prefix_bytes`) to hold at most `limit` bytes of it. A
/// pack's records lie anywhere after its index, so its first bytes up to the
/// last end within `limit` hold every record that ends within it: a usable
/// pack once [`trim`] names only those. `Err` when the index fails the
/// checks `Pack::parse` makes of it; a [`Within::length`] past `limit` when
/// the index alone passes it.
pub fn within(prefix: &[u8], translator: &Digest, limit: u64) -> Result<Within, PackError> {
    Pack::length(prefix, translator)?;
    let start = pack::prefix_bytes(prefix, translator)?;
    let count = (start - HEADER_BYTES - CHECKSUM_BYTES) / INDEX_ENTRY_BYTES;
    let mut within = Within {
        length: start as u64,
        records: 0,
        omitted: 0,
    };
    for index in 0..count {
        let (offset, bytes) = entry(prefix, index);
        // `Pack::length` checked that the sum does not overflow.
        let end = offset + bytes;
        if end <= limit {
            within.records += 1;
            within.length = within.length.max(end);
        } else {
            within.omitted += 1;
        }
    }
    Ok(within)
}

/// Make the index at the start of `pack`, a pack's first bytes whose index
/// [`within`] checked, name only the records that lie inside them, with its
/// count and checksum to match and zeros for the rest of its old room. The
/// records keep their offsets. Returns the records it names.
pub fn trim(pack: &mut [u8]) -> usize {
    let count = u32::from_le_bytes(
        pack[COUNT_AT..COUNT_AT + 4]
            .try_into()
            .expect("a count word"),
    ) as usize;
    let old_end = HEADER_BYTES + count * INDEX_ENTRY_BYTES + CHECKSUM_BYTES;
    assert!(old_end <= pack.len(), "a checked index inside the pack");
    let mut kept = 0;
    for index in 0..count {
        let (offset, bytes) = entry(pack, index);
        if offset
            .checked_add(bytes)
            .is_some_and(|end| end <= pack.len() as u64)
        {
            let from = HEADER_BYTES + index * INDEX_ENTRY_BYTES;
            pack.copy_within(
                from..from + INDEX_ENTRY_BYTES,
                HEADER_BYTES + kept * INDEX_ENTRY_BYTES,
            );
            kept += 1;
        }
    }
    pack[COUNT_AT..COUNT_AT + 4].copy_from_slice(&(kept as u32).to_le_bytes());
    let index_end = HEADER_BYTES + kept * INDEX_ENTRY_BYTES;
    let checksum = Sha256::digest(&pack[..index_end]);
    pack[index_end..index_end + CHECKSUM_BYTES].copy_from_slice(&checksum);
    pack[index_end + CHECKSUM_BYTES..old_end].fill(0);
    kept
}

/// Index entry `index`'s record offset and length (the length field less
/// the record's age, `pack::LENGTH_MASK`).
fn entry(pack: &[u8], index: usize) -> (u64, u64) {
    let at = HEADER_BYTES + index * INDEX_ENTRY_BYTES + 32;
    let field = |at: usize| u64::from_le_bytes(pack[at..at + 8].try_into().expect("a field"));
    (field(at), field(at + 8) & pack::LENGTH_MASK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_engine::machine::Translations as _;
    use stela_engine::translations::pack::{Layout, Piece};

    /// A pack of 40 valid, empty records of `translator`, in key order.
    fn sample(translator: Digest) -> Vec<u8> {
        use stela_engine::translations::Record;
        let records = (0u8..40)
            .map(|index| {
                let key = Digest::of(&[index]);
                (key, Piece::New(Record::new(translator, key).encode()))
            })
            .collect();
        Layout::new(&translator, records).to_vec()
    }

    #[test]
    fn a_pack_larger_than_the_budget_is_read_as_its_records_within_it() {
        use stela_engine::translations::pack::Store;
        let translator = Digest::of(b"translator");
        let bytes = sample(translator);
        let full = Pack::parse(&bytes, &translator).unwrap();
        let header = &bytes[..HEADER_BYTES];
        let prefix = &bytes[..pack::prefix_bytes(header, &translator).unwrap()];
        // The whole pack within a budget its size or more.
        let whole = within(prefix, &translator, bytes.len() as u64).unwrap();
        assert_eq!(
            whole,
            Within {
                length: bytes.len() as u64,
                records: 40,
                omitted: 0
            }
        );
        // A budget that cuts the records: the bytes up to the last record
        // ending within it, and the rest left out.
        let limit = (prefix.len() + (bytes.len() - prefix.len()) / 2) as u64;
        let part = within(prefix, &translator, limit).unwrap();
        assert!(part.length <= limit && part.length > prefix.len() as u64);
        assert!(part.records > 0 && part.omitted > 0);
        assert_eq!(part.records + part.omitted, 40);
        let mut read = bytes[..part.length as usize].to_vec();
        // Untrimmed, the index names records past the bytes read.
        assert!(Pack::parse(&read, &translator).is_err());
        assert_eq!(trim(&mut read), part.records);
        let trimmed = Pack::parse(&read, &translator).unwrap();
        assert_eq!(trimmed.records(), part.records);
        assert_eq!(trimmed.bytes() as u64, part.length);
        // Each record read is the pack's, at its offset; the others are
        // absent, as a key the pack never held.
        for (key, record) in full.iter() {
            match trimmed.get(&key) {
                Some(kept) => {
                    assert_eq!(kept, record);
                    let at = |slice: &[u8], base: &[u8]| {
                        slice.as_ptr() as usize - base.as_ptr() as usize
                    };
                    assert_eq!(at(kept, &read), at(record, &bytes));
                }
                None => assert!(at_least_past(record, &bytes, part.length)),
            }
        }
        // A store over the part finds each record it holds.
        let mut store = Store::new(translator, Some(&read)).0;
        for (key, _) in trimmed.iter() {
            assert!(store.record(&key).is_some());
        }
        assert_eq!(store.counters.loaded, part.records as u64);
        // A budget the index alone passes reads nothing.
        let none = within(prefix, &translator, prefix.len() as u64 - 1).unwrap();
        assert!(none.length > prefix.len() as u64 - 1);
        assert_eq!(none.records, 0);
        // A damaged index is refused as the engine would.
        let mut damaged = prefix.to_vec();
        damaged[HEADER_BYTES] ^= 1;
        assert_eq!(
            within(&damaged, &translator, limit),
            Err(PackError::Checksum)
        );
    }

    /// Whether `record`, a slice of `pack`, ends past `length`.
    fn at_least_past(record: &[u8], pack: &[u8], length: u64) -> bool {
        let start = record.as_ptr() as usize - pack.as_ptr() as usize;
        (start + record.len()) as u64 > length
    }
}
