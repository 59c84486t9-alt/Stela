//! The pack container `stela.efi` keeps its translations in
//! (`docs/design/runtime.md#persistent-translation-store`), and the store a
//! boot reads from it and plans the next pack with.
//!
//! A pack is one file per translator id: a header, an index sorted by page
//! key with the SHA-256 of the header and index, and the page records
//! (each checked by its own trailer when it is first used). Its length
//! follows from the index, so a file allocated larger than its pack (to be
//! rewritten in place) holds bytes past it that are never read.
//!
//! The store hands the engine the pack's records and keeps the blocks the
//! engine compiled anew. A store shared by machines that run at once (one
//! per PE) also keeps those blocks' native code, within a bound, for the
//! other machines to install instead of compiling them again. At a quiescent point it proves them (each compiled
//! again at its page's probe addresses) and lays out the next pack within a
//! bound: the records that gained entries, then the records this boot used,
//! then the others, as long as they fit.
use super::{Digest, Record};
use crate::machine::engine::SharedTranslation;
use crate::machine::{Offer, Preparation, Translations};
use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    vec::Vec,
};
use core::mem::size_of;
use stela_crypto::Sha256;
use stela_crypto::digest::Digest as _;

pub const MAGIC: [u8; 8] = *b"STLTPACK";
pub const SCHEMA: u32 = 1;
/// Magic, schema, record count and translator id.
pub const HEADER_BYTES: usize = MAGIC.len() + 4 + 4 + DIGEST_BYTES;
const DIGEST_BYTES: usize = 32;
/// Page key, offset and length.
const INDEX_ENTRY_BYTES: usize = DIGEST_BYTES + 8 + 8;
const CHECKSUM_BYTES: usize = DIGEST_BYTES;
/// The most records a pack holds.
pub const MAX_RECORDS: usize = 1 << 22;
/// The most memory the blocks waiting for proof take; later blocks are
/// counted as dropped.
const MAX_PENDING_BYTES: usize = 16 << 20;
/// A direct-mapped cache of decoded pack records shared by all PEs. Each
/// slot has its own bound so one large record cannot evict many small ones.
const DECODED_SLOTS: usize = 128;
const DECODED_SLOT_BYTES: usize = 64 << 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackError {
    Truncated,
    Magic,
    Schema,
    Translator,
    Count,
    Checksum,
    /// An index entry is out of order or names bytes outside the pack.
    Index,
}

/// The bytes of the header, index and index checksum of the pack whose
/// header is `header`: what to read before its records.
pub fn prefix_bytes(header: &[u8], translator: &Digest) -> Result<usize, PackError> {
    if header.len() < HEADER_BYTES {
        return Err(PackError::Truncated);
    }
    if header[..MAGIC.len()] != MAGIC {
        return Err(PackError::Magic);
    }
    let word = |at: usize| u32::from_le_bytes(header[at..at + 4].try_into().expect("a word"));
    if word(MAGIC.len()) != SCHEMA {
        return Err(PackError::Schema);
    }
    let count = word(MAGIC.len() + 4) as usize;
    if count > MAX_RECORDS {
        return Err(PackError::Count);
    }
    if header[MAGIC.len() + 8..HEADER_BYTES] != translator.0 {
        return Err(PackError::Translator);
    }
    Ok(HEADER_BYTES + count * INDEX_ENTRY_BYTES + CHECKSUM_BYTES)
}

/// A pack's index over its bytes.
#[derive(Debug, Clone, Copy)]
pub struct Pack<'a> {
    bytes: &'a [u8],
    count: usize,
    length: usize,
}

impl<'a> Pack<'a> {
    /// The length of the pack whose header, index and checksum start
    /// `prefix`, checked as [`Self::parse`] checks them.
    pub fn length(prefix: &[u8], translator: &Digest) -> Result<u64, PackError> {
        Self::index(prefix, translator).map(|(_, length)| length as u64)
    }

    /// The pack at the start of `bytes`: its header, index checksum, key
    /// order and every record's range are checked; bytes past its length
    /// are ignored.
    pub fn parse(bytes: &'a [u8], translator: &Digest) -> Result<Self, PackError> {
        let (count, length) = Self::index(bytes, translator)?;
        if bytes.len() < length {
            return Err(PackError::Truncated);
        }
        Ok(Self {
            bytes: &bytes[..length],
            count,
            length,
        })
    }

    /// The record count and the pack's length.
    fn index(prefix: &[u8], translator: &Digest) -> Result<(usize, usize), PackError> {
        let records_start = prefix_bytes(prefix, translator)?;
        if prefix.len() < records_start {
            return Err(PackError::Truncated);
        }
        let index_end = records_start - CHECKSUM_BYTES;
        if Sha256::digest(&prefix[..index_end]).as_slice() != &prefix[index_end..records_start] {
            return Err(PackError::Checksum);
        }
        let count = (index_end - HEADER_BYTES) / INDEX_ENTRY_BYTES;
        let mut length = records_start;
        let mut previous: Option<Digest> = None;
        for index in 0..count {
            let (key, offset, bytes) = entry(prefix, index);
            let end = offset.checked_add(bytes).ok_or(PackError::Index)?;
            if previous.is_some_and(|previous| previous >= key)
                || offset < records_start as u64
                || bytes == 0
            {
                return Err(PackError::Index);
            }
            length = length.max(usize::try_from(end).map_err(|_| PackError::Index)?);
            previous = Some(key);
        }
        Ok((count, length))
    }

    pub fn records(&self) -> usize {
        self.count
    }

    /// The pack's length in bytes.
    pub fn bytes(&self) -> usize {
        self.length
    }

    /// The record bytes of page key `key`, unchecked.
    pub fn get(&self, key: &Digest) -> Option<&'a [u8]> {
        let (mut low, mut high) = (0, self.count);
        while low < high {
            let middle = (low + high) / 2;
            let (found, offset, bytes) = entry(self.bytes, middle);
            match found.cmp(key) {
                core::cmp::Ordering::Less => low = middle + 1,
                core::cmp::Ordering::Greater => high = middle,
                core::cmp::Ordering::Equal => {
                    return Some(&self.bytes[offset as usize..(offset + bytes) as usize]);
                }
            }
        }
        None
    }

    /// Every record's page key and bytes, in key order.
    pub fn iter(&self) -> impl Iterator<Item = (Digest, &'a [u8])> + '_ {
        (0..self.count).map(|index| {
            let (key, offset, bytes) = entry(self.bytes, index);
            (key, &self.bytes[offset as usize..(offset + bytes) as usize])
        })
    }
}

/// Index entry `index` of the pack starting `bytes`: page key, offset and
/// length.
fn entry(bytes: &[u8], index: usize) -> (Digest, u64, u64) {
    let at = HEADER_BYTES + index * INDEX_ENTRY_BYTES;
    let field = |offset: usize| {
        u64::from_le_bytes(
            bytes[at + offset..at + offset + 8]
                .try_into()
                .expect("a field"),
        )
    };
    (
        Digest(bytes[at..at + DIGEST_BYTES].try_into().expect("a key")),
        field(DIGEST_BYTES),
        field(DIGEST_BYTES + 8),
    )
}

/// A record of a pack being laid out: one of the read pack's, or new.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Piece<'a> {
    Kept(&'a [u8]),
    New(Vec<u8>),
}

impl Piece<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Kept(bytes) => bytes,
            Self::New(bytes) => bytes,
        }
    }
}

/// A pack to write: its header, index and checksum, then its records, in
/// order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout<'a> {
    prefix: Vec<u8>,
    records: Vec<Piece<'a>>,
}

impl<'a> Layout<'a> {
    /// The pack of `records` (page keys and their record bytes, each key
    /// once) for `translator`.
    pub fn new(translator: &Digest, mut records: Vec<(Digest, Piece<'a>)>) -> Self {
        records.sort_by_key(|record| record.0);
        let count = records.len();
        let mut prefix =
            Vec::with_capacity(HEADER_BYTES + count * INDEX_ENTRY_BYTES + CHECKSUM_BYTES);
        prefix.extend(MAGIC);
        prefix.extend(SCHEMA.to_le_bytes());
        prefix.extend((count as u32).to_le_bytes());
        prefix.extend(translator.0);
        let mut offset = (HEADER_BYTES + count * INDEX_ENTRY_BYTES + CHECKSUM_BYTES) as u64;
        for (key, piece) in &records {
            let bytes = piece.bytes().len() as u64;
            prefix.extend(key.0);
            prefix.extend(offset.to_le_bytes());
            prefix.extend(bytes.to_le_bytes());
            offset += bytes;
        }
        let checksum = Sha256::digest(&prefix);
        prefix.extend(checksum);
        Self {
            prefix,
            records: records.into_iter().map(|(_, piece)| piece).collect(),
        }
    }

    pub fn records(&self) -> usize {
        self.records.len()
    }

    /// The pack's length in bytes.
    pub fn bytes(&self) -> u64 {
        self.chunks().map(|chunk| chunk.len() as u64).sum()
    }

    /// The pack's bytes, in order.
    pub fn chunks(&self) -> impl Iterator<Item = &[u8]> + '_ {
        core::iter::once(self.prefix.as_slice()).chain(self.records.iter().map(Piece::bytes))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.chunks().flatten().copied().collect()
    }
}

/// The pack bytes a layout of `records` records holding `bytes` record
/// bytes takes.
fn layout_bytes(records: usize, bytes: u64) -> u64 {
    (HEADER_BYTES + records * INDEX_ENTRY_BYTES + CHECKSUM_BYTES) as u64 + bytes
}

/// What a boot's store did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counters {
    /// Records looked up and valid, absent, or invalid.
    pub loaded: u64,
    pub absent: u64,
    pub invalid: u64,
    /// Blocks offered and kept for proof, and those past the memory bound.
    pub offered: u64,
    pub dropped: u64,
}

/// A block offered for proof: its place in its page and its input's in the
/// page's [`PendingPage::inputs`]. The proof compiles the block again.
#[derive(Debug, Clone, Copy)]
struct PendingBlock {
    offset: u16,
    length: u16,
    start: u32,
}

/// A page's blocks of one context waiting for proof, by offset. What the
/// blocks share is held once, so a block costs little more than its words.
#[derive(Debug)]
struct PendingPage {
    preparation: Arc<Preparation>,
    blocks: Vec<PendingBlock>,
    inputs: Vec<u8>,
}

/// A pending page's key, guest page and context.
type PendingKey = (Digest, u64, Digest);

/// A shared block's PC and the leading words of its page key and context:
/// a compact index whose rare collision only replaces an entry, as a hit
/// still matches the whole key and context ([`SharedTranslation::matches`]).
type SharedKey = (u64, u64, u64);

fn shared_key(key: &Digest, pc: u64, context: &Digest) -> SharedKey {
    let word = |digest: &Digest| u64::from_le_bytes(digest.0[..8].try_into().expect("a word"));
    (pc, word(key), word(context))
}

#[derive(Debug)]
struct SharedEntry {
    translation: Arc<SharedTranslation>,
    /// Immutable owner charge, computed once before admission.
    bytes: usize,
}

/// A validated record paired with the immutable pack bytes it came from.
pub struct DecodedRecord<'a> {
    bytes: &'a [u8],
    record: Arc<Record>,
    retained_bytes: usize,
}

impl<'a> DecodedRecord<'a> {
    pub fn decode(bytes: &'a [u8], translator: &Digest, key: &Digest) -> Option<Self> {
        let record = Arc::new(Record::decode(bytes, translator, key).ok()?);
        let retained_bytes = record.retained_bytes();
        Some(Self {
            bytes,
            record,
            retained_bytes,
        })
    }

    pub fn into_record(self) -> Arc<Record> {
        self.record
    }
}

/// One boot's store over the pack it read.
#[derive(Debug)]
pub struct Store<'a> {
    translator: Digest,
    pack: Option<Pack<'a>>,
    /// The keys looked up, and whether the pack held a valid record for
    /// each. The records themselves are the engine's to keep: decoded, they
    /// take several times the pack's bytes.
    loaded: BTreeMap<Digest, bool>,
    decoded: Vec<Option<Arc<Record>>>,
    pending: BTreeMap<PendingKey, PendingPage>,
    /// The blocks in `pending`.
    pending_blocks: usize,
    /// What `pending` holds: a charge for each page's entry and tree node,
    /// and the capacity of its buffers.
    pending_bytes: usize,
    /// The blocks offered, by page key, PC and context, for the other
    /// machines sharing the store, oldest first. The bound charges kept
    /// source/template buffers, Arc payloads, index entries and FIFO capacity;
    /// allocator node slack/bookkeeping and shared Preparation are excluded.
    shared: BTreeMap<SharedKey, SharedEntry>,
    shared_order: VecDeque<SharedKey>,
    shared_bytes: usize,
    shared_bound: usize,
    pub counters: Counters,
}

/// The next pack, and what laying it out did.
#[derive(Debug)]
pub struct Planned<'a> {
    pub layout: Layout<'a>,
    /// Blocks proven and refused by their proofs, and those left unproven
    /// when the room to prove them ran out.
    pub proven: u64,
    pub unprovable: u64,
    pub unproven: u64,
    /// Records of the read pack left out to stay within the bound, and new
    /// ones that did not fit.
    pub evicted: u64,
}

impl<'a> Store<'a> {
    /// A store of `translator` over the pack `pack` holds, if any; `None`
    /// or a damaged pack (whose error comes back too) starts it empty.
    pub fn new(translator: Digest, pack: Option<&'a [u8]>) -> (Self, Option<PackError>) {
        let parsed = pack
            .map(|bytes| Pack::parse(bytes, &translator))
            .transpose();
        let empty = |pack| Self {
            translator,
            pack,
            loaded: BTreeMap::new(),
            decoded: Vec::new(),
            pending: BTreeMap::new(),
            pending_blocks: 0,
            pending_bytes: 0,
            shared: BTreeMap::new(),
            shared_order: VecDeque::new(),
            shared_bytes: 0,
            shared_bound: 0,
            counters: Counters::default(),
        };
        match parsed {
            Ok(pack) => (empty(pack), None),
            Err(error) => (empty(None), Some(error)),
        }
    }

    /// Keep offered blocks and their buffers, up to `bound` bytes, for
    /// [`Translations::prepared`]: for machines that share the store. Full,
    /// it forgets the oldest until a new one fits.
    pub fn share(&mut self, bound: usize) {
        self.shared_bound = bound;
        while self.shared_usage() > bound {
            if !self.evict_shared() {
                self.shared_order = VecDeque::new();
                break;
            }
        }
    }

    fn shared_usage(&self) -> usize {
        self.shared_bytes
            .saturating_add(self.shared_order.capacity() * size_of::<SharedKey>())
    }

    fn evict_shared(&mut self) -> bool {
        let Some(oldest) = self.shared_order.pop_front() else {
            return false;
        };
        if let Some(evicted) = self.shared.remove(&oldest) {
            self.shared_bytes -= evicted.bytes;
        }
        true
    }

    fn keep_shared(&mut self, offer: Offer) {
        use alloc::collections::btree_map::Entry;

        if self.shared_bound == 0 {
            return;
        }
        let key = shared_key(&offer.key(), offer.pc(), &offer.context());
        let bytes = offer
            .retained_bytes()
            .saturating_add(size_of::<(SharedKey, SharedEntry)>());
        if bytes > self.shared_bound {
            return;
        }
        loop {
            let usage = self.shared_usage();
            match self.shared.entry(key) {
                Entry::Occupied(mut slot)
                    if usage.saturating_sub(slot.get().bytes).saturating_add(bytes)
                        <= self.shared_bound =>
                {
                    self.shared_bytes = self.shared_bytes - slot.get().bytes + bytes;
                    slot.insert(SharedEntry {
                        translation: offer.shared(),
                        bytes,
                    });
                    return;
                }
                Entry::Vacant(slot)
                    if usage.saturating_add(bytes) <= self.shared_bound
                        && self.shared_order.try_reserve(1).is_ok() =>
                {
                    // A FIFO allocation can itself exceed the budget.
                    let fifo = self.shared_order.capacity() * size_of::<SharedKey>();
                    if self.shared_bytes.saturating_add(fifo).saturating_add(bytes)
                        <= self.shared_bound
                    {
                        slot.insert(SharedEntry {
                            translation: offer.shared(),
                            bytes,
                        });
                        self.shared_order.push_back(key);
                        self.shared_bytes += bytes;
                        return;
                    }
                }
                _ => {}
            }
            if !self.evict_shared() {
                self.shared_order = VecDeque::new();
                return;
            }
        }
    }

    fn keep_pending(&mut self, offer: &Offer) {
        if !self.reserve_pending(offer) {
            self.counters.dropped += 1;
        }
    }

    /// Keep `offer` for proof unless its page holds the block already:
    /// whether it fit.
    fn reserve_pending(&mut self, offer: &Offer) -> bool {
        const BLOCK_BYTES: usize = size_of::<PendingBlock>();
        // An entry in a B-tree node about half full.
        const PAGE_BYTES: usize = 2 * size_of::<(PendingKey, PendingPage)>();
        let (Ok(offset), Ok(length)) = (
            u16::try_from(offer.pc() - offer.page()),
            u16::try_from(offer.input().len()),
        ) else {
            return false;
        };
        let group = (offer.key(), offer.page(), offer.context());
        let known = self.pending.get(&group);
        let place = known.map_or(Err(0), |page| {
            page.blocks
                .binary_search_by_key(&offset, |block| block.offset)
        });
        let Err(place) = place else {
            return true;
        };
        let new_page = if known.is_some() { 0 } else { PAGE_BYTES };
        let charge = BLOCK_BYTES + usize::from(length) + new_page;
        if self.pending_bytes.saturating_add(charge) > MAX_PENDING_BYTES {
            return false;
        }
        let page = self.pending.entry(group).or_insert_with(|| PendingPage {
            preparation: Arc::clone(offer.preparation()),
            blocks: Vec::new(),
            inputs: Vec::new(),
        });
        let held = page.blocks.capacity() * BLOCK_BYTES + page.inputs.capacity();
        // A page's inputs stay far below 4 GiB: its blocks do not overlap by
        // more than a block each, and `length` fits 16 bits.
        let start = page.inputs.len() as u32;
        if page.blocks.try_reserve(1).is_err()
            || page.inputs.try_reserve(usize::from(length)).is_err()
        {
            if page.blocks.is_empty() {
                self.pending.remove(&group);
            }
            return false;
        }
        page.blocks.insert(
            place,
            PendingBlock {
                offset,
                length,
                start,
            },
        );
        page.inputs.extend_from_slice(offer.input());
        let grown = page.blocks.capacity() * BLOCK_BYTES + page.inputs.capacity() - held;
        self.pending_bytes += grown + new_page;
        self.pending_blocks += 1;
        self.counters.offered += 1;
        true
    }

    /// The translator whose records the store keeps.
    pub fn translator(&self) -> &Digest {
        &self.translator
    }

    fn decoded_slot(key: &Digest) -> usize {
        usize::from(key.0[0]) % DECODED_SLOTS
    }

    /// A record already decoded and checked against this pack.
    pub fn cached_record(&self, key: &Digest) -> Option<Arc<Record>> {
        let record = self.decoded.get(Self::decoded_slot(key))?.as_ref()?;
        (record.key == *key).then(|| Arc::clone(record))
    }

    /// Remember a decoded record from this pack. The caller can drop an
    /// evicted record after releasing the shared store lock.
    pub fn remember_record(&mut self, decoded: &DecodedRecord<'a>) -> Option<Arc<Record>> {
        let record = &decoded.record;
        if record.translator != self.translator
            || decoded.retained_bytes > DECODED_SLOT_BYTES
            || !self
                .stored(&record.key)
                .is_some_and(|bytes| core::ptr::eq(bytes, decoded.bytes))
        {
            return None;
        }
        if self.decoded.is_empty() {
            self.decoded.try_reserve_exact(DECODED_SLOTS).ok()?;
            self.decoded.resize_with(DECODED_SLOTS, || None);
        }
        let slot = &mut self.decoded[Self::decoded_slot(&record.key)];
        if slot.as_ref().is_some_and(|held| held.key == record.key) {
            return None;
        }
        slot.replace(Arc::clone(record))
    }

    /// The pack's bytes for `key`, unless an earlier lookup found them
    /// invalid: for a caller to decode ([`Record::decode`]) without holding
    /// the store, then report with [`Self::looked_up`].
    pub fn stored(&self, key: &Digest) -> Option<&'a [u8]> {
        let pack = self.pack?;
        if self.loaded.get(key) == Some(&false) {
            return None;
        }
        pack.get(key)
    }

    /// Count `key`'s first lookup: whether the pack held bytes for it, and
    /// whether they decoded.
    pub fn looked_up(&mut self, key: &Digest, found: bool, valid: bool) {
        let alloc::collections::btree_map::Entry::Vacant(slot) = self.loaded.entry(*key) else {
            return;
        };
        match (found, valid) {
            (true, true) => self.counters.loaded += 1,
            (true, false) => self.counters.invalid += 1,
            (false, _) => self.counters.absent += 1,
        }
        slot.insert(valid);
    }

    /// The pack read, if valid.
    pub fn pack(&self) -> Option<&Pack<'a>> {
        self.pack.as_ref()
    }

    /// Blocks waiting for proof.
    pub fn pending(&self) -> usize {
        self.pending_blocks
    }

    /// Prove the offered blocks while `room` says there is memory to, and
    /// lay out the next pack within `bound` bytes.
    pub fn plan(&mut self, bound: u64, room: impl Fn() -> bool) -> Planned<'a> {
        let mut proven: BTreeMap<Digest, Record> = BTreeMap::new();
        let (mut count, mut unprovable) = (0, 0);
        let pending = core::mem::take(&mut self.pending);
        let mut unproven = self.pending_blocks as u64;
        'pages: for ((key, page, context), held) in pending {
            for block in held.blocks {
                if !room() {
                    break 'pages;
                }
                unproven -= 1;
                let start = block.start as usize;
                let input = held.inputs[start..start + usize::from(block.length)].to_vec();
                let pc = page + u64::from(block.offset);
                let preparation = Arc::clone(&held.preparation);
                let entry = Offer::compile(key, page, pc, context, input, preparation)
                    .and_then(|offer| offer.prove());
                match entry {
                    Some(entry) => {
                        count += 1;
                        proven
                            .entry(key)
                            .or_insert_with(|| Record::new(self.translator, key))
                            .insert(entry);
                    }
                    None => unprovable += 1,
                }
            }
        }
        self.pending_blocks = 0;
        self.pending_bytes = 0;
        // Gained entries first, then this boot's records, then the others.
        let stored = |key: &Digest| {
            self.pack
                .and_then(|pack| pack.get(key))
                .and_then(|bytes| Record::decode(bytes, &self.translator, key).ok())
        };
        let mut candidates: Vec<(Digest, Piece<'a>)> = Vec::new();
        for (key, record) in &mut proven {
            if let Some(stored) = stored(key) {
                record.merge(stored);
            }
            candidates.push((*key, Piece::New(record.encode())));
        }
        if let Some(pack) = self.pack {
            for (key, valid) in &self.loaded {
                if *valid
                    && !proven.contains_key(key)
                    && let Some(bytes) = pack.get(key)
                {
                    candidates.push((*key, Piece::Kept(bytes)));
                }
            }
            for (key, bytes) in pack.iter() {
                if !self.loaded.contains_key(&key) && !proven.contains_key(&key) {
                    candidates.push((key, Piece::Kept(bytes)));
                }
            }
        }
        let (mut kept, mut kept_bytes, mut evicted) = (Vec::new(), 0u64, 0);
        for (key, piece) in candidates {
            let bytes = piece.bytes().len() as u64;
            if kept.len() < MAX_RECORDS && layout_bytes(kept.len() + 1, kept_bytes + bytes) <= bound
            {
                kept_bytes += bytes;
                kept.push((key, piece));
            } else {
                evicted += 1;
            }
        }
        Planned {
            layout: Layout::new(&self.translator, kept),
            proven: count,
            unprovable,
            unproven,
            evicted,
        }
    }
}

impl Translations for Store<'_> {
    fn record(&mut self, key: &Digest) -> Option<Arc<Record>> {
        if let Some(record) = self.cached_record(key) {
            return Some(record);
        }
        let bytes = self.stored(key);
        let decoded = bytes.and_then(|bytes| DecodedRecord::decode(bytes, &self.translator, key));
        self.looked_up(key, bytes.is_some(), decoded.is_some());
        decoded.map(|decoded| {
            self.remember_record(&decoded);
            decoded.into_record()
        })
    }

    fn prepared(
        &mut self,
        key: &Digest,
        pc: u64,
        context: &Digest,
    ) -> Option<Arc<SharedTranslation>> {
        self.shared
            .get(&shared_key(key, pc, context))
            .map(|entry| Arc::clone(&entry.translation))
    }

    fn offer(&mut self, offer: Offer) {
        self.keep_pending(&offer);
        self.keep_shared(offer);
    }

    fn lend(&mut self, offer: Offer) {
        self.keep_shared(offer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::test_preparation;
    use crate::translations::{PAGE_BYTES, translator_id};

    /// An offer of `add x0, x0, #1; ret` at `pc`, in a page whose bytes
    /// hash to `key`.
    fn offer(pc: u64, key: Digest) -> Offer {
        let preparation = Arc::new(test_preparation());
        let page = pc & !(PAGE_BYTES as u64 - 1);
        let mut input: Vec<u8> = [0x9100_0400u32, 0xd65f_03c0]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        preparation.admit(&mut input);
        Offer::compile(key, page, pc, preparation.context(page), input, preparation).unwrap()
    }

    #[test]
    fn decoded_pack_records_share_an_owner_and_check_the_full_key() {
        let translator = translator_id();
        let first = Digest([1; 32]);
        let mut second = first;
        second.0[1] = 2;
        let bytes = Layout::new(
            &translator,
            [first, second]
                .map(|key| (key, Piece::New(Record::new(translator, key).encode())))
                .into(),
        )
        .to_vec();
        let mut store = Store::new(translator, Some(&bytes)).0;
        let held = store.record(&first).unwrap();
        assert!(Arc::ptr_eq(&held, &store.record(&first).unwrap()));
        assert_eq!(store.record(&second).unwrap().key, second);
        assert!(!Arc::ptr_eq(&held, &store.record(&first).unwrap()));
        assert_eq!(store.counters.loaded, 2);
    }

    #[test]
    fn decoded_cache_declines_oversized_and_foreign_records() {
        let translator = translator_id();
        let key = Digest::of(b"page");
        let mut large = Record::new(translator, key);
        let mut entry = offer(0x1000, key).prove().unwrap();
        entry.code.resize(DECODED_SLOT_BYTES, 0);
        large.insert(entry);
        let bytes = Layout::new(&translator, vec![(key, Piece::New(large.encode()))]).to_vec();
        let mut store = Store::new(translator, Some(&bytes)).0;
        assert!(store.record(&key).is_some());
        assert!(store.cached_record(&key).is_none());

        let bytes = Layout::new(
            &translator,
            vec![(key, Piece::New(Record::new(translator, key).encode()))],
        )
        .to_vec();
        let foreign = bytes.clone();
        let mut store = Store::new(translator, Some(&bytes)).0;
        let foreign = Pack::parse(&foreign, &translator)
            .unwrap()
            .get(&key)
            .unwrap();
        let decoded = DecodedRecord::decode(foreign, &translator, &key).unwrap();
        assert!(store.remember_record(&decoded).is_none());
        assert!(store.cached_record(&key).is_none());
    }

    #[test]
    fn shared_cache_budget_includes_source_and_recovery_owners() {
        let translator = Digest::of(b"translator");
        let key = Digest::of(b"page");
        let first = offer(0x1000, key);
        let context = first.context();
        let code = first.block().native.x86_64_code.len();
        let (mut store, _) = Store::new(translator, None);
        // The native bytes fit, but their source/template/collection owners do not.
        store.share(code);
        store.offer(first);
        assert!(store.prepared(&key, 0x1000, &context).is_none());
        assert!(store.shared_order.is_empty());
    }

    #[test]
    fn shared_cache_budget_charges_emitted_recovery_buffers() {
        let key = Digest::of(b"page");
        let preparation = Arc::new(test_preparation());
        let context = preparation.context(0x1000);
        let mut input: Vec<u8> = core::iter::repeat_n(0xf900_0020u32, 16)
            .chain(core::iter::once(0xd65f_03c0))
            .flat_map(u32::to_le_bytes)
            .collect();
        preparation.admit(&mut input);
        let offered = Offer::compile(key, 0x1000, 0x1000, context, input, preparation).unwrap();
        let code = offered.block().native.x86_64_code.len();
        assert!(!offered.block().fault_recovery.is_empty());
        assert!(
            offered.block().fault_recovery.len()
                * size_of::<stela_compiler::block::FaultRecovery>()
                > code
        );
        let (mut store, _) = Store::new(Digest::of(b"translator"), None);
        store.share(2 * code);
        store.offer(offered);
        assert!(store.prepared(&key, 0x1000, &context).is_none());
        assert!(store.shared_order.is_empty());
    }

    #[test]
    fn an_offer_keeps_no_reserved_source_capacity_against_the_shared_bound() {
        let key = Digest::of(b"page");
        let first = offer(0x1000, key);
        let context = first.context();
        let preparation = Arc::clone(first.preparation());
        let mut input = Vec::with_capacity(2 << 20);
        input.extend_from_slice(first.input());
        let replacement = Offer::compile(key, 0x1000, 0x1000, context, input, preparation).unwrap();
        let (mut store, _) = Store::new(Digest::of(b"translator"), None);
        store.share(1 << 20);
        store.offer(replacement);
        assert!(store.prepared(&key, 0x1000, &context).is_some());
        assert_eq!(store.shared_order.len(), 1);
    }

    #[test]
    fn reducing_shared_cache_budget_releases_kept_entries_and_fifo_capacity() {
        let key = Digest::of(b"page");
        let first = offer(0x1000, key);
        let context = first.context();
        let (mut store, _) = Store::new(Digest::of(b"translator"), None);
        store.share(usize::MAX);
        store.offer(first);
        assert!(store.prepared(&key, 0x1000, &context).is_some());
        store.share(0);
        assert!(store.prepared(&key, 0x1000, &context).is_none());
        assert_eq!(store.shared_order.capacity(), 0);
    }

    #[test]
    fn a_shared_store_hands_offered_blocks_to_other_machines_and_forgets_the_oldest_when_full() {
        let translator = Digest::of(b"translator");
        let key = Digest::of(b"page");
        let (first, second) = (offer(0x1000, key), offer(0x1008, key));
        let code = first.block().native.x86_64_code.len();
        let bytes = first.clone().retained_bytes() + size_of::<(SharedKey, SharedEntry)>();
        let mut queue = VecDeque::<SharedKey>::new();
        queue.try_reserve(1).unwrap();
        let fifo = queue.capacity() * size_of::<SharedKey>();
        let (mut store, _) = Store::new(translator, None);
        store.offer(first.clone());
        // A store no machine shares keeps no native code.
        assert!(store.prepared(&key, 0x1000, &first.context()).is_none());
        store.share(bytes + bytes / 2 + fifo);
        store.offer(first.clone());
        store.offer(first.clone());
        store.offer(second.clone());
        assert!(
            store
                .prepared(&key, 0x1000, &Digest::of(b"other"))
                .is_none()
        );
        assert!(store.prepared(&key, 0x1008, &second.context()).is_some());
        assert!(store.prepared(&key, 0x1000, &first.context()).is_none());
        store.share(4 * bytes + fifo);
        store.offer(first.clone());
        assert_eq!(
            store
                .prepared(&key, 0x1000, &first.context())
                .map(|block| block.block().native.x86_64_code.clone()),
            Some(first.block().native.x86_64_code.clone())
        );
        // Offered again, a block keeps its one place and its bytes.
        store.offer(first.clone());
        assert_eq!(store.shared_bytes, 2 * bytes);
        // Full, the oldest goes first: the second, offered before the first
        // came back.
        let third = offer(0x1010, key);
        let fourth = offer(0x1018, key);
        store.offer(third.clone());
        store.offer(fourth.clone());
        let preparation = Arc::new(test_preparation());
        let pc = 0x1020;
        let page = pc & !(PAGE_BYTES as u64 - 1);
        let fifth = Offer::compile(
            key,
            page,
            pc,
            preparation.context(page),
            0xd65f03c0_u32.to_le_bytes().to_vec(),
            preparation,
        )
        .unwrap();
        assert!(
            fifth.block().native.x86_64_code.len() < code,
            "a genuine shorter emitted block"
        );
        store.offer(fifth.clone());
        assert!(store.prepared(&key, 0x1008, &second.context()).is_none());
        assert!(store.prepared(&key, 0x1000, &first.context()).is_some());
        assert!(store.prepared(&key, 0x1020, &fifth.context()).is_some());
        assert!(store.shared_usage() <= 4 * bytes + fifo);
        // Each distinct block waits for proof once, however often offered.
        assert_eq!(store.pending(), 5);
    }

    #[test]
    fn a_pack_indexes_its_records_by_key_and_ignores_bytes_past_its_end() {
        let translator = Digest::of(b"translator");
        let names: [&[u8]; 3] = [b"b", b"a", b"c"];
        let records: Vec<(Digest, Piece)> = names
            .iter()
            .map(|name| (Digest::of(name), Piece::New(name.repeat(10))))
            .collect();
        let layout = Layout::new(&translator, records);
        let mut bytes = layout.to_vec();
        assert_eq!(bytes.len() as u64, layout.bytes());
        let length = Pack::length(&bytes, &translator).unwrap();
        assert_eq!(length, layout.bytes());
        // A file allocated larger than its pack.
        bytes.extend([0xa5; 100]);
        let pack = Pack::parse(&bytes, &translator).unwrap();
        assert_eq!((pack.records(), pack.bytes() as u64), (3, length));
        assert_eq!(pack.get(&Digest::of(b"c")), Some(&b"cccccccccc"[..]));
        assert_eq!(pack.get(&Digest::of(b"d")), None);
        let mut keys: Vec<Digest> = names.iter().map(|name| Digest::of(name)).collect();
        keys.sort();
        assert_eq!(pack.iter().map(|(key, _)| key).collect::<Vec<_>>(), keys);
        let prefix = prefix_bytes(&bytes, &translator).unwrap();
        assert_eq!(
            prefix,
            HEADER_BYTES + 3 * INDEX_ENTRY_BYTES + CHECKSUM_BYTES
        );
        assert_eq!(
            Pack::parse(&bytes, &Digest::default()).unwrap_err(),
            PackError::Translator
        );
        assert_eq!(
            Pack::parse(&bytes[..prefix - 1], &translator).unwrap_err(),
            PackError::Truncated
        );
        assert_eq!(
            Pack::parse(&bytes[..length as usize - 1], &translator).unwrap_err(),
            PackError::Truncated
        );
        let mut damaged = bytes.clone();
        damaged[HEADER_BYTES + DIGEST_BYTES] ^= 1;
        assert_eq!(
            Pack::parse(&damaged, &translator).unwrap_err(),
            PackError::Checksum
        );
        let mut magic = bytes;
        magic[0] ^= 1;
        assert_eq!(
            Pack::parse(&magic, &translator).unwrap_err(),
            PackError::Magic
        );
    }

    #[test]
    fn blocks_past_the_room_to_prove_them_stay_unproven() {
        let translator = translator_id();
        let (first, second) = (Digest::of(b"first page"), Digest::of(b"second page"));
        let mut store = Store::new(translator, None).0;
        store.offer(offer(0x1_0000_4008, first));
        store.offer(offer(0x1_0000_8010, second));
        let tried = core::cell::Cell::new(0);
        let planned = store.plan(u64::MAX, || {
            tried.set(tried.get() + 1);
            tried.get() == 1
        });
        assert_eq!((planned.proven, planned.unproven), (1, 1));
        assert_eq!(planned.layout.records(), 1);
    }

    #[test]
    fn a_boot_proves_its_blocks_into_the_next_pack_and_the_one_after_reads_them() {
        let translator = translator_id();
        let (first, second) = (Digest::of(b"first page"), Digest::of(b"second page"));
        let mut store = Store::new(translator, None).0;
        store.offer(offer(0x1_0000_4008, first));
        store.offer(offer(0x1_0000_8010, second));
        assert_eq!(store.record(&first), None);
        let planned = store.plan(u64::MAX, || true);
        assert_eq!(
            (planned.proven, planned.unprovable, planned.evicted),
            (2, 0, 0)
        );
        assert_eq!(store.pending(), 0);
        let bytes = planned.layout.to_vec();

        let mut next = Store::new(translator, Some(&bytes)).0;
        let record = next.record(&first).expect("the first page's record");
        let context = offer(0x1_0000_4008, first).context();
        assert!(
            record
                .find(8, &context)
                .unwrap()
                .rebase(0x1_0000_4000, offer(0x1_0000_4008, first).input())
                .is_some()
        );
        assert_eq!(next.counters.loaded, 1);
        // The record this boot used is kept first under a tight bound.
        let one = layout_bytes(1, next.pack().unwrap().get(&first).unwrap().len() as u64);
        let planned = next.plan(one, || true);
        assert_eq!((planned.layout.records(), planned.evicted), (1, 1));
        let kept = planned.layout.to_vec();
        let pack = Pack::parse(&kept, &translator).unwrap();
        assert!(pack.get(&first).is_some() && pack.get(&second).is_none());

        // A damaged pack starts the store empty.
        let (mut empty, error) = Store::new(translator, Some(&bytes[..10]));
        assert_eq!(error, Some(PackError::Truncated));
        assert_eq!(empty.record(&first), None);
        assert_eq!(empty.counters.absent, 1);
    }

    #[test]
    fn new_entries_of_a_stored_page_are_merged_with_its_record() {
        let translator = translator_id();
        let key = Digest::of(b"page");
        let mut store = Store::new(translator, None).0;
        store.offer(offer(0x1_0000_4008, key));
        let bytes = store.plan(u64::MAX, || true).layout.to_vec();
        let mut next = Store::new(translator, Some(&bytes)).0;
        next.offer(offer(0x1_0000_4010, key));
        let merged = next.plan(u64::MAX, || true).layout.to_vec();
        let pack = Pack::parse(&merged, &translator).unwrap();
        let record = Record::decode(pack.get(&key).unwrap(), &translator, &key).unwrap();
        let mut offsets: Vec<u16> = record.entries.iter().map(|entry| entry.offset).collect();
        offsets.sort();
        assert_eq!(offsets, [8, 0x10]);
    }
}
