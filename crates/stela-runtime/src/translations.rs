//! The persistent translation store's format
//! (`docs/design/runtime.md#persistent-translation-store`): page records of
//! block translations keyed by the SHA-256 of their guest fetch page, with
//! guest addresses in the native code stored relative to the page, and the
//! proof that a block's code depends on its address only through them.
//!
//! The format is the same in every container: the hosted directory store
//! (`crate::hosted::translations`) and the pack `stela.efi` keeps
//! ([`pack`]).
pub mod pack;

use alloc::{string::String, vec::Vec};
use sha2::{Digest as _, Sha256};
use stela_compiler::{
    GuestAddress, NativeBlock,
    block::{CompiledBlock, ExitKind, FaultRecovery},
    x86_64::chain::DirectExit,
};

/// The bytes of the fetch page a record covers: no block leaves it.
pub const PAGE_BYTES: usize = 4096;
pub const SCHEMA: u32 = 1;
const RECORD_MAGIC: [u8; 8] = *b"STLTPAGE";
const HEADER_BYTES: usize = 88;
const TRAILER_BYTES: usize = 32;
/// A relocated field: a little-endian u64 in the native code.
const FIELD_BYTES: usize = 8;
/// The bits of a page's address its translations are bound to (the
/// address class): probes and rebasing never change them.
const CLASS_SHIFT: u32 = 47;
/// The probe displacements: 16 KiB multiples (every slide is one, so page
/// offsets are kept) with bits set in every 16-bit lane below the class
/// bits, in complementary patterns, so that a guest address the compiler
/// narrowed or partly overwrote moves by other than the displacement.
const PROBES: [u64; 2] = [0x2aaa_aaaa_c000, 0x1555_5555_4000];

/// A SHA-256 digest: a translator id, a page key or an entry context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// The translator id: what decides the code a translation input produces.
pub fn translator_id() -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_MAGIC);
    hasher.update(SCHEMA.to_le_bytes());
    for part in [
        stela_compiler::block::SYSTEM_MODE_BLOCK_ABI,
        stela_compiler::SOURCE_SHA256,
        ENGINE_SOURCE_SHA256,
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    Digest(hasher.finalize().into())
}

/// The engine's compile-driver sources (`build.rs`).
pub const ENGINE_SOURCE_SHA256: &str = env!("STELA_ENGINE_SOURCE_SHA256");

/// The address class of a page: bits 47..63 of its address.
pub fn address_class(page: u64) -> u64 {
    page >> CLASS_SHIFT
}

/// One direct exit, its target relative to the page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exit {
    pub offset: u32,
    pub target: u64,
    pub kind: u8,
}

/// One stored block translation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub context: Digest,
    /// The page offset of its entry PC.
    pub offset: u16,
    pub source_bytes: u16,
    /// Native code, each relocation field holding `value - page`.
    pub code: Vec<u8>,
    /// Code offsets of the relocation fields, ascending.
    pub relocations: Vec<u32>,
    /// Page offset of each guest instruction and its native offset.
    pub source_map: Vec<(u16, u32)>,
    pub exits: Vec<Exit>,
    pub recovery: Vec<FaultRecovery>,
}

impl Entry {
    /// The block as compiled at the page whose address is `page`.
    pub fn rebase(&self, page: u64) -> Option<CompiledBlock> {
        let mut code = self.code.clone();
        for &at in &self.relocations {
            let field = code.get_mut(at as usize..at as usize + FIELD_BYTES)?;
            let value = u64::from_le_bytes(field.try_into().ok()?).wrapping_add(page);
            field.copy_from_slice(&value.to_le_bytes());
        }
        let direct_exits = self
            .exits
            .iter()
            .map(|exit| {
                Some(DirectExit {
                    offset: exit.offset as usize,
                    target: GuestAddress(exit.target.wrapping_add(page)),
                    kind: ExitKind::try_from(u64::from(exit.kind)).ok()?,
                })
            })
            .collect::<Option<_>>()?;
        Some(CompiledBlock {
            native: NativeBlock {
                x86_64_code: code,
                source_map: self
                    .source_map
                    .iter()
                    .map(|&(guest, native)| {
                        (GuestAddress(page + u64::from(guest)), native as usize)
                    })
                    .collect(),
            },
            source_bytes: usize::from(self.source_bytes),
            direct_exits,
            fault_recovery: self.recovery.clone(),
        })
    }

    /// Check what decoding cannot: offsets inside the code and the page,
    /// ascending source map and relocations, and fields that do not overlap.
    fn consistent(&self) -> bool {
        let code = self.code.len();
        let in_code = |offset: u32, bytes: usize| (offset as usize).saturating_add(bytes) <= code;
        usize::from(self.offset) + usize::from(self.source_bytes) <= PAGE_BYTES
            && self.source_bytes != 0
            && self.offset.is_multiple_of(4)
            && self.source_bytes.is_multiple_of(4)
            && self.relocations.windows(2).all(|pair| {
                pair[0]
                    .checked_add(FIELD_BYTES as u32)
                    .is_some_and(|end| end <= pair[1])
            })
            && self
                .relocations
                .iter()
                .all(|&offset| in_code(offset, FIELD_BYTES))
            && crate::artifact::validate_source_map_geometry(
                u64::from(self.offset),
                usize::from(self.source_bytes),
                code,
                0,
                self.source_map
                    .iter()
                    .map(|&(guest, native)| (u64::from(guest), native as usize)),
            )
            .is_ok()
            && self.exits.iter().all(|exit| {
                in_code(exit.offset, 0) && ExitKind::try_from(u64::from(exit.kind)).is_ok()
            })
            && self.recovery.iter().all(|range| {
                range.start <= range.end
                    && range.end <= code
                    && range
                        .registers
                        .iter()
                        .all(|&(guest, host)| guest <= 31 && host < 16)
            })
    }
}

/// Why a stored record is not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    Truncated,
    Magic,
    Schema,
    Translator,
    Key,
    Checksum,
    Entry,
}

/// The translations of one page content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub translator: Digest,
    pub key: Digest,
    pub entries: Vec<Entry>,
}

impl Record {
    pub fn new(translator: Digest, key: Digest) -> Self {
        Self {
            translator,
            key,
            entries: Vec::new(),
        }
    }

    pub fn find(&self, offset: u16, context: &Digest) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|entry| entry.offset == offset && entry.context == *context)
    }

    /// Add `entry`, replacing one for the same entry PC and context.
    pub fn insert(&mut self, entry: Entry) {
        match self
            .entries
            .iter_mut()
            .find(|other| other.offset == entry.offset && other.context == entry.context)
        {
            Some(other) => *other = entry,
            None => self.entries.push(entry),
        }
    }

    /// Add the entries of `other` this record lacks.
    pub fn merge(&mut self, other: Self) {
        for entry in other.entries {
            if self.find(entry.offset, &entry.context).is_none() {
                self.entries.push(entry);
            }
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            HEADER_BYTES
                + TRAILER_BYTES
                + self
                    .entries
                    .iter()
                    .map(|entry| 64 + entry.code.len() + entry.source_map.len() * 6)
                    .sum::<usize>(),
        );
        out.extend(RECORD_MAGIC);
        out.extend(SCHEMA.to_le_bytes());
        out.extend((self.entries.len() as u32).to_le_bytes());
        out.extend(self.translator.0);
        out.extend(self.key.0);
        out.extend(0u64.to_le_bytes());
        for entry in &self.entries {
            out.extend(entry.context.0);
            out.extend(entry.offset.to_le_bytes());
            out.extend(entry.source_bytes.to_le_bytes());
            out.extend((entry.code.len() as u32).to_le_bytes());
            out.extend((entry.relocations.len() as u32).to_le_bytes());
            for offset in &entry.relocations {
                out.extend(offset.to_le_bytes());
            }
            out.extend((entry.source_map.len() as u32).to_le_bytes());
            for (guest, native) in &entry.source_map {
                out.extend(guest.to_le_bytes());
                out.extend(native.to_le_bytes());
            }
            out.extend((entry.exits.len() as u32).to_le_bytes());
            for exit in &entry.exits {
                out.extend(exit.offset.to_le_bytes());
                out.extend(exit.target.to_le_bytes());
                out.push(exit.kind);
            }
            out.extend((entry.recovery.len() as u32).to_le_bytes());
            for range in &entry.recovery {
                out.extend((range.start as u32).to_le_bytes());
                out.extend((range.end as u32).to_le_bytes());
                out.extend((range.registers.len() as u32).to_le_bytes());
                for &(guest, host) in &range.registers {
                    out.extend([guest, host]);
                }
            }
            out.extend(&entry.code);
        }
        let total = (out.len() + TRAILER_BYTES) as u64;
        out[80..88].copy_from_slice(&total.to_le_bytes());
        let checksum = Sha256::digest(&out);
        out.extend(checksum);
        out
    }

    /// Decode a record for `translator` and page `key`, checking it whole.
    pub fn decode(bytes: &[u8], translator: &Digest, key: &Digest) -> Result<Self, FormatError> {
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
        let count = reader.u32()?;
        if reader.digest()? != *translator {
            return Err(FormatError::Translator);
        }
        if reader.digest()? != *key {
            return Err(FormatError::Key);
        }
        if reader.u64()? != bytes.len() as u64 {
            return Err(FormatError::Truncated);
        }
        if Sha256::digest(body).as_slice() != trailer {
            return Err(FormatError::Checksum);
        }
        let mut entries = Vec::new();
        for _ in 0..count {
            let entry = reader.entry()?;
            if !entry.consistent() {
                return Err(FormatError::Entry);
            }
            entries.push(entry);
        }
        if !reader.0.is_empty() {
            return Err(FormatError::Entry);
        }
        Ok(Self {
            translator: *translator,
            key: *key,
            entries,
        })
    }
}

/// Bounded little-endian reads; every count is checked against the bytes
/// left before anything is allocated.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, bytes: usize) -> Result<&'a [u8], FormatError> {
        if self.0.len() < bytes {
            return Err(FormatError::Truncated);
        }
        let (taken, rest) = self.0.split_at(bytes);
        self.0 = rest;
        Ok(taken)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], FormatError> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    fn u8(&mut self) -> Result<u8, FormatError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, FormatError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, FormatError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, FormatError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn digest(&mut self) -> Result<Digest, FormatError> {
        Ok(Digest(self.array()?))
    }

    /// A count of items of at least `item` bytes each.
    fn count(&mut self, item: usize) -> Result<usize, FormatError> {
        let count = self.u32()? as usize;
        if count.saturating_mul(item) > self.0.len() {
            return Err(FormatError::Truncated);
        }
        Ok(count)
    }

    fn entry(&mut self) -> Result<Entry, FormatError> {
        let context = self.digest()?;
        let offset = self.u16()?;
        let source_bytes = self.u16()?;
        let code_bytes = self.u32()? as usize;
        let relocations = (0..self.count(4)?)
            .map(|_| self.u32())
            .collect::<Result<_, _>>()?;
        let source_map = (0..self.count(6)?)
            .map(|_| Ok((self.u16()?, self.u32()?)))
            .collect::<Result<_, _>>()?;
        let exits = (0..self.count(13)?)
            .map(|_| {
                Ok(Exit {
                    offset: self.u32()?,
                    target: self.u64()?,
                    kind: self.u8()?,
                })
            })
            .collect::<Result<_, _>>()?;
        let recovery = (0..self.count(12)?)
            .map(|_| {
                let start = self.u32()? as usize;
                let end = self.u32()? as usize;
                let registers = (0..self.count(2)?)
                    .map(|_| Ok((self.u8()?, self.u8()?)))
                    .collect::<Result<_, _>>()?;
                Ok(FaultRecovery {
                    start,
                    end,
                    registers,
                })
            })
            .collect::<Result<_, _>>()?;
        let code = self.take(code_bytes)?.to_vec();
        Ok(Entry {
            context,
            offset,
            source_bytes,
            code,
            relocations,
            source_map,
            exits,
            recovery,
        })
    }
}

/// The two probe displacements for a page at `page`: each moves it within
/// its address class, up when that stays in the class and down otherwise.
pub fn probe_displacements(page: u64) -> [u64; 2] {
    PROBES.map(|probe| {
        let up = page.wrapping_add(probe);
        if address_class(up) == address_class(page) && up > page {
            probe
        } else {
            probe.wrapping_neg()
        }
    })
}

/// The stored form of `block`, compiled at `pc` in the page at `page`, given
/// the same source compiled at the two [`probe_displacements`] of the page:
/// `None` unless the three differ only in 8-byte fields, each by exactly
/// its probe's displacement, and in their exit targets and source maps by
/// the same.
pub fn prove(
    block: &CompiledBlock,
    page: u64,
    pc: u64,
    context: Digest,
    probes: [&CompiledBlock; 2],
) -> Option<Entry> {
    let displacements = probe_displacements(page);
    let code = &block.native.x86_64_code;
    let same_shape = |probe: &CompiledBlock, displacement: u64| {
        probe.source_bytes == block.source_bytes
            && probe.native.x86_64_code.len() == code.len()
            && probe.fault_recovery == block.fault_recovery
            && probe.native.source_map.len() == block.native.source_map.len()
            && probe
                .native
                .source_map
                .iter()
                .zip(&block.native.source_map)
                .all(|(moved, original)| {
                    moved.1 == original.1 && moved.0.0.wrapping_sub(original.0.0) == displacement
                })
            && probe.direct_exits.len() == block.direct_exits.len()
            && probe
                .direct_exits
                .iter()
                .zip(&block.direct_exits)
                .all(|(moved, original)| {
                    moved.offset == original.offset
                        && moved.kind == original.kind
                        && moved.target.0.wrapping_sub(original.target.0) == displacement
                })
    };
    if !probes
        .iter()
        .zip(displacements)
        .all(|(probe, displacement)| same_shape(probe, displacement))
    {
        return None;
    }
    let field = |bytes: &[u8], at: usize| {
        u64::from_le_bytes(bytes[at..at + FIELD_BYTES].try_into().expect("8 bytes"))
    };
    let moves = |at: usize| {
        at + FIELD_BYTES <= code.len()
            && probes
                .iter()
                .zip(displacements)
                .all(|(probe, displacement)| {
                    field(&probe.native.x86_64_code, at).wrapping_sub(field(code, at))
                        == displacement
                })
    };
    let mut relocations = Vec::new();
    let mut at = 0;
    while at < code.len() {
        if probes
            .iter()
            .all(|probe| probe.native.x86_64_code[at] == code[at])
        {
            at += 1;
            continue;
        }
        // The field holding the first differing byte starts at most 7
        // bytes before it, and after the previous field.
        let floor = relocations
            .last()
            .map_or(0, |&last: &u32| last as usize + FIELD_BYTES);
        let start =
            (at.saturating_sub(FIELD_BYTES - 1).max(floor)..=at).find(|&start| moves(start))?;
        relocations.push(start as u32);
        at = start + FIELD_BYTES;
    }
    let mut stored = code.clone();
    for &start in &relocations {
        let start = start as usize;
        let value = field(code, start).wrapping_sub(page);
        stored[start..start + FIELD_BYTES].copy_from_slice(&value.to_le_bytes());
    }
    let page_offset = |guest: u64| {
        u16::try_from(guest.wrapping_sub(page))
            .ok()
            .filter(|&offset| usize::from(offset) < PAGE_BYTES)
    };
    let entry = Entry {
        context,
        offset: page_offset(pc)?,
        source_bytes: u16::try_from(block.source_bytes).ok()?,
        code: stored,
        relocations,
        source_map: block
            .native
            .source_map
            .iter()
            .map(|&(guest, native)| Some((page_offset(guest.0)?, u32::try_from(native).ok()?)))
            .collect::<Option<_>>()?,
        exits: block
            .direct_exits
            .iter()
            .map(|exit| {
                Some(Exit {
                    offset: u32::try_from(exit.offset).ok()?,
                    target: exit.target.0.wrapping_sub(page),
                    kind: exit.kind as u8,
                })
            })
            .collect::<Option<_>>()?,
        recovery: block.fault_recovery.clone(),
    };
    entry.consistent().then_some(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::{
        TargetCpu,
        block::{BlockProfile, CompilationPlan},
        x86_64::MemoryChecks,
    };

    const PAGE: u64 = 0x1_0000_4000;

    fn words(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    fn compile(source: &[u8], pc: u64) -> CompiledBlock {
        CompilationPlan::new(
            source,
            GuestAddress(pc),
            BlockProfile::SystemModeV1,
            TargetCpu::Baseline,
        )
        .and_then(|plan| plan.with_memory_checks(MemoryChecks::system(true, false, true, true)))
        .and_then(CompilationPlan::compile)
        .unwrap()
    }

    fn proved(source: &[u8], offset: u64) -> Option<Entry> {
        let pc = PAGE + offset;
        let block = compile(source, pc);
        let [first, second] = probe_displacements(PAGE);
        let probes = [
            compile(source, pc.wrapping_add(first)),
            compile(source, pc.wrapping_add(second)),
        ];
        prove(
            &block,
            PAGE,
            pc,
            Digest::of(b"context"),
            [&probes[0], &probes[1]],
        )
    }

    #[test]
    fn address_dependent_blocks_rebase_to_what_the_compiler_emits_at_another_page() {
        // adrp x0, 1; add x0, x0, #8; ldr x1, #16; bl +8
        let source = words(&[0x9000_0020, 0x9100_2000, 0x5800_0081, 0x9400_0002]);
        let entry = proved(&source, 0x40).expect("relocatable");
        assert!(entry.relocations.len() >= 3, "{:?}", entry.relocations);
        for other in [0x2_3456_8000u64, 0x4000, 0x7fff_0000_0000] {
            let expected = compile(&source, other + 0x40);
            let rebased = entry.rebase(other).unwrap();
            assert_eq!(
                rebased.native.x86_64_code, expected.native.x86_64_code,
                "page {other:#x}"
            );
            assert_eq!(rebased.native.source_map, expected.native.source_map);
            assert_eq!(rebased.direct_exits, expected.direct_exits);
            assert_eq!(rebased.fault_recovery, expected.fault_recovery);
            assert_eq!(rebased.source_bytes, expected.source_bytes);
        }
    }

    #[test]
    fn records_reject_malformed_source_geometry_with_a_valid_checksum() {
        let source = words(&[0x9000_0020, 0x9100_2000, 0x5800_0081, 0x9400_0002]);
        let entry = proved(&source, 0x40).expect("actual relocatable four-word block");
        assert_eq!(entry.source_map.len(), 4);
        assert!(entry.consistent());
        assert!(entry.source_map[1].1 > 1);
        let (translator, key) = (translator_id(), Digest::of(&[7; PAGE_BYTES]));
        let mut good = Record::new(translator, key);
        good.insert(entry.clone());
        assert_eq!(
            Record::decode(&good.encode(), &translator, &key),
            Ok(good.clone())
        );
        type Mutation = (&'static str, fn(&mut Entry));
        let mutations: [Mutation; 15] = [
            ("missing word", |entry| {
                entry.source_map.remove(1);
            }),
            ("duplicate guest", |entry| {
                entry.source_map[1].0 = entry.source_map[0].0
            }),
            ("guest gap", |entry| entry.source_map[1].0 += 4),
            ("equal native", |entry| {
                entry.source_map[1].1 = entry.source_map[0].1
            }),
            ("descending native", |entry| {
                entry.source_map[2].1 = entry.source_map[1].1 - 1
            }),
            ("one-past native", |entry| {
                entry.source_map[3].1 = u32::try_from(entry.code.len()).unwrap()
            }),
            ("out-of-range native", |entry| {
                entry.source_map[3].1 = u32::try_from(entry.code.len() + 1).unwrap()
            }),
            ("wrong native entry", |entry| entry.source_map[0].1 = 1),
            ("unaligned source base", |entry| {
                entry.offset += 1;
                for (guest, _) in &mut entry.source_map {
                    *guest += 1;
                }
            }),
            ("partial source word", |entry| entry.source_bytes += 1),
            ("empty extent", |entry| {
                entry.source_bytes = 0;
                entry.source_map.clear();
            }),
            ("page crossing", |entry| {
                entry.offset = PAGE_BYTES as u16 - 4;
                for (index, (guest, _)) in entry.source_map.iter_mut().enumerate() {
                    *guest = entry.offset + index as u16 * 4;
                }
            }),
            ("wrong first guest", |entry| entry.source_map[0].0 += 4),
            ("overflowing relocation", |entry| {
                entry.relocations = vec![u32::MAX, u32::MAX]
            }),
            ("overlapping relocations", |entry| {
                let first = entry.relocations[0];
                entry.relocations = vec![first, first + FIELD_BYTES as u32 - 1];
            }),
        ];
        for (name, mutate) in mutations {
            let mut bad = entry.clone();
            mutate(&mut bad);
            assert!(!bad.consistent(), "{name}");
            let mut record = Record::new(translator, key);
            record.insert(bad);
            // The actual writer recomputes lengths and checksum: this reaches
            // the loader's source geometry check, not a checksum failure.
            assert_eq!(
                Record::decode(&record.encode(), &translator, &key),
                Err(FormatError::Entry),
                "{name}"
            );
        }
        assert_eq!(Record::decode(&good.encode(), &translator, &key), Ok(good));
    }

    #[test]
    fn a_narrowed_page_address_is_not_relocatable() {
        // adrp x8, 0; add w9, w8, #0x20 (a 32-bit result of the address); ret
        let source = words(&[0x9000_0008, 0x1100_8109, 0xd65f_03c0]);
        assert_eq!(proved(&source, 0), None);
    }

    #[test]
    fn records_round_trip_and_refuse_every_damaged_byte_of_their_header_and_trailer() {
        let source = words(&[0x9000_0020, 0x9400_0002]);
        let entry = proved(&source, 0x10).unwrap();
        let (translator, key) = (translator_id(), Digest::of(&[7; PAGE_BYTES]));
        let mut record = Record::new(translator, key);
        record.insert(entry.clone());
        record.insert(entry);
        assert_eq!(record.entries.len(), 1);
        let bytes = record.encode();
        assert_eq!(
            Record::decode(&bytes, &translator, &key),
            Ok(record.clone())
        );
        assert_eq!(
            Record::decode(&bytes, &Digest::default(), &key),
            Err(FormatError::Translator)
        );
        assert_eq!(
            Record::decode(&bytes, &translator, &Digest::default()),
            Err(FormatError::Key)
        );
        for at in (0..bytes.len()).step_by(7) {
            let mut damaged = bytes.clone();
            damaged[at] ^= 0x40;
            assert!(
                Record::decode(&damaged, &translator, &key).is_err(),
                "byte {at}"
            );
        }
        for length in [0, HEADER_BYTES, bytes.len() - 1] {
            assert!(Record::decode(&bytes[..length], &translator, &key).is_err());
        }
    }

    #[test]
    fn probes_stay_in_the_address_class_of_their_page() {
        for page in [0u64, 0x1_8000_0000, 0x7fff_ffff_c000, 0xffff_fe00_0700_4000] {
            for displacement in probe_displacements(page) {
                let moved = page.wrapping_add(displacement);
                assert_eq!(address_class(moved), address_class(page), "{page:#x}");
                assert_eq!(moved & 0x3fff, page & 0x3fff);
            }
        }
    }
}
