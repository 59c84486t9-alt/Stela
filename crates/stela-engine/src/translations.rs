//! The persistent translation store's format
//! (`docs/design/runtime.md#persistent-translation-store`): page records of
//! block translations keyed by the SHA-256 of their guest fetch page, with
//! guest addresses in the native code stored relative to the page, and the
//! proof that a block's code depends on its address only through them.
//!
//! The format is the same in every container: the directory store
//! and the pack `stela.efi` keeps
//! ([`pack`]).
pub mod pack;

use alloc::{string::String, vec::Vec};
use sha2::Digest as _;
use stela_compiler::block::Features;
use stela_compiler::{
    GuestAddress, NativeBlock,
    block::{
        CompiledBlock, ExitKind, RecoveryBinding, RecoverySiteKind, RecoverySource,
        RetirementPhase, RetirementPoint, SpillOffset, UnqualifiedFaultRecovery,
    },
    x86_64::chain::DirectExit,
};
use stela_crypto::Sha256;

/// The bytes of the fetch page a record covers: no block leaves it.
pub const PAGE_BYTES: usize = 4096;
pub const SCHEMA: u32 = 3;
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
    let abi = stela_compiler::block::BlockProfile::new(Features::SYSTEM_MODE).abi();
    for part in [
        abi.as_str(),
        stela_compiler::SOURCE_SHA256,
        ENGINE_SOURCE_SHA256,
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    Digest(hasher.finalize().into())
}

/// The runtime crate's sources (`build.rs`).
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
    /// Exact admitted instruction bytes given to the compiler, including any
    /// analyzed suffix beyond the emitted block. Raw fetch-page identity and
    /// the preparation context remain separate record bindings.
    pub input: Vec<u8>,
    /// Native code, each relocation field holding `value - page`.
    pub code: Vec<u8>,
    /// Code offsets of the relocation fields, ascending.
    pub relocations: Vec<u32>,
    /// Page offset of each guest instruction and its native offset.
    pub source_map: Vec<(u16, u32)>,
    pub exits: Vec<Exit>,
    pub recovery: Vec<UnqualifiedFaultRecovery>,
}

/// A rebased immutable template. Persisted fault tags remain unchecked until
/// the exact input/profile/template passes compiler plan validation.
#[derive(Debug, Clone)]
pub struct StoredBlock {
    pub native: NativeBlock,
    pub source_bytes: usize,
    pub direct_exits: Vec<DirectExit>,
    pub fault_recovery: Vec<UnqualifiedFaultRecovery>,
}

impl Entry {
    /// The block as compiled at the page whose address is `page`.
    pub fn rebase(&self, page: u64, admitted: &[u8]) -> Option<StoredBlock> {
        if !self.consistent() || admitted.get(..self.input.len())? != self.input {
            return None;
        }
        if !page.is_multiple_of(PAGE_BYTES as u64) {
            return None;
        }
        page.checked_add(u64::from(self.offset))?
            .checked_add(u64::from(self.source_bytes))?;
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
        Some(StoredBlock {
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
            fault_recovery: self
                .recovery
                .iter()
                .map(|row| {
                    let mut row = row.clone();
                    row.retirement = self.retirement_at(row.retirement, page)?;
                    Some(row)
                })
                .collect::<Option<_>>()?,
        })
    }

    /// Reconstruct only a source-backed retirement shape. This never mints a
    /// guest-access site or grants memory-effect permission from a portable tag.
    fn retirement_at(&self, point: RetirementPoint, page: u64) -> Option<RetirementPoint> {
        use stela_compiler::Lifter as _;
        let relative = point
            .instruction_pc()
            .0
            .checked_sub(u64::from(self.offset))?;
        if !relative.is_multiple_of(4)
            || relative > u64::from(self.source_bytes)
            || u64::from(point.retired_before()) != relative / 4
        {
            return None;
        }
        let pc = GuestAddress(page.checked_add(point.instruction_pc().0)?);
        match point.phase() {
            RetirementPhase::Before => RetirementPoint::before(pc, point.retired_before()).ok(),
            RetirementPhase::AfterFallthrough => {
                let at = usize::try_from(relative).ok()?;
                if at.checked_add(4)? > usize::from(self.source_bytes) {
                    return None;
                }
                let word = u32::from_le_bytes(self.input.get(at..at + 4)?.try_into().ok()?);
                let instruction = stela_compiler::aarch64::Decoder.lift(pc, word).ok()?;
                RetirementPoint::from_instruction(
                    &instruction,
                    point.retired_before(),
                    point.phase(),
                )
                .ok()
            }
        }
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
            && self.input.len() >= usize::from(self.source_bytes)
            && self.input.len().is_multiple_of(4)
            && usize::from(self.offset)
                .checked_add(self.input.len())
                .is_some_and(|end| end <= PAGE_BYTES)
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
                range.start < range.end
                    && range.end <= code
                    && self.retirement_at(range.retirement, 0).is_some()
                    && (range.site == RecoverySiteKind::NativeInternal
                        || range.retirement.phase() == RetirementPhase::Before)
                    && range.bindings.iter().all(|binding| {
                        binding.guest <= 31
                            && match binding.source {
                                RecoverySource::HostRegister(host) => host < 32,
                                RecoverySource::NativeSpill(_) => true,
                            }
                    })
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
            out.extend((entry.input.len() as u16).to_le_bytes());
            out.extend(&entry.input);
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
                out.extend(range.retirement.instruction_pc().0.to_le_bytes());
                out.extend(range.retirement.retired_before().to_le_bytes());
                out.push(match range.retirement.phase() {
                    RetirementPhase::Before => 0,
                    RetirementPhase::AfterFallthrough => 1,
                });
                out.push(range.site as u8);
                out.extend((range.bindings.len() as u32).to_le_bytes());
                for binding in &range.bindings {
                    out.push(binding.guest);
                    let (kind, value) = match binding.source {
                        RecoverySource::HostRegister(host) => (0, u16::from(host)),
                        RecoverySource::NativeSpill(offset) => (1, offset.bytes()),
                    };
                    out.push(kind);
                    out.extend(value.to_le_bytes());
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
        let input_bytes = usize::from(self.u16()?);
        if input_bytes > PAGE_BYTES {
            return Err(FormatError::Entry);
        }
        let input = self.take(input_bytes)?.to_vec();
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
        let recovery = (0..self.count(24)?)
            .map(|_| {
                let start = self.u32()? as usize;
                let end = self.u32()? as usize;
                let pc = GuestAddress(self.u64()?);
                let count = self.u16()?;
                let phase = match self.u8()? {
                    0 => RetirementPhase::Before,
                    1 => RetirementPhase::AfterFallthrough,
                    _ => return Err(FormatError::Entry),
                };
                let site =
                    RecoverySiteKind::try_from(self.u8()?).map_err(|_| FormatError::Entry)?;
                let bindings = (0..self.count(4)?)
                    .map(|_| {
                        let guest = self.u8()?;
                        let kind = self.u8()?;
                        let value = self.u16()?;
                        let source = match kind {
                            0 => RecoverySource::HostRegister(
                                u8::try_from(value).map_err(|_| FormatError::Entry)?,
                            ),
                            1 => RecoverySource::NativeSpill(
                                SpillOffset::new(value).map_err(|_| FormatError::Entry)?,
                            ),
                            _ => return Err(FormatError::Entry),
                        };
                        Ok(RecoveryBinding { guest, source })
                    })
                    .collect::<Result<_, _>>()?;
                // Build a structurally valid source-backed shape using an
                // entry view below; no raw After constructor is exposed.
                let before = RetirementPoint::before(pc, count).map_err(|_| FormatError::Entry)?;
                let retirement = match phase {
                    RetirementPhase::Before => before,
                    RetirementPhase::AfterFallthrough => {
                        use stela_compiler::Lifter as _;
                        let at = usize::try_from(
                            pc.0.checked_sub(u64::from(offset))
                                .ok_or(FormatError::Entry)?,
                        )
                        .map_err(|_| FormatError::Entry)?;
                        if at.checked_add(4).ok_or(FormatError::Entry)? > usize::from(source_bytes)
                        {
                            return Err(FormatError::Entry);
                        }
                        let word = u32::from_le_bytes(
                            input
                                .get(at..at + 4)
                                .ok_or(FormatError::Entry)?
                                .try_into()
                                .map_err(|_| FormatError::Entry)?,
                        );
                        let instruction = stela_compiler::aarch64::Decoder
                            .lift(pc, word)
                            .map_err(|_| FormatError::Entry)?;
                        RetirementPoint::from_instruction(&instruction, count, phase)
                            .map_err(|_| FormatError::Entry)?
                    }
                };
                Ok(UnqualifiedFaultRecovery {
                    start,
                    end,
                    bindings,
                    retirement,
                    site,
                })
            })
            .collect::<Result<_, _>>()?;
        let code = self.take(code_bytes)?.to_vec();
        Ok(Entry {
            context,
            offset,
            source_bytes,
            input,
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
    input: &[u8],
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
            && probe.fault_recovery.len() == block.fault_recovery.len()
            && probe
                .fault_recovery
                .iter()
                .zip(&block.fault_recovery)
                .all(|(moved, original)| {
                    moved.start == original.start
                        && moved.end == original.end
                        && moved.bindings == original.bindings
                        && moved.site == original.site
                        && moved.retirement.phase() == original.retirement.phase()
                        && moved.retirement.retired_before() == original.retirement.retired_before()
                        && moved
                            .retirement
                            .instruction_pc()
                            .0
                            .wrapping_sub(original.retirement.instruction_pc().0)
                            == displacement
                })
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
        input: input.to_vec(),
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
        recovery: block
            .fault_recovery
            .iter()
            .map(|row| {
                let mut row = UnqualifiedFaultRecovery::from(row);
                row.retirement = row
                    .retirement
                    .relocated(GuestAddress(
                        row.retirement.instruction_pc().0.checked_sub(page)?,
                    ))
                    .ok()?;
                Some(row)
            })
            .collect::<Option<_>>()?,
    };
    entry.consistent().then_some(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::{TargetCpu, block::BlockProfile, x86_64::MemoryChecks};

    const PAGE: u64 = 0x1_0000_4000;

    fn words(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    fn compile(source: &[u8], pc: u64) -> CompiledBlock {
        let options = stela_compiler::Options::new(
            BlockProfile::new(Features::SYSTEM_MODE),
            TargetCpu::Baseline,
        )
        .with_memory_checks(MemoryChecks::system(true, false, true, true));
        stela_compiler::compile(source, GuestAddress(pc), &options).unwrap()
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
            source,
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
            let rebased = entry.rebase(other, &source).unwrap();
            assert_eq!(
                rebased.native.x86_64_code, expected.native.x86_64_code,
                "page {other:#x}"
            );
            assert_eq!(rebased.native.source_map, expected.native.source_map);
            assert_eq!(rebased.direct_exits, expected.direct_exits);
            assert_eq!(
                rebased.fault_recovery,
                expected
                    .fault_recovery
                    .iter()
                    .map(UnqualifiedFaultRecovery::from)
                    .collect::<Vec<_>>()
            );
            assert_eq!(rebased.source_bytes, expected.source_bytes);
        }
    }

    #[test]
    fn stored_source_witness_requires_the_exact_admitted_compiler_prefix() {
        // The compiler stops at B, but the complete offered analysis input is
        // kept. Changing that suffix must not silently change its witness.
        let source = words(&[0x1400_0002, 0xd503_201f, 0xd65f_03c0]);
        let entry = proved(&source, 0x40).expect("relocatable branch");
        assert_eq!(entry.source_bytes, 4);
        assert_eq!(entry.input, source);
        let translator = translator_id();
        let key = Digest::of(b"raw fetch page identity");
        let mut record = Record::new(translator, key);
        record.insert(entry.clone());
        let decoded = Record::decode(&record.encode(), &translator, &key).unwrap();
        let held = &decoded.entries[0];
        assert_eq!(held.input, source);
        assert!(held.rebase(PAGE, &source).is_some());
        for at in 0..source.len() {
            let mut changed = source.clone();
            changed[at] ^= 1;
            assert!(held.rebase(PAGE, &changed).is_none(), "input byte {at}");
        }
        for length in 0..source.len() {
            assert!(held.rebase(PAGE, &source[..length]).is_none());
        }
        let mut longer_window = source.clone();
        longer_window.extend(words(&[0xd503_201f]));
        assert!(held.rebase(PAGE, &longer_window).is_some());
        assert!(held.rebase(u64::MAX - 3, &source).is_none());
        assert!(held.rebase(!(PAGE_BYTES as u64 - 1), &source).is_some());
        assert!(held.rebase(PAGE + 4, &source).is_none());
    }

    #[test]
    fn source_witness_geometry_is_checked_even_with_a_valid_record_checksum() {
        let source = words(&[0x1400_0002, 0xd503_201f, 0xd65f_03c0]);
        let original = proved(&source, 0x40).unwrap();
        let translator = translator_id();
        let key = Digest::of(b"raw fetch page identity");
        for input in [
            vec![],
            vec![0; 3],
            vec![0; PAGE_BYTES],
            vec![0; PAGE_BYTES + 4],
        ] {
            let mut entry = original.clone();
            entry.input = input;
            assert!(!entry.consistent());
            assert!(entry.rebase(PAGE, &source).is_none());
            let mut record = Record::new(translator, key);
            record.insert(entry);
            assert_eq!(
                Record::decode(&record.encode(), &translator, &key),
                Err(FormatError::Entry)
            );
        }
        let mut legacy = Record::new(translator, key);
        legacy.insert(original);
        let mut bytes = legacy.encode();
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        let end = bytes.len() - TRAILER_BYTES;
        let checksum = Sha256::digest(&bytes[..end]);
        bytes[end..].copy_from_slice(&checksum);
        assert_eq!(
            Record::decode(&bytes, &translator, &key),
            Err(FormatError::Schema)
        );
    }

    #[test]
    fn portable_after_phase_requires_the_actual_retained_fallthrough_instruction() {
        use stela_compiler::Lifter as _;
        let source = words(&[0xd503201f, 0xd4000001]);
        let mut entry = proved(&source, 0x40).unwrap();
        let instruction = stela_compiler::aarch64::Decoder
            .lift(GuestAddress(0x40), 0xd503201f)
            .unwrap();
        entry.recovery = vec![UnqualifiedFaultRecovery {
            start: 0,
            end: 1,
            bindings: Vec::new(),
            retirement: RetirementPoint::after_fallthrough(&instruction, 0).unwrap(),
            site: RecoverySiteKind::NativeInternal,
        }];
        let (translator, key) = (translator_id(), Digest::of(b"phase fixture raw page"));
        let encode = |entry| {
            let mut record = Record::new(translator, key);
            record.insert(entry);
            record.encode()
        };
        let decoded = Record::decode(&encode(entry.clone()), &translator, &key).unwrap();
        let row = &decoded.entries[0]
            .rebase(PAGE, &source)
            .unwrap()
            .fault_recovery[0];
        assert_eq!(row.retirement.position().unwrap().pc.0, PAGE + 0x44);
        assert_eq!(
            row.site,
            RecoverySiteKind::NativeInternal,
            "portable decoding never mints a guest site"
        );
        let mut branch = entry.clone();
        branch.input[..4].copy_from_slice(&0xd65f03c0_u32.to_le_bytes());
        assert_eq!(
            Record::decode(&encode(branch), &translator, &key),
            Err(FormatError::Entry),
            "serialized After does not authorize RET fallthrough"
        );
        let mut guest_after = entry;
        guest_after.recovery[0].site = RecoverySiteKind::GuestAccess;
        assert_eq!(
            Record::decode(&encode(guest_after), &translator, &key),
            Err(FormatError::Entry)
        );
    }

    #[test]
    fn portable_before_endpoint_keeps_exact_prefix_count_and_checked_relocation() {
        let source = words(&[0xd503201f, 0xd4000001]);
        let mut entry = proved(&source, 0x40).unwrap();
        let end = u64::from(entry.offset) + u64::from(entry.source_bytes);
        let count = entry.source_bytes / 4;
        entry.recovery = vec![UnqualifiedFaultRecovery {
            start: 0,
            end: 1,
            bindings: Vec::new(),
            retirement: RetirementPoint::before(GuestAddress(end), count).unwrap(),
            site: RecoverySiteKind::NativeInternal,
        }];
        assert!(entry.consistent());
        let rebased = entry.rebase(PAGE, &source).unwrap();
        assert_eq!(
            rebased.fault_recovery[0]
                .retirement
                .position()
                .unwrap()
                .pc
                .0,
            PAGE + end
        );
        assert_eq!(
            rebased.fault_recovery[0]
                .retirement
                .position()
                .unwrap()
                .retired_instructions,
            count
        );
        let (translator, key) = (translator_id(), Digest::of(b"endpoint fixture raw page"));
        let mut record = Record::new(translator, key);
        record.insert(entry.clone());
        assert_eq!(
            Record::decode(&record.encode(), &translator, &key),
            Ok(record)
        );
        entry.recovery[0].retirement =
            RetirementPoint::before(GuestAddress(end), count - 1).unwrap();
        let mut bad = Record::new(translator, key);
        bad.insert(entry);
        assert_eq!(
            Record::decode(&bad.encode(), &translator, &key),
            Err(FormatError::Entry)
        );
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
            // The writer recomputes lengths and checksum: this reaches
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
