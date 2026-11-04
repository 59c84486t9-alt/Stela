//! An installed block's minted recovery rows in one allocation, for as long
//! as the code lives. Faults read them; everything else only holds them, so
//! they are packed for that: LEB128 deltas in table order, a few bytes per
//! row against a [`FaultRecovery`] and its binding allocation.
use super::{
    FaultRecovery, RecoveryBinding, RecoverySite, RecoverySource, RetirementPhase, RetirementPoint,
    SpillOffset,
};
use crate::GuestAddress;
use alloc::{borrow::Cow, boxed::Box, vec::Vec};

const AFTER_FALLTHROUGH: u8 = 1 << 2;
const TRANSLATED: u8 = 1 << 3;
const SEPARATE_PC_DELTA: u8 = 1 << 4;
const BINDINGS_SHIFT: u32 = 5;
const LONG_BINDINGS: usize = 7;
const RETAINED_ROWS: usize = 4;
const RETAINED_BINDINGS: usize = 32;

fn zigzag(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)) as u64
}

fn unzigzag(value: u64) -> i64 {
    (value >> 1) as i64 ^ -((value & 1) as i64)
}

fn put(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Minted rows, packed. Only [`PackedRecovery::new`] makes one, from rows
/// that are already minted: the bytes grant nothing a caller could forge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedRecovery(Box<[u8]>);

struct Reader<'a> {
    bytes: &'a [u8],
}
impl Reader<'_> {
    fn byte(&mut self) -> u8 {
        let (&first, rest) = self.bytes.split_first().expect("packed by new");
        self.bytes = rest;
        first
    }
    fn value(&mut self) -> u64 {
        let (mut value, mut shift) = (0, 0);
        loop {
            let byte = self.byte();
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return value;
            }
            shift += 7;
        }
    }

    fn skip_bindings(&mut self, count: usize) {
        // A guest byte and a single-byte source, as for every host GPR.
        let (head, tail) = self.bytes.split_at(2 * count);
        if head
            .as_chunks::<2>()
            .0
            .iter()
            .all(|binding| binding[1] < 0x80)
        {
            self.bytes = tail;
            return;
        }
        for _ in 0..count {
            self.byte();
            self.value();
        }
    }
}

impl PackedRecovery {
    pub fn new(rows: &[FaultRecovery]) -> Self {
        if rows.is_empty() {
            return Self(Box::default());
        }
        let mut out = Vec::with_capacity(rows.len() * 12 + 2);
        put(&mut out, rows.len() as u64);
        let (mut end, mut pc, mut retired) = (0, 0, 0);
        for row in rows {
            let point = row.retirement;
            let at = point.instruction_pc().0;
            let site = row.site;
            let pc_delta = at.wrapping_sub(pc) as i64;
            let retired_delta = i64::from(point.retired_before()) - retired;
            let separate_pc = pc_delta != retired_delta * 4;
            let inline_bindings = row.bindings.len().min(LONG_BINDINGS);
            let start = zigzag(row.start as i64 - end);
            let span = (row.end - row.start) as u64;
            let delta = zigzag(retired_delta);
            let translated = site.translated_access();
            let tag = site.kind() as u8
                | if point.phase() == RetirementPhase::AfterFallthrough {
                    AFTER_FALLTHROUGH
                } else {
                    0
                }
                | if translated.is_some() { TRANSLATED } else { 0 }
                | if separate_pc { SEPARATE_PC_DELTA } else { 0 }
                | (inline_bindings as u8) << BINDINGS_SHIFT;
            if (start | span | delta) < 0x80 {
                out.extend_from_slice(&[start as u8, span as u8, delta as u8, tag]);
            } else {
                put(&mut out, start);
                put(&mut out, span);
                put(&mut out, delta);
                out.push(tag);
            }
            // The PC normally advances by four bytes for each instruction
            // retired. Keep a separate delta only when the row differs.
            if separate_pc {
                put(&mut out, zigzag(pc_delta));
            }
            if let Some(access) = translated {
                out.extend_from_slice(&[access.bytes, access.flags]);
            }
            if inline_bindings == LONG_BINDINGS {
                put(&mut out, row.bindings.len() as u64);
            }
            for binding in &row.bindings {
                out.push(binding.guest);
                put(
                    &mut out,
                    match binding.source {
                        RecoverySource::HostRegister(register) => u64::from(register) << 1,
                        RecoverySource::NativeSpill(offset) => u64::from(offset.bytes()) << 1 | 1,
                    },
                );
            }
            (end, pc, retired) = (row.end as i64, at, i64::from(point.retired_before()));
        }
        Self(out.into_boxed_slice())
    }

    /// The packed length.
    pub fn bytes(&self) -> usize {
        self.0.len()
    }

    /// The rows given to [`Self::new`].
    pub fn rows(&self) -> Vec<FaultRecovery> {
        let mut rows = Vec::new();
        self.decode(None, &mut rows);
        rows
    }

    /// Rows that apply at this native offset, plus any malformed ranges that
    /// the caller must reject regardless of where the fault occurred.
    pub fn rows_at(&self, offset: usize) -> Vec<FaultRecovery> {
        let mut rows = Vec::new();
        self.decode(Some(offset), &mut rows);
        rows
    }

    /// Like [`Self::rows_at`], reusing storage across fault lookups. Large
    /// tables are owned by this lookup alone, so the scratch retains only
    /// enough space for a few rows and a register file's worth of bindings
    /// in each.
    pub fn rows_at_reusing<'a>(
        &self,
        offset: usize,
        scratch: &'a mut Vec<FaultRecovery>,
    ) -> Cow<'a, [FaultRecovery]> {
        let count = self.decode(Some(offset), scratch);
        if scratch.capacity() > RETAINED_ROWS
            || scratch
                .iter()
                .any(|row| row.bindings.capacity() > RETAINED_BINDINGS)
        {
            let mut rows = core::mem::take(scratch);
            rows.truncate(count);
            Cow::Owned(rows)
        } else {
            Cow::Borrowed(&scratch[..count])
        }
    }

    fn decode(&self, offset: Option<usize>, rows: &mut Vec<FaultRecovery>) -> usize {
        if self.0.is_empty() {
            return 0;
        }
        let mut reader = Reader { bytes: &self.0 };
        let count = reader.value() as usize;
        if offset.is_none() {
            rows.reserve(count);
        }
        let mut kept = 0;
        let (mut end, mut pc, mut retired) = (0, 0, 0);
        for _ in 0..count {
            let start = end + unzigzag(reader.value());
            let row_end = start + reader.value() as i64;
            let retired_delta = unzigzag(reader.value());
            retired += retired_delta;
            let tag = reader.byte();
            let pc_delta = if tag & SEPARATE_PC_DELTA == 0 {
                retired_delta * 4
            } else {
                unzigzag(reader.value())
            };
            pc = u64::wrapping_add_signed(pc, pc_delta);
            let translated = (tag & TRANSLATED != 0).then(|| (reader.byte(), reader.byte()));
            let inline_bindings = usize::from(tag >> BINDINGS_SHIFT);
            let binding_count = if inline_bindings == LONG_BINDINGS {
                reader.value() as usize
            } else {
                inline_bindings
            };
            let range = start as usize..row_end as usize;
            end = row_end;
            if offset.is_some_and(|at| range.start < range.end && !range.contains(&at)) {
                reader.skip_bindings(binding_count);
                continue;
            }
            let mut bindings = rows.get_mut(kept).map_or_else(Vec::new, |row| {
                let mut bindings = core::mem::take(&mut row.bindings);
                bindings.clear();
                bindings
            });
            bindings.extend((0..binding_count).map(|_| {
                let guest = reader.byte();
                let source = reader.value();
                RecoveryBinding {
                    guest,
                    source: if source & 1 == 0 {
                        RecoverySource::HostRegister((source >> 1) as u8)
                    } else {
                        RecoverySource::NativeSpill(
                            SpillOffset::new((source >> 1) as u16).expect("packed by new"),
                        )
                    },
                }
            }));
            let row = FaultRecovery {
                start: range.start,
                end: range.end,
                bindings,
                retirement: RetirementPoint::packed(
                    GuestAddress(pc),
                    retired as u16,
                    if tag & AFTER_FALLTHROUGH != 0 {
                        RetirementPhase::AfterFallthrough
                    } else {
                        RetirementPhase::Before
                    },
                ),
                site: RecoverySite::packed(tag & 3, translated),
            };
            if let Some(prior) = rows.get_mut(kept) {
                *prior = row;
            } else {
                rows.push(row);
            }
            kept += 1;
        }
        kept
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn empty_tables_keep_no_payload() {
        let packed = PackedRecovery::new(&[]);
        assert_eq!(packed.bytes(), 0);
        assert!(packed.rows().is_empty());
    }

    #[test]
    fn a_large_binding_count_round_trips_with_a_separate_pc_delta() {
        let row = FaultRecovery {
            start: 10,
            end: 15,
            bindings: (0..12)
                .map(|register| RecoveryBinding::gpr(register, register))
                .collect(),
            retirement: RetirementPoint::before(GuestAddress(0x1234_8000), 26).unwrap(),
            site: RecoverySite::guest_access(),
        };
        let packed = PackedRecovery::new(core::slice::from_ref(&row));
        assert_eq!(packed.rows(), [row]);
    }

    #[test]
    fn selected_rows_keep_overlaps_and_malformed_ranges() {
        let row = |start, end| FaultRecovery {
            start,
            end,
            bindings: vec![RecoveryBinding::gpr(1, 2)],
            retirement: RetirementPoint::before(GuestAddress(0x4000), 0).unwrap(),
            site: RecoverySite::guest_access(),
        };
        let rows = [row(0, 4), row(8, 16), row(9, 11), row(100, 100)];
        let packed = PackedRecovery::new(&rows);
        assert_eq!(
            packed.rows_at(10),
            [rows[1].clone(), rows[2].clone(), rows[3].clone()],
        );
        assert_eq!(packed.rows_at(16), [rows[3].clone()]);

        let mut scratch = Vec::new();
        let selected = packed.rows_at_reusing(10, &mut scratch);
        assert_eq!(selected.as_ref(), packed.rows_at(10));
        let bindings = selected[0].bindings.as_ptr();
        let selected = packed.rows_at_reusing(16, &mut scratch);
        assert_eq!(selected.as_ref(), packed.rows_at(16));
        assert_eq!(selected[0].bindings.as_ptr(), bindings);
    }

    #[test]
    fn oversized_fault_tables_do_not_grow_the_scratch() {
        let row = FaultRecovery {
            start: 0,
            end: 4,
            bindings: vec![RecoveryBinding::gpr(1, 2)],
            retirement: RetirementPoint::before(GuestAddress(0x4000), 0).unwrap(),
            site: RecoverySite::guest_access(),
        };
        let rows = vec![row.clone(); RETAINED_ROWS + 1];
        let bindings = FaultRecovery {
            bindings: vec![RecoveryBinding::gpr(1, 2); RETAINED_BINDINGS + 1],
            ..row
        };
        for table in [&rows[..], &[bindings][..]] {
            let packed = PackedRecovery::new(table);
            let mut scratch = Vec::new();
            let selected = packed.rows_at_reusing(0, &mut scratch);
            assert!(matches!(selected, Cow::Owned(_)));
            assert_eq!(selected.as_ref(), table);
            assert_eq!(scratch.capacity(), 0);
        }
    }

    #[test]
    fn rows_survive_packing_exactly_and_in_order() {
        let pc = 0xffff_fe00_0912_3000;
        let point = |offset: u64, retired| {
            RetirementPoint::before(GuestAddress(pc + offset), retired).unwrap()
        };
        let rows = vec![
            FaultRecovery {
                start: 40,
                end: 47,
                bindings: vec![
                    RecoveryBinding::gpr(3, 9),
                    RecoveryBinding::spill(30, SpillOffset::new(96).unwrap()),
                ],
                retirement: point(8, 2),
                site: RecoverySite::guest_access(),
            },
            // Overlapping and moving backwards, as a table may.
            FaultRecovery {
                start: 10,
                end: 300,
                bindings: vec![],
                retirement: point(0, 0),
                site: RecoverySite::native_internal(),
            },
            FaultRecovery {
                start: 12,
                end: 13,
                bindings: vec![],
                retirement: point(4, 1),
                site: RecoverySite::translated_helper(8, 0b101),
            },
            FaultRecovery {
                start: 14,
                end: 15,
                bindings: vec![],
                retirement: point(4, 1),
                site: RecoverySite::guest_check(),
            },
        ];
        let packed = PackedRecovery::new(&rows);
        assert_eq!(packed.rows(), rows);
        assert_eq!(packed.rows_at(13), [rows[1].clone()]);
        assert!(packed.0.len() < 64);
        assert_eq!(PackedRecovery::new(&[]).rows(), []);
    }
}
