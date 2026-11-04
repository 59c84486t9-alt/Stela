//! An installed block's minted recovery rows in one allocation, for as long
//! as the code lives. Faults read them; everything else only holds them, so
//! they are packed for that: LEB128 deltas in table order, a few bytes per
//! row against a [`FaultRecovery`] and its binding allocation.
use super::{
    FaultRecovery, RecoveryBinding, RecoverySite, RecoverySource, RetirementPhase, RetirementPoint,
    SpillOffset,
};
use crate::GuestAddress;
use alloc::{boxed::Box, vec::Vec};

const AFTER_FALLTHROUGH: u8 = 1 << 2;
const TRANSLATED: u8 = 1 << 3;
const SEPARATE_PC_DELTA: u8 = 1 << 4;
const BINDINGS_SHIFT: u32 = 5;
const LONG_BINDINGS: usize = 7;

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
        if self.0.is_empty() {
            return Vec::new();
        }
        let mut reader = Reader { bytes: &self.0 };
        let count = reader.value() as usize;
        let mut rows = Vec::with_capacity(count);
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
            let bindings = if inline_bindings == LONG_BINDINGS {
                reader.value() as usize
            } else {
                inline_bindings
            };
            let bindings = (0..bindings)
                .map(|_| {
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
                })
                .collect();
            rows.push(FaultRecovery {
                start: start as usize,
                end: row_end as usize,
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
            });
            end = row_end;
        }
        rows
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
                    RecoveryBinding::spill(30, SpillOffset::new(8).unwrap()),
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
        assert!(packed.0.len() < 64);
        assert_eq!(PackedRecovery::new(&[]).rows(), []);
    }
}
