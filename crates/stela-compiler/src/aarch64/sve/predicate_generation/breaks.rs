//! Predicate breaks decode operand roles without state-layout assumptions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Boundary {
    Before,
    After,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BreakKind {
    Break { boundary: Boundary, merging: bool },
    Next,
    Previous { boundary: Boundary, source: u8 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BreakOperand {
    pub kind: BreakKind,
    pub destination: u8,
    pub guard: u8,
    pub source: u8,
    pub set_flags: bool,
}

const PREDICATE_FIELD_MASK: u32 = 0xf;
const SOURCE_SHIFT: u32 = 5;
const GUARD_SHIFT: u32 = 10;
const PREVIOUS_SOURCE_SHIFT: u32 = 16;
const MERGING_BIT: u32 = 1 << 4;
const BREAK_MASK: u32 = 0xffff_c200;
const BREAK_FLAGS_MASK: u32 = 0xffff_c210;
const PREVIOUS_MASK: u32 = 0xfff0_c210;
const BRKA: u32 = 0x2510_4000;
const BRKAS: u32 = 0x2550_4000;
const BRKB: u32 = 0x2590_4000;
const BRKBS: u32 = 0x25d0_4000;
const BRKN: u32 = 0x2518_4000;
const BRKNS: u32 = 0x2558_4000;
const BRKPA: u32 = 0x2500_c000;
const BRKPAS: u32 = 0x2540_c000;
const BRKPB: u32 = 0x2500_c010;
const BRKPBS: u32 = 0x2540_c010;

fn predicate(word: u32, shift: u32) -> u8 {
    ((word >> shift) & PREDICATE_FIELD_MASK) as u8
}

pub fn decode(word: u32) -> Option<Result<BreakOperand, ()>> {
    let previous_source = predicate(word, PREVIOUS_SOURCE_SHIFT);
    let (kind, set_flags) = match word & BREAK_FLAGS_MASK {
        BRKAS => (
            BreakKind::Break {
                boundary: Boundary::After,
                merging: false,
            },
            true,
        ),
        BRKBS => (
            BreakKind::Break {
                boundary: Boundary::Before,
                merging: false,
            },
            true,
        ),
        BRKN => (BreakKind::Next, false),
        BRKNS => (BreakKind::Next, true),
        _ => match word & BREAK_MASK {
            BRKA => (
                BreakKind::Break {
                    boundary: Boundary::After,
                    merging: word & MERGING_BIT != 0,
                },
                false,
            ),
            BRKB => (
                BreakKind::Break {
                    boundary: Boundary::Before,
                    merging: word & MERGING_BIT != 0,
                },
                false,
            ),
            _ => match word & PREVIOUS_MASK {
                BRKPA => (
                    BreakKind::Previous {
                        boundary: Boundary::After,
                        source: previous_source,
                    },
                    false,
                ),
                BRKPAS => (
                    BreakKind::Previous {
                        boundary: Boundary::After,
                        source: previous_source,
                    },
                    true,
                ),
                BRKPB => (
                    BreakKind::Previous {
                        boundary: Boundary::Before,
                        source: previous_source,
                    },
                    false,
                ),
                BRKPBS => (
                    BreakKind::Previous {
                        boundary: Boundary::Before,
                        source: previous_source,
                    },
                    true,
                ),
                _ => return None,
            },
        },
    };
    Some(Ok(BreakOperand {
        kind,
        destination: predicate(word, 0),
        guard: predicate(word, GUARD_SHIFT),
        source: predicate(word, SOURCE_SHIFT),
        set_flags,
    }))
}

#[cfg(test)]
mod tests;
