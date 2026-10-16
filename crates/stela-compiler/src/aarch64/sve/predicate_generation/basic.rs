//! Basic predicate generation. Predicate indices are packed architectural P registers.
use crate::aarch64::scalable::ElementSize;
use crate::aarch64::{Register, Width, register};

const PREDICATE_MASK: u32 = 15;
const SCALAR_REGISTER_MASK: u32 = 31;
const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const FIRST_SOURCE_SHIFT: u32 = 5;
const GOVERNING_SHIFT: u32 = 10;
const SECOND_SOURCE_SHIFT: u32 = 16;
const PATTERN_MASK: u32 = 31;
const PN_MASK: u32 = 7;
const PN_BASE: u8 = 8;
const PFALSE_MASK: u32 = 0xffff_fff0;
const PFALSE_CLASS: u32 = 0x2518_e400;
const PFIRST_MASK: u32 = 0xffff_fe10;
const PFIRST_CLASS: u32 = 0x2558_c000;
const PNEXT_MASK: u32 = 0xff3f_fe10;
const PNEXT_CLASS: u32 = 0x2519_c400;
const PTEST_MASK: u32 = 0xffff_c21f;
const PTEST_CLASS: u32 = 0x2550_c000;
const PTRUE_MASK: u32 = 0xff3f_fc10;
const PTRUE_CLASS: u32 = 0x2518_e000;
const PTRUES_CLASS: u32 = 0x2519_e000;
const PTRUE_PN_MASK: u32 = 0xff3f_fff8;
const PTRUE_PN_CLASS: u32 = 0x2520_7810;
const CTERM_MASK: u32 = 0xffa0_fc1f;
const CTERMEQ_CLASS: u32 = 0x25a0_2000;
const CTERMNE_CLASS: u32 = 0x25a0_2010;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BasicOperand {
    False {
        destination: u8,
    },
    First {
        destination: u8,
        governing: u8,
    },
    Next {
        destination: u8,
        governing: u8,
        element: ElementSize,
    },
    Test {
        governing: u8,
        source: u8,
    },
    True {
        destination: u8,
        element: ElementSize,
        pattern: u8,
        set_flags: bool,
    },
    TrueCounter {
        destination: u8,
        element: ElementSize,
    },
    ConditionalTerminate {
        first: Register,
        second: Register,
        width: Width,
        equal: bool,
    },
}

/// No basic form has reserved operand encodings. Unnamed five-bit PTRUE patterns
/// execute with zero active elements; they are not decoder errors. GPR31 is ZR.
pub fn decode_basic(word: u32) -> Option<Result<BasicOperand, ()>> {
    let destination = (word & PREDICATE_MASK) as u8;
    let element = ElementSize::from_bytes(1 << ((word >> SIZE_SHIFT) & SIZE_MASK))?;
    let near_source = ((word >> FIRST_SOURCE_SHIFT) & PREDICATE_MASK) as u8;
    let operand = if word & PFALSE_MASK == PFALSE_CLASS {
        BasicOperand::False { destination }
    } else if word & PFIRST_MASK == PFIRST_CLASS {
        BasicOperand::First {
            destination,
            governing: near_source,
        }
    } else if word & PNEXT_MASK == PNEXT_CLASS {
        BasicOperand::Next {
            destination,
            governing: near_source,
            element,
        }
    } else if word & PTEST_MASK == PTEST_CLASS {
        BasicOperand::Test {
            governing: ((word >> GOVERNING_SHIFT) & PREDICATE_MASK) as u8,
            source: near_source,
        }
    } else if matches!(word & PTRUE_MASK, PTRUE_CLASS | PTRUES_CLASS) {
        BasicOperand::True {
            destination,
            element,
            pattern: ((word >> FIRST_SOURCE_SHIFT) & PATTERN_MASK) as u8,
            set_flags: word & PTRUE_MASK == PTRUES_CLASS,
        }
    } else if word & PTRUE_PN_MASK == PTRUE_PN_CLASS {
        BasicOperand::TrueCounter {
            destination: PN_BASE + (word & PN_MASK) as u8,
            element,
        }
    } else if matches!(word & CTERM_MASK, CTERMEQ_CLASS | CTERMNE_CLASS) {
        BasicOperand::ConditionalTerminate {
            first: register((word >> FIRST_SOURCE_SHIFT) & SCALAR_REGISTER_MASK, false),
            second: register((word >> SECOND_SOURCE_SHIFT) & SCALAR_REGISTER_MASK, false),
            width: if word & (1 << SIZE_SHIFT) == 0 {
                Width::W32
            } else {
                Width::X64
            },
            equal: word & CTERM_MASK == CTERMEQ_CLASS,
        }
    } else {
        return None;
    };
    Some(Ok(operand))
}

#[cfg(test)]
mod tests;
