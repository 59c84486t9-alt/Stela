//! Scalar WHILE conditions and predicate/counter destination roles.
const ELEMENT_SIZE_SHIFT: u32 = 22;
const ELEMENT_SIZE_MASK: u32 = 3;
const SOURCE_N_SHIFT: u32 = 5;
const SOURCE_M_SHIFT: u32 = 16;
const SCALAR_REGISTER_MASK: u32 = 31;
const SCALAR_WIDTH_SHIFT: u32 = 12;
const COUNTER_WIDTH_SHIFT: u32 = 13;
const PREDICATE_MASK: u32 = 15;
const COUNTER_DESTINATION_BASE: u8 = 8;
const COUNTER_DESTINATION_MASK: u32 = 7;
const PAIR_DESTINATION_MASK: u32 = 14;

use crate::aarch64::scalable::ElementSize;
use crate::aarch64::{Register, Width, register};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    SignedLt,
    SignedLe,
    SignedGe,
    SignedGt,
    UnsignedLt,
    UnsignedLe,
    UnsignedGe,
    UnsignedGt,
    ReadWriteDistance,
    WriteReadDistance,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    Predicate(u8),
    Pair(u8),
    Counter { register: u8, vectors: u8 },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WhileOperand {
    pub comparison: Comparison,
    pub element: ElementSize,
    pub width: Width,
    pub destination: Destination,
    pub first: Register,
    pub limit: Register,
}
#[derive(Debug, Clone, Copy)]
enum Representation {
    Predicate,
    Pair,
    Counter,
}
struct Form {
    mask: u32,
    class: u32,
    comparison: Comparison,
    representation: Representation,
}
const FORMS: [Form; 26] = [
    Form {
        mask: 0xff20ec10,
        class: 0x25200000,
        comparison: Comparison::SignedGe,
        representation: Representation::Predicate,
    },
    Form {
        mask: 0xff20dc18,
        class: 0x25204010,
        comparison: Comparison::SignedGe,
        representation: Representation::Counter,
    },
    Form {
        mask: 0xff20fc11,
        class: 0x25205010,
        comparison: Comparison::SignedGe,
        representation: Representation::Pair,
    },
    Form {
        mask: 0xff20ec10,
        class: 0x25200010,
        comparison: Comparison::SignedGt,
        representation: Representation::Predicate,
    },
    Form {
        mask: 0xff20dc18,
        class: 0x25204018,
        comparison: Comparison::SignedGt,
        representation: Representation::Counter,
    },
    Form {
        mask: 0xff20fc11,
        class: 0x25205011,
        comparison: Comparison::SignedGt,
        representation: Representation::Pair,
    },
    Form {
        mask: 0xff20ec10,
        class: 0x25200810,
        comparison: Comparison::UnsignedGt,
        representation: Representation::Predicate,
    },
    Form {
        mask: 0xff20dc18,
        class: 0x25204818,
        comparison: Comparison::UnsignedGt,
        representation: Representation::Counter,
    },
    Form {
        mask: 0xff20fc11,
        class: 0x25205811,
        comparison: Comparison::UnsignedGt,
        representation: Representation::Pair,
    },
    Form {
        mask: 0xff20ec10,
        class: 0x25200800,
        comparison: Comparison::UnsignedGe,
        representation: Representation::Predicate,
    },
    Form {
        mask: 0xff20dc18,
        class: 0x25204810,
        comparison: Comparison::UnsignedGe,
        representation: Representation::Counter,
    },
    Form {
        mask: 0xff20fc11,
        class: 0x25205810,
        comparison: Comparison::UnsignedGe,
        representation: Representation::Pair,
    },
    Form {
        mask: 0xff20ec10,
        class: 0x25200410,
        comparison: Comparison::SignedLe,
        representation: Representation::Predicate,
    },
    Form {
        mask: 0xff20dc18,
        class: 0x25204418,
        comparison: Comparison::SignedLe,
        representation: Representation::Counter,
    },
    Form {
        mask: 0xff20fc11,
        class: 0x25205411,
        comparison: Comparison::SignedLe,
        representation: Representation::Pair,
    },
    Form {
        mask: 0xff20ec10,
        class: 0x25200c00,
        comparison: Comparison::UnsignedLt,
        representation: Representation::Predicate,
    },
    Form {
        mask: 0xff20dc18,
        class: 0x25204c10,
        comparison: Comparison::UnsignedLt,
        representation: Representation::Counter,
    },
    Form {
        mask: 0xff20fc11,
        class: 0x25205c10,
        comparison: Comparison::UnsignedLt,
        representation: Representation::Pair,
    },
    Form {
        mask: 0xff20ec10,
        class: 0x25200c10,
        comparison: Comparison::UnsignedLe,
        representation: Representation::Predicate,
    },
    Form {
        mask: 0xff20dc18,
        class: 0x25204c18,
        comparison: Comparison::UnsignedLe,
        representation: Representation::Counter,
    },
    Form {
        mask: 0xff20fc11,
        class: 0x25205c11,
        comparison: Comparison::UnsignedLe,
        representation: Representation::Pair,
    },
    Form {
        mask: 0xff20ec10,
        class: 0x25200400,
        comparison: Comparison::SignedLt,
        representation: Representation::Predicate,
    },
    Form {
        mask: 0xff20dc18,
        class: 0x25204410,
        comparison: Comparison::SignedLt,
        representation: Representation::Counter,
    },
    Form {
        mask: 0xff20fc11,
        class: 0x25205410,
        comparison: Comparison::SignedLt,
        representation: Representation::Pair,
    },
    Form {
        mask: 0xff20fc10,
        class: 0x25203010,
        comparison: Comparison::ReadWriteDistance,
        representation: Representation::Predicate,
    },
    Form {
        mask: 0xff20fc10,
        class: 0x25203000,
        comparison: Comparison::WriteReadDistance,
        representation: Representation::Predicate,
    },
];
fn scalar_register(encoded: u32) -> Register {
    register(encoded, false)
}
/// All matching operand fields are allocated; mode/feature checks belong to the caller.
/// Scalar sources31 are ZR, never SP. Pair destinations are encoded even first registers.
pub fn decode(word: u32) -> Option<Result<WhileOperand, ()>> {
    let form = FORMS.iter().find(|form| word & form.mask == form.class)?;
    let element = ElementSize::from_bytes(1 << ((word >> ELEMENT_SIZE_SHIFT) & ELEMENT_SIZE_MASK))?;
    let (destination, width) = match form.representation {
        Representation::Predicate => {
            let address_distance = matches!(
                form.comparison,
                Comparison::ReadWriteDistance | Comparison::WriteReadDistance
            );
            let width = if address_distance || (word >> SCALAR_WIDTH_SHIFT) & 1 != 0 {
                Width::X64
            } else {
                Width::W32
            };
            (Destination::Predicate((word & PREDICATE_MASK) as u8), width)
        }
        Representation::Pair => (
            Destination::Pair((word & PAIR_DESTINATION_MASK) as u8),
            Width::X64,
        ),
        Representation::Counter => (
            Destination::Counter {
                register: COUNTER_DESTINATION_BASE + (word & COUNTER_DESTINATION_MASK) as u8,
                vectors: 2 << ((word >> COUNTER_WIDTH_SHIFT) & 1),
            },
            Width::X64,
        ),
    };
    Some(Ok(WhileOperand {
        comparison: form.comparison,
        element,
        width,
        destination,
        first: scalar_register((word >> SOURCE_N_SHIFT) & SCALAR_REGISTER_MASK),
        limit: scalar_register((word >> SOURCE_M_SHIFT) & SCALAR_REGISTER_MASK),
    }))
}

#[cfg(test)]
mod tests;
