//! Address descriptors shared by streaming SVE memory instructions.

use crate::aarch64::Register;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scale {
    Bytes,
    VectorBytes { multiply: u8, divide: u8 },
    PredicateBytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offset {
    Immediate { value: i16, scale: Scale },
    Register { index: Register, shift: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Address {
    pub base: Register,
    pub offset: Offset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Extension {
    Zero,
    Sign,
}
