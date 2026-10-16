//! AESE, AESD, AESMC and AESIMC.

const FORM_MASK: u32 = 0xffff_fc00;
const AESE: u32 = 0x4e28_4800;
const AESD: u32 = 0x4e28_5800;
const AESMC: u32 = 0x4e28_6800;
const AESIMC: u32 = 0x4e28_7800;
const REGISTER_MASK: u32 = 31;
const SOURCE_SHIFT: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Encrypt,
    Decrypt,
    MixColumns,
    InverseMixColumns,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: u8,
    pub source: u8,
}

/// Only the exact .16B encodings are accepted. Other classes and reserved size
/// encodings decline and retain the shared decoder's unsupported failure.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let kind = match word & FORM_MASK {
        AESE => Kind::Encrypt,
        AESD => Kind::Decrypt,
        AESMC => Kind::MixColumns,
        AESIMC => Kind::InverseMixColumns,
        _ => return None,
    };
    Some(Ok(Operand {
        kind,
        destination: (word & REGISTER_MASK) as u8,
        source: ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8,
    }))
}

#[cfg(test)]
mod tests;
