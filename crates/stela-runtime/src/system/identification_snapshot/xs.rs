//! The XS field of ID_AA64ISAR1_EL1 (nXS barrier and TLBI support).
use super::{Register, Snapshot, Unsupported};
use crate::system::barriers::Xs;

const ID_FIELD_MASK: u64 = 0xf;
const XS_SHIFT: u32 = 56;
const XS_ABSENT: u8 = 0;
const XS_IMPLEMENTED: u8 = 1;

impl Snapshot {
    pub(crate) fn xs(&self) -> Result<Xs, Unsupported> {
        let value = ((self.read(Register::IdAa64Isar1El1)? >> XS_SHIFT) & ID_FIELD_MASK) as u8;
        match value {
            XS_ABSENT => Ok(Xs::Absent),
            XS_IMPLEMENTED => Ok(Xs::Present),
            _ => Err(Unsupported::Field {
                register: Register::IdAa64Isar1El1,
                field: "XS",
                value,
            }),
        }
    }
}

#[cfg(test)]
mod tests;
