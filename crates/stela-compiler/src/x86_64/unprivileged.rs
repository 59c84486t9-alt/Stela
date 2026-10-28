//! LDTR*/STTR* at EL0, where they behave as ordinary accesses. Checks the
//! incoming SP and keeps completed store prefixes on a fault.
use super::{AddressMode, memory};
use crate::aarch64::unprivileged::Operand;
use crate::x86_64::asm::Code;

pub(super) fn emit(code: &mut Code, operand: &Operand, checks: super::MemoryChecks) {
    memory(
        code,
        checks,
        operand.transfer,
        operand.bytes,
        operand.data,
        operand.base,
        operand.displacement,
        AddressMode::Offset,
    );
}
