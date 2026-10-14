//! EL0 direct private Normal-RAM unprivileged scalar transfers.
//!
//! At EL0 their access descriptor has the same privilege as ordinary accesses.
//! The shared path checks incoming SP, retains exact widths and load faults,
//! and preserves completed store prefixes without writeback. This mapping
//! assumes disabled tag/PAC/CPA checks; it does not emulate privileged execution
//! or guest MMU/user-permission checks.
use super::{AddressMode, memory};
use crate::aarch64::unprivileged::Operand;

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
    memory(
        code,
        operand.transfer,
        operand.bytes,
        operand.data,
        operand.base,
        operand.displacement,
        AddressMode::Offset,
    );
}
