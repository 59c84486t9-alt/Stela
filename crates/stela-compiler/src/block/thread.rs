//! Explicit guest thread-register reads through the runtime-owned TSD domain.
use crate::{CompileError, GuestAddress};
use serde::Serialize;

const INSTRUCTION_BYTES: u64 = 4;
const DESTINATION_MASK: u32 = 0x1f;
const MRS_TPIDRRO_EL0: u32 = 0xd53bd060;

/// Only MRS TPIDRRO_EL0 is admitted. X31 discards the value, never writes SP.
/// Native code requests a helper without reading host TLS or changing guest state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ThreadRegisterInstruction {
    pub destination: u8,
    pub instruction_pc: GuestAddress,
    pub next_pc: GuestAddress,
}

pub fn decode_thread_register_instruction(
    pc: GuestAddress,
    word: u32,
) -> Result<Option<ThreadRegisterInstruction>, CompileError> {
    if !pc.0.is_multiple_of(INSTRUCTION_BYTES) {
        return Err(CompileError(
            "thread-register instruction PC must be aligned to 4 bytes".into(),
        ));
    }
    if word & !DESTINATION_MASK != MRS_TPIDRRO_EL0 {
        return Ok(None);
    }
    Ok(Some(ThreadRegisterInstruction {
        destination: (word & DESTINATION_MASK) as u8,
        instruction_pc: pc,
        next_pc: GuestAddress(pc.0.checked_add(INSTRUCTION_BYTES).ok_or_else(|| {
            CompileError("thread-register continuation PC overflows guest address range".into())
        })?),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_only_readonly_thread_pointer_and_all_destinations() {
        let pc = GuestAddress(0x1000);
        for destination in 0..=DESTINATION_MASK {
            let decoded = decode_thread_register_instruction(pc, MRS_TPIDRRO_EL0 | destination)
                .unwrap()
                .unwrap();
            assert_eq!(decoded.destination, destination as u8);
            assert_eq!(decoded.instruction_pc, pc);
            assert_eq!(decoded.next_pc.0, pc.0 + INSTRUCTION_BYTES);
        }
        // TPIDR_EL0, TPIDR_EL1, and MSR TPIDRRO_EL0 are separate boundaries.
        for word in [0xd53bd040, 0xd538d080, 0xd51bd060] {
            assert_eq!(decode_thread_register_instruction(pc, word).unwrap(), None);
        }
        assert!(decode_thread_register_instruction(GuestAddress(1), MRS_TPIDRRO_EL0).is_err());
        assert!(
            decode_thread_register_instruction(GuestAddress(u64::MAX - 3), MRS_TPIDRRO_EL0)
                .is_err()
        );
    }
    #[test]
    fn shared_parser_requires_thread_profile_and_stops_before_unknown_successor() {
        use crate::{
            Lifter,
            block::{self, BlockProfile, SuccessorKind},
        };
        use std::collections::BTreeSet;
        let base = GuestAddress(0x1000);
        const ADD_X0_X0_ONE: u32 = 0x91000400;
        const UNSUPPORTED_SUCCESSOR: u32 = 0;
        let source: Vec<_> = [ADD_X0_X0_ONE, MRS_TPIDRRO_EL0 | 8, UNSUPPORTED_SUCCESSOR]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let profiles = [
            BlockProfile::Ordinary,
            BlockProfile::AppleArm64eSoftwarePauthV1,
            BlockProfile::AppleArm64eSoftwarePauthClockV1,
            BlockProfile::DarwinArm64ThreadV1,
            BlockProfile::AppleArm64eSoftwarePauthThreadV1,
            BlockProfile::AppleArm64eSoftwarePauthClockThreadV1,
        ];
        let mut abis = BTreeSet::new();
        for profile in profiles {
            assert!(
                abis.insert(profile.abi()),
                "cache ABI identities must be distinct"
            );
            let analyzed = block::analyze_with_profile(&source, base, profile);
            let compiled = block::compile_with_profile(&source, base, profile);
            if !profile.supports_thread_registers() {
                assert_eq!(analyzed.unwrap_err().pc.0, base.0 + INSTRUCTION_BYTES);
                assert!(compiled.is_err());
                continue;
            }
            let analyzed = analyzed.unwrap();
            let compiled = compiled.unwrap();
            assert_eq!(analyzed.source_bytes, 2 * INSTRUCTION_BYTES as usize);
            assert_eq!(compiled.source_bytes, analyzed.source_bytes);
            let instruction = analyzed.thread_register_instruction.unwrap();
            assert_eq!(instruction.destination, 8);
            assert_eq!(analyzed.terminator_pc, Some(instruction.instruction_pc));
            assert_eq!(analyzed.static_successors.len(), 1);
            assert_eq!(
                analyzed.static_successors[0].kind,
                SuccessorKind::Fallthrough
            );
            assert_eq!(analyzed.static_successors[0].target, instruction.next_pc);
            assert_eq!(compiled.native.source_map.len(), 2);
            assert_eq!(compiled.native.source_map[1].0, instruction.instruction_pc);
        }
        assert!(crate::aarch64::Decoder.lift(base, MRS_TPIDRRO_EL0).is_err());
    }
}
