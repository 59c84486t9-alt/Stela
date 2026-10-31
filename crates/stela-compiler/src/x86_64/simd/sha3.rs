//! EOR3, BCAX, RAX1 and XAR with SSE2, or AVX-512 ternary logic and rotates.
use super::{Host, commit, packed, packed_imm, read_vector, vector_memory};
use crate::x86_64::asm::{Code, vector_extensions};
use crate::{
    TargetCpu,
    aarch64::simd::sha3::{Kind, Operand},
    x86_64::isa::ShiftOpcode,
};

const RESULT: u8 = 0;
const SECOND: u8 = 1;
const TEMPORARY: u8 = 2;
const WORD_BITS: u8 = 16;
const DWORD_BITS: u8 = 32;
const QWORD_BITS: u8 = 64;
const NO_ROTATION: u8 = 0;
const ROTATE_RIGHT_THREE_WORDS: u8 = 3 * WORD_BITS;
const ROTATE_LEFT_ONE: u8 = 1;
const SWAP_DWORDS_IN_QWORDS: u8 = 0xb1;
const ROTATE_WORDS_RIGHT_ONE: u8 = 0x39;
const ROTATE_WORDS_RIGHT_THREE: u8 = 0x93;
/// VPTERNLOG tables over A:B:C = Vn:Vm:Va.
const EXCLUSIVE_OR_THREE: u8 = 0x96;
const EXCLUSIVE_OR_AND_NOT: u8 = 0xb4;

/// AVX-512 F with VL: one VPTERNLOGD reading Va from guest state for EOR3
/// and BCAX, PXOR and one rotate for RAX1 and XAR. XAR by 0 or 32 keeps its
/// single SSE2 shuffle.
fn emit_extended(code: &mut Code, operand: &Operand, target: TargetCpu) -> bool {
    if !vector_extensions::merge_supported(target)
        || matches!(
            operand.kind,
            Kind::Xar {
                rotation: NO_ROTATION | DWORD_BITS
            }
        )
    {
        return false;
    }
    read_vector(code, operand.left, RESULT);
    match operand.kind {
        Kind::Eor3 { third } | Kind::Bcax { third } => {
            read_vector(code, operand.right, SECOND);
            let table = if matches!(operand.kind, Kind::Eor3 { .. }) {
                EXCLUSIVE_OR_THREE
            } else {
                EXCLUSIVE_OR_AND_NOT
            };
            vector_extensions::ternary(code, RESULT, SECOND, vector_memory(third), table, target);
        }
        Kind::Rax1 => {
            read_vector(code, operand.right, SECOND);
            vector_extensions::rotate_qwords_right(
                code,
                SECOND,
                SECOND,
                QWORD_BITS - ROTATE_LEFT_ONE,
                target,
            );
            packed(code, Host::Xor, RESULT, SECOND);
        }
        Kind::Xar { rotation } => {
            read_vector(code, operand.right, SECOND);
            packed(code, Host::Xor, RESULT, SECOND);
            if rotation != NO_ROTATION {
                vector_extensions::rotate_qwords_right(code, RESULT, RESULT, rotation, target);
            }
        }
    }
    commit(code, operand.destination, RESULT);
    true
}

fn rotate_right(code: &mut Code, rotation: u8) {
    match rotation {
        NO_ROTATION => {}
        DWORD_BITS => {
            packed_imm(
                code,
                Host::ShuffleDword,
                RESULT,
                RESULT,
                SWAP_DWORDS_IN_QWORDS,
            );
        }
        WORD_BITS | ROTATE_RIGHT_THREE_WORDS => {
            let selector = if rotation == WORD_BITS {
                ROTATE_WORDS_RIGHT_ONE
            } else {
                ROTATE_WORDS_RIGHT_THREE
            };
            for opcode in [Host::ShuffleLowWord, Host::ShuffleHighWord] {
                packed_imm(code, opcode, RESULT, RESULT, selector);
            }
        }
        _ => {
            packed(code, Host::MoveAligned, TEMPORARY, RESULT);
            ShiftOpcode::RightQword.emit(code, RESULT, rotation);
            ShiftOpcode::LeftQword.emit(code, TEMPORARY, QWORD_BITS - rotation);
            packed(code, Host::Or, RESULT, TEMPORARY);
        }
    }
}

pub(super) fn emit(code: &mut Code, operand: &Operand, target: TargetCpu) {
    if emit_extended(code, operand, target) {
        return;
    }
    match operand.kind {
        Kind::Eor3 { third } => {
            read_vector(code, operand.left, RESULT);
            read_vector(code, operand.right, SECOND);
            read_vector(code, third, TEMPORARY);
            packed(code, Host::Xor, RESULT, SECOND);
            packed(code, Host::Xor, RESULT, TEMPORARY);
        }
        Kind::Bcax { third } => {
            // PANDN complements its destination: ~Va & Vm, then XOR Vn.
            read_vector(code, third, RESULT);
            read_vector(code, operand.right, SECOND);
            read_vector(code, operand.left, TEMPORARY);
            packed(code, Host::AndNot, RESULT, SECOND);
            packed(code, Host::Xor, RESULT, TEMPORARY);
        }
        Kind::Rax1 => {
            read_vector(code, operand.right, RESULT);
            read_vector(code, operand.left, SECOND);
            packed(code, Host::MoveAligned, TEMPORARY, RESULT);
            ShiftOpcode::RightQword.emit(code, TEMPORARY, QWORD_BITS - ROTATE_LEFT_ONE);
            // m+m is m<<1 modulo each64; the separately shifted top bit wraps.
            packed(code, Host::AddQword, RESULT, RESULT);
            packed(code, Host::Or, RESULT, TEMPORARY);
            packed(code, Host::Xor, RESULT, SECOND);
        }
        Kind::Xar { rotation } => {
            read_vector(code, operand.left, RESULT);
            read_vector(code, operand.right, SECOND);
            packed(code, Host::Xor, RESULT, SECOND);
            rotate_right(code, rotation);
        }
    }
    commit(code, operand.destination, RESULT);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn staging_cost_accounts_for_complete_state_access_and_immediate_specializations() {
        for (kind, expected_bytes) in [
            (Kind::Eor3 { third: 31 }, 40),
            (Kind::Bcax { third: 31 }, 40),
            (Kind::Rax1, 45),
            (Kind::Xar { rotation: 0 }, 28),
            (Kind::Xar { rotation: 16 }, 38),
            (Kind::Xar { rotation: 32 }, 33),
            (Kind::Xar { rotation: 48 }, 38),
            (Kind::Xar { rotation: 63 }, 46),
        ] {
            let mut code = Code::new();
            emit(
                &mut code,
                &Operand {
                    kind,
                    destination: 31,
                    left: 31,
                    right: 31,
                },
                TargetCpu::X86_64_V3,
            );
            assert_eq!(code.len(), expected_bytes, "{kind:?}");
            // MOVDQU is the only write and covers all of V31.
            let mut expected_store = vec![0xf3, 0x0f, 0x7f, 0x87];
            expected_store.extend(super::super::vector_offset(31).to_le_bytes());
            assert!(code.ends_with(&expected_store), "{kind:?}");
        }
    }

    #[test]
    fn ternary_logic_and_rotates_match_the_sse2_recipes() {
        use crate::x86_64::asm::vector_extensions::execution::Native;
        use crate::{GuestAddress, GuestState, context::ExecutionContext};
        use alloc::vec::Vec;
        let candidate = TargetCpu::X86_64_V4;
        if !TargetCpu::detect().supports(candidate) {
            return;
        }
        let mut words = Vec::new();
        for (destination, left, right, third) in
            [(3u32, 1u32, 2u32, 4u32), (5, 5, 5, 5), (1, 2, 1, 2)]
        {
            let registers = right << 16 | left << 5 | destination;
            words.push((0xce00_0000 | registers | third << 10, true));
            words.push((0xce20_0000 | registers | third << 10, true));
            words.push((0xce60_8c00 | registers, true));
            for rotation in [0u32, 1, 16, 32, 48, 63] {
                let shortened = rotation % 32 != 0;
                words.push((0xce80_0000 | registers | rotation << 10, shortened));
            }
        }
        let mut random = 0x6a09_e667_f3bc_c908_u64;
        for (word, shortened) in words {
            let source: Vec<u8> = [word, 0xd65f03c0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            let compile = |target| {
                crate::testing::leaf_for(&source, GuestAddress(0x1000), target)
                    .unwrap()
                    .x86_64_code
            };
            let baseline = compile(TargetCpu::X86_64_V3);
            let extended = compile(candidate);
            if shortened {
                assert!(extended.len() < baseline.len(), "{word:#010x}");
            } else {
                assert_eq!(extended, baseline, "{word:#010x}");
            }
            let [baseline, extended] = [&baseline, &extended].map(|code| Native::new(code));
            for _ in 0..16 {
                let mut state = GuestState::default();
                for vector in &mut state.v {
                    for limb in vector {
                        random ^= random << 13;
                        random ^= random >> 7;
                        random ^= random << 17;
                        *limb = random;
                    }
                }
                let mut expected = state.clone();
                baseline.run(&mut expected, &mut ExecutionContext::default());
                extended.run(&mut state, &mut ExecutionContext::default());
                assert_eq!(state, expected, "{word:#010x}");
            }
        }
    }
}
