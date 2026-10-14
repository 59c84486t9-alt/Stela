//! SSE2 lowering for classic SHA3 logical forms. Source state is read completely
//! before the single destination commit, including every legal operand alias.
use super::{Host, commit, packed, read_vector};
use crate::{
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

fn rotate_right(code: &mut Vec<u8>, rotation: u8) {
    match rotation {
        NO_ROTATION => {}
        DWORD_BITS => {
            packed(code, Host::ShuffleDword, RESULT, RESULT);
            code.push(SWAP_DWORDS_IN_QWORDS);
        }
        WORD_BITS | ROTATE_RIGHT_THREE_WORDS => {
            let selector = if rotation == WORD_BITS {
                ROTATE_WORDS_RIGHT_ONE
            } else {
                ROTATE_WORDS_RIGHT_THREE
            };
            for opcode in [Host::ShuffleLowWord, Host::ShuffleHighWord] {
                packed(code, opcode, RESULT, RESULT);
                code.push(selector);
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

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
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
            let mut code = Vec::new();
            emit(
                &mut code,
                &Operand {
                    kind,
                    destination: 31,
                    left: 31,
                    right: 31,
                },
            );
            assert_eq!(code.len(), expected_bytes, "{kind:?}");
            // MOVDQU is the sole architectural commit and writes all V31 bits.
            let mut expected_store = vec![0xf3, 0x0f, 0x7f, 0x87];
            expected_store.extend(super::super::vector_offset(31).to_le_bytes());
            assert!(code.ends_with(&expected_store), "{kind:?}");
        }
    }
}
