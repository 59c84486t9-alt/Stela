//! AES: constant-time SSE2 circuits, or AES-NI when available. All sources are
//! read before the destination is written.
use alloc::vec::Vec;
mod sbox;

use super::{Host, commit, packed, read_vector, rearrange::constant, shuffle};
use crate::{
    TargetCpu,
    aarch64::simd::aes::{Kind, Operand},
    x86_64::isa::ShiftOpcode as Shift,
};

const RCX: u8 = 1;
const RESULT: u8 = 0;
const OLD_DESTINATION: u8 = 1;
const MASK: u8 = 3;
const LEFT: u8 = 4;
const RIGHT: u8 = 5;
const TERM: u8 = 6;
const HIGH: u8 = 7;
const BYTE_BITS: u8 = 8;
const COLUMN_BITS: u8 = 32;
const COLUMN_REPLICATION: u64 = 0x0000_0001_0000_0001;
const FORWARD_COLUMN_ORDER: [u8; 4] = [0xe4, 0x39, 0x4e, 0x93];
const INVERSE_COLUMN_ORDER: [u8; 4] = [0xe4, 0x93, 0x4e, 0x39];
const BYTE_REPLICATION: u64 = 0x0101_0101_0101_0101;
const FIELD_REDUCTION: u8 = 0x1b;
const MOVABS_RCX: [u8; 2] = [0x48, 0xb9];
const SHIFT_ROWS: [u8; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];
const INVERSE_SHIFT_ROWS: [u8; 16] = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3];
/// Broadcast a byte without a memory pool or an additional SIMD clobber.
fn byte_constant(code: &mut Vec<u8>, destination: u8, value: u8) {
    code.extend(MOVABS_RCX);
    code.extend((u64::from(value) * BYTE_REPLICATION).to_le_bytes());
    packed(code, Host::MoveGprQword, destination, RCX); // RCX -> XMM.
    packed(code, Host::UnpackLowQword, destination, destination);
}

/// Per-byte multiplication by x modulo x^8+x^4+x^3+x+1. MASK holds 1b;
/// HIGH is scratch. PADDB avoids carries between adjacent byte lanes.
fn xtime(code: &mut Vec<u8>, value: u8) {
    packed(code, Host::Xor, HIGH, HIGH);
    packed(code, Host::GreaterByte, HIGH, value);
    packed(code, Host::AddByte, value, value);
    packed(code, Host::And, HIGH, MASK);
    packed(code, Host::Xor, value, HIGH);
}

fn shift_rows(code: &mut Vec<u8>, inverse: bool, target: TargetCpu) {
    let selection = if inverse {
        INVERSE_SHIFT_ROWS
    } else {
        SHIFT_ROWS
    };
    if target.supports(TargetCpu::Ssse3) {
        constant(code, MASK, selection);
        Host::ByteShuffle.register(code, RESULT, MASK, target);
        return;
    }
    // Each row rotates whole four-byte columns, then a fixed mask selects
    // that row from every column. PSHUFD is baseline SSE2, not SSSE3.
    let order = if inverse {
        INVERSE_COLUMN_ORDER
    } else {
        FORWARD_COLUMN_ORDER
    };
    for (row, control) in order.into_iter().enumerate() {
        let mask = u64::from(u8::MAX) << (row * usize::from(BYTE_BITS));
        code.extend(MOVABS_RCX);
        code.extend((mask * COLUMN_REPLICATION).to_le_bytes());
        packed(code, Host::MoveGprQword, MASK, RCX);
        packed(code, Host::UnpackLowQword, MASK, MASK);
        if row == 0 {
            packed(code, Host::MoveAligned, RIGHT, RESULT);
            packed(code, Host::And, RIGHT, MASK);
        } else {
            shuffle(code, LEFT, RESULT, control);
            packed(code, Host::And, LEFT, MASK);
            packed(code, Host::Or, RIGHT, LEFT);
        }
    }
    packed(code, Host::MoveAligned, RESULT, RIGHT);
}

/// Rotate every four-byte AES column right, preserving the original input.
/// MASK/HIGH remain available for xtime; RESULT may also be the destination.
fn rotate_column(code: &mut Vec<u8>, destination: u8, source: u8, bits: u8) {
    packed(code, Host::MoveAligned, TERM, source);
    packed(code, Host::MoveAligned, destination, source);
    Shift::LeftDword.emit(code, TERM, COLUMN_BITS - bits);
    Shift::RightDword.emit(code, destination, bits);
    packed(code, Host::Or, destination, TERM);
}

fn mix_columns(code: &mut Vec<u8>, inverse: bool) {
    byte_constant(code, MASK, FIELD_REDUCTION);
    if inverse {
        rotate_column(code, RIGHT, RESULT, BYTE_BITS * 2);
        packed(code, Host::Xor, RIGHT, RESULT);
        xtime(code, RIGHT);
        xtime(code, RIGHT);
        packed(code, Host::Xor, RESULT, RIGHT);
    }
    packed(code, Host::MoveAligned, LEFT, RESULT);
    rotate_column(code, RIGHT, LEFT, BYTE_BITS);
    packed(code, Host::Xor, RESULT, RIGHT);
    // RESULT = a XOR rot8(a), LEFT retains a.
    xtime(code, RESULT);
    packed(code, Host::Xor, RESULT, RIGHT);
    rotate_column(code, RIGHT, LEFT, BYTE_BITS * 2);
    packed(code, Host::Xor, RESULT, RIGHT);
    rotate_column(code, RIGHT, LEFT, BYTE_BITS * 3);
    packed(code, Host::Xor, RESULT, RIGHT);
    // Above equals xtime(a XOR rot8(a)) XOR rot8(a) XOR rot16(a) XOR
    // rot24(a): a XOR columnXor simplifies away the duplicate a.
}

fn aes(code: &mut Vec<u8>, kind: Kind, target: TargetCpu) {
    if kind == Kind::InverseMixColumns {
        Host::AesInverseMixColumns.register(code, RESULT, RESULT, target);
        return;
    }
    packed(code, Host::Xor, MASK, MASK);
    match kind {
        Kind::Encrypt => Host::AesEncryptLast.register(code, RESULT, MASK, target),
        Kind::Decrypt => Host::AesDecryptLast.register(code, RESULT, MASK, target),
        Kind::MixColumns => {
            Host::AesDecryptLast.register(code, RESULT, MASK, target);
            Host::AesEncryptRound.register(code, RESULT, MASK, target);
        }
        Kind::InverseMixColumns => unreachable!("handled before zero preparation"),
    }
}

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    read_vector(code, operand.source, RESULT);
    if matches!(operand.kind, Kind::Encrypt | Kind::Decrypt) {
        read_vector(code, operand.destination, OLD_DESTINATION);
        packed(code, Host::Xor, RESULT, OLD_DESTINATION);
    }
    if target.supports(TargetCpu::Aes) {
        aes(code, operand.kind, target);
    } else {
        match operand.kind {
            Kind::Encrypt => {
                shift_rows(code, false, target);
                sbox::emit(code, false);
            }
            Kind::Decrypt => {
                shift_rows(code, true, target);
                sbox::emit(code, true);
            }
            Kind::MixColumns => mix_columns(code, false),
            Kind::InverseMixColumns => mix_columns(code, true),
        }
    }
    commit(code, operand.destination, RESULT);
}

#[cfg(test)]
mod tests;
