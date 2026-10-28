//! SIMD loads and stores to private RAM, immediate and register offsets.
use super::Host;
use super::{commit, read_vector, vector_offset};
use crate::TargetCpu;
use crate::aarch64::simd::memory::Operand;
use crate::x86_64::asm::{Code, Gpr, Mem, Size};
use crate::x86_64::simd::encode::guest;

const BYTE_BYTES: u8 = 1;
const HALFWORD_BYTES: u8 = 2;
const DWORD_BYTES: u8 = 4;
const QWORD_BYTES: u8 = 8;
const VECTOR_BYTES: u8 = 16;

/// With `held`, XMM0 holds the vector whole ([`transfer`]).
pub(super) fn emit_register_offset(
    code: &mut Code,
    operand: &Operand,
    checks: super::super::MemoryChecks,
    held: bool,
) {
    super::super::register_offset::address(
        code,
        checks,
        operand.base,
        operand.index,
        operand.extend,
        operand.shift,
        operand.bytes,
        !operand.load,
    );
    let aligned = checks.stack_alignment
        && super::super::memory_store::aligned_register_offset(
            operand.base,
            operand.index,
            operand.shift,
            operand.bytes,
        );
    transfer(
        code,
        operand.load,
        operand.bytes,
        operand.vector,
        aligned,
        held,
    );
}

/// S/D/Q at [RAX+displacement], using XMM0/XMM1. Loads zero higher bits.
/// Pair transfers use only positive second-element displacements 4/8/16.
pub(super) fn wide_transfer(
    code: &mut Code,
    load: bool,
    bytes: u8,
    xmm: u8,
    displacement: u8,
    aligned: bool,
) {
    if !load {
        super::super::memory_store::emit(
            code,
            bytes,
            displacement,
            super::super::memory_store::Source::Xmm(xmm),
            aligned,
        );
        return;
    }
    let address = Mem::base(Gpr::Rax, displacement.into());
    match bytes {
        DWORD_BYTES => code.asm().movd_to_xmm(xmm, address),
        QWORD_BYTES => Host::MoveQword.emit(code, xmm, address, TargetCpu::Baseline),
        VECTOR_BYTES => Host::LoadUnaligned.emit(code, xmm, address, TargetCpu::Baseline),
        _ => unreachable!("decoder validates wide vector memory width"),
    }
}

/// Whether [`transfer`] passes the vector through XMM0, which then holds
/// it whole: every load, which commits from there, and the stores of
/// more than a halfword.
pub(super) fn transfers_xmm0(load: bool, bytes: u8) -> bool {
    load || bytes > HALFWORD_BYTES
}

/// Transfer one vector through RAX, without base writeback. A failed load
/// commits nothing. With `held`, XMM0 holds the vector whole, and a store
/// through XMM0 ([`transfers_xmm0`]) takes it from there.
pub(in crate::x86_64) fn transfer(
    code: &mut Code,
    load: bool,
    bytes: u8,
    vector: u8,
    aligned: bool,
    held: bool,
) {
    if load {
        match bytes {
            BYTE_BYTES | HALFWORD_BYTES => {
                // Never widen a guest access. MOVD clears every upper vector bit.
                let from = if bytes == BYTE_BYTES {
                    Size::Byte
                } else {
                    Size::Word
                };
                let mut asm = code.asm();
                asm.movzx(Size::Dword, Gpr::Rcx, from, Mem::base(Gpr::Rax, 0));
                asm.movd_to_xmm(0, Gpr::Rcx);
            }
            DWORD_BYTES | QWORD_BYTES | VECTOR_BYTES => {
                wide_transfer(code, true, bytes, 0, 0, aligned)
            }
            _ => unreachable!("decoder validates vector memory width"),
        }
        commit(code, vector, 0);
    } else if bytes <= HALFWORD_BYTES {
        code.asm()
            .mov_load(Size::Qword, Gpr::Rcx, guest(vector_offset(vector)));
        super::super::memory_store::emit(
            code,
            bytes,
            0,
            super::super::memory_store::Source::Rcx,
            aligned,
        );
    } else {
        if !held {
            read_vector(code, vector, 0);
        }
        wide_transfer(code, false, bytes, 0, 0, aligned);
    }
}
