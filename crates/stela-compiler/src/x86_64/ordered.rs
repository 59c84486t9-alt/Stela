//! Ordered Normal-WB scalar accesses and data-memory barriers.
//!
//! Release stores use XCHG so a later acquire load cannot bypass them. Checked
//! loads crossing eight bytes take one read-only aligned 16-byte snapshot; the profile guarantees
//! uniform page permissions and excludes device memory, tags and debug watches.
use super::atomic::{address_offset, commit_rax, input_rcx, read_rax};
use crate::{
    TargetCpu,
    aarch64::{
        Register, Width,
        ordered::{Barrier, Kind, LoadExtension, Operand},
    },
};
use alloc::vec::Vec;

const BYTE_BYTES: u8 = 1;
const HALFWORD_BYTES: u8 = 2;
const DWORD_BYTES: u8 = 4;
const QWORD_BYTES: u8 = 8;
const ATOMIC_QUANTITY_BYTES: u8 = 16;
const BASELINE_ATOMIC_BYTES: u8 = 8;
const BASELINE_ATOMIC_MASK: u8 = BASELINE_ATOMIC_BYTES - 1;
const BITS_PER_BYTE_SHIFT: u8 = 3;
const OPERAND_SIZE_PREFIX: u8 = 0x66;
const REX_W_PREFIX: u8 = 0x48;
const TWO_BYTE_OPCODE: u8 = 0x0f;
const MOVSX_BYTE: u8 = 0xbe;
const MOVSX_HALFWORD: u8 = 0xbf;
const MOVSXD: u8 = 0x63;
const RDX_ADDRESS: u8 = 2;
const RAX_REGISTER: u8 = 0xc0;
const XCHG_BYTE: u8 = 0x86;
const XCHG_WIDER: u8 = 0x87;
const RCX_RDX_MEMORY: u8 = 0x0a;
const MFENCE: &[u8] = &[0x0f, 0xae, 0xf0];
const NOP: u8 = 0x90;
const MOV_ECX_EDX: &[u8] = &[0x89, 0xd1];
const AND_ECX_IMM8: &[u8] = &[0x83, 0xe1];
const CMP_CL_IMM8: &[u8] = &[0x80, 0xf9];
const JA_REL8: u8 = 0x77;
const JMP_REL8: u8 = 0xeb;
const SHL_ECX_IMM8: &[u8] = &[0xc1, 0xe1];
const AND_RDX_IMM8: &[u8] = &[0x48, 0x83, 0xe2];
const MOVDQA_XMM0_RDX: &[u8] = &[0x66, 0x0f, 0x6f, 0x02];
const MOVQ_RAX_XMM0: &[u8] = &[0x66, 0x48, 0x0f, 0x7e, 0xc0];
const MOVHLPS_XMM0_XMM0: &[u8] = &[0x0f, 0x12, 0xc0];
const MOVQ_R8_XMM0: &[u8] = &[0x66, 0x49, 0x0f, 0x7e, 0xc0];
const SHRD_RAX_R8_CL: &[u8] = &[0x4c, 0x0f, 0xad, 0xc0];
const SHRD_RAX_R8_IMM8: &[u8] = &[0x4c, 0x0f, 0xac, 0xc0];
const MOVZX_EAX_AX: &[u8] = &[0x0f, 0xb7, 0xc0];
const MOV_EAX_EAX: &[u8] = &[0x89, 0xc0];

/// Generic wider loads can cross eight bytes. Aligned SP makes the effective
/// residue known; a statically faulting access never needs a snapshot capability.
pub(super) fn requires_atomic_load16(operand: &Operand) -> bool {
    let Operand::Transfer {
        kind: Kind::Acquire | Kind::AcquirePc,
        bytes: bytes @ (HALFWORD_BYTES | DWORD_BYTES | QWORD_BYTES),
        base,
        displacement,
        ..
    } = *operand
    else {
        return false;
    };
    base != Register::Sp
        || (displacement.rem_euclid(i32::from(ATOMIC_QUANTITY_BYTES))
            <= i32::from(ATOMIC_QUANTITY_BYTES - bytes)
            && displacement.rem_euclid(i32::from(BASELINE_ATOMIC_BYTES))
                > i32::from(BASELINE_ATOMIC_BYTES - bytes))
}

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    match *operand {
        Operand::Barrier { requirement, .. } => {
            // Cached ordinary WB accesses already preserve reads→reads/writes
            // and writes→writes. Full barriers additionally close store→load.
            match requirement {
                Barrier::All => code.extend(MFENCE),
                Barrier::Reads | Barrier::Writes => code.push(NOP),
            }
        }
        Operand::Transfer {
            kind,
            bytes,
            data,
            base,
            displacement,
            extension,
        } => {
            address_offset(code, base, bytes, displacement);
            if kind == Kind::Release {
                input_rcx(code, bytes, data);
                release(code, bytes);
            } else {
                if requires_atomic_load16(operand) {
                    // The compiler validates this requirement before emission.
                    debug_assert!(target.supports(TargetCpu::AtomicLoad16));
                    if base == Register::Sp {
                        let offset =
                            displacement.rem_euclid(i32::from(BASELINE_ATOMIC_BYTES)) as u8;
                        snapshot_value(code, bytes, extension, Some(offset << BITS_PER_BYTE_SHIFT));
                    } else {
                        acquire_snapshot(code, bytes, extension);
                    }
                } else {
                    read_extended(code, bytes, extension);
                }
                // ZR still performs the access, including its acquire order.
                commit_rax(code, bytes, data);
            }
        }
    }
}

fn release(code: &mut Vec<u8>, bytes: u8) {
    if bytes == HALFWORD_BYTES {
        code.push(OPERAND_SIZE_PREFIX);
    } else if bytes == QWORD_BYTES {
        code.push(REX_W_PREFIX);
    }
    code.extend([
        if bytes == BYTE_BYTES {
            XCHG_BYTE
        } else {
            XCHG_WIDER
        },
        RCX_RDX_MEMORY,
    ]);
}

fn read_extended(code: &mut Vec<u8>, bytes: u8, extension: LoadExtension) {
    match extension {
        LoadExtension::Zero => read_rax(code, bytes),
        LoadExtension::Sign(width) => sign_extend(code, bytes, width, RDX_ADDRESS),
    }
}

/// The memory and register forms share the same extension semantics. A W result
/// clears upper X bits through its 32-bit destination; an X result sign-fills them.
fn sign_extend(code: &mut Vec<u8>, bytes: u8, width: Width, operand: u8) {
    if width == Width::X64 {
        code.push(REX_W_PREFIX);
    }
    match bytes {
        BYTE_BYTES => code.extend([TWO_BYTE_OPCODE, MOVSX_BYTE, operand]),
        HALFWORD_BYTES => code.extend([TWO_BYTE_OPCODE, MOVSX_HALFWORD, operand]),
        DWORD_BYTES if width == Width::X64 => code.extend([MOVSXD, operand]),
        _ => unreachable!("decoder validates ordered signed widths"),
    }
}

/// A legal ordered access is contained inside 16 bytes. Exact reads contained inside eight bytes
/// use the baseline guarantee; only the crossing path reads the containing 16 bytes.
fn acquire_snapshot(code: &mut Vec<u8>, bytes: u8, extension: LoadExtension) {
    code.extend(MOV_ECX_EDX);
    code.extend(AND_ECX_IMM8);
    code.push(BASELINE_ATOMIC_MASK);
    code.extend(CMP_CL_IMM8);
    code.push(BASELINE_ATOMIC_BYTES - bytes);
    code.push(JA_REL8);
    let snapshot_branch = code.len();
    code.push(0);
    read_extended(code, bytes, extension);
    code.push(JMP_REL8);
    let done_branch = code.len();
    code.push(0);
    code[snapshot_branch] = i8::try_from(code.len() - snapshot_branch - 1)
        .expect("exact load branch fits rel8")
        .to_le_bytes()[0];

    snapshot_value(code, bytes, extension, None);
    code[done_branch] = i8::try_from(code.len() - done_branch - 1)
        .expect("snapshot branch fits rel8")
        .to_le_bytes()[0];
}

/// A known SP residue avoids a runtime boundary branch and variable shift setup.
/// Generic crossings retain their established CL recipe and output bytes.
fn snapshot_value(code: &mut Vec<u8>, bytes: u8, extension: LoadExtension, shift: Option<u8>) {
    if shift.is_none() {
        code.extend(SHL_ECX_IMM8);
        code.push(BITS_PER_BYTE_SHIFT);
    }
    code.extend(AND_RDX_IMM8);
    code.push(0u8.wrapping_sub(ATOMIC_QUANTITY_BYTES));
    code.extend(MOVDQA_XMM0_RDX);
    code.extend(MOVQ_RAX_XMM0);
    code.extend(MOVHLPS_XMM0_XMM0);
    code.extend(MOVQ_R8_XMM0);
    if let Some(shift) = shift {
        code.extend(SHRD_RAX_R8_IMM8);
        code.push(shift);
    } else {
        code.extend(SHRD_RAX_R8_CL);
    }
    match extension {
        LoadExtension::Sign(width) => sign_extend(code, bytes, width, RAX_REGISTER),
        LoadExtension::Zero => match bytes {
            HALFWORD_BYTES => code.extend(MOVZX_EAX_AX),
            DWORD_BYTES => code.extend(MOV_EAX_EAX),
            QWORD_BYTES => {}
            _ => unreachable!("only wider ordered loads can cross eight bytes"),
        },
    }
}

#[cfg(test)]
mod tests;
