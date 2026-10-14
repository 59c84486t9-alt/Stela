//! Ordered Normal-WB scalar accesses and data-memory barriers.
//!
//! Release stores use XCHG so a later acquire load cannot bypass them. Checked
//! loads crossing eight bytes take one read-only aligned 16-byte snapshot; the profile guarantees
//! uniform page permissions and excludes device memory, tags and debug watches.
use super::atomic::{address, commit_rax, input_rcx, read_rax};
use crate::{
    TargetCpu,
    aarch64::{
        Register,
        ordered::{Barrier, Kind, Operand},
    },
};

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
const MOVZX_EAX_AX: &[u8] = &[0x0f, 0xb7, 0xc0];
const MOV_EAX_EAX: &[u8] = &[0x89, 0xc0];

/// A non-SP address can require an atomic snapshot across an eight-byte boundary.
/// SP is checked for 16-byte alignment before access; byte loads cannot cross it.
pub(super) fn requires_atomic_load16(operand: &Operand) -> bool {
    matches!(
        operand,
        Operand::Transfer {
            kind: Kind::Acquire | Kind::AcquirePc,
            bytes: HALFWORD_BYTES | DWORD_BYTES | QWORD_BYTES,
            base,
            ..
        } if *base != Register::Sp
    )
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
        } => {
            address(code, base, bytes);
            if kind == Kind::Release {
                input_rcx(code, bytes, data);
                release(code, bytes);
            } else {
                if bytes != BYTE_BYTES && base != Register::Sp {
                    // The compiler validates this requirement before emission.
                    debug_assert!(target.supports(TargetCpu::AtomicLoad16));
                    acquire_snapshot(code, bytes);
                } else {
                    read_rax(code, bytes);
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

/// A legal ordered access is contained inside 16 bytes. Exact reads contained inside eight bytes
/// use the baseline guarantee; only the crossing path reads the containing 16 bytes.
fn acquire_snapshot(code: &mut Vec<u8>, bytes: u8) {
    code.extend(MOV_ECX_EDX);
    code.extend(AND_ECX_IMM8);
    code.push(BASELINE_ATOMIC_MASK);
    code.extend(CMP_CL_IMM8);
    code.push(BASELINE_ATOMIC_BYTES - bytes);
    code.push(JA_REL8);
    let snapshot_branch = code.len();
    code.push(0);
    read_rax(code, bytes);
    code.push(JMP_REL8);
    let done_branch = code.len();
    code.push(0);
    code[snapshot_branch] = i8::try_from(code.len() - snapshot_branch - 1)
        .expect("exact load branch fits rel8")
        .to_le_bytes()[0];

    // The crossing path starts at bytes 1..7. Keep that offset in CL, align the snapshot,
    // then shift the combined low/high qwords to the requested scalar field.
    code.extend(SHL_ECX_IMM8);
    code.push(BITS_PER_BYTE_SHIFT);
    code.extend(AND_RDX_IMM8);
    code.push(0u8.wrapping_sub(ATOMIC_QUANTITY_BYTES));
    code.extend(MOVDQA_XMM0_RDX);
    code.extend(MOVQ_RAX_XMM0);
    code.extend(MOVHLPS_XMM0_XMM0);
    code.extend(MOVQ_R8_XMM0);
    code.extend(SHRD_RAX_R8_CL);
    match bytes {
        HALFWORD_BYTES => code.extend(MOVZX_EAX_AX),
        DWORD_BYTES => code.extend(MOV_EAX_EAX),
        QWORD_BYTES => {}
        _ => unreachable!("only wider ordered loads can cross eight bytes"),
    }
    code[done_branch] = i8::try_from(code.len() - done_branch - 1)
        .expect("snapshot branch fits rel8")
        .to_le_bytes()[0];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_potentially_crossing_loads_require_atomic_load16() {
        for kind in [Kind::Acquire, Kind::Release, Kind::AcquirePc] {
            for bytes in [BYTE_BYTES, HALFWORD_BYTES, DWORD_BYTES, QWORD_BYTES] {
                for base in [Register::X(0), Register::X(30), Register::Sp] {
                    let operand = Operand::Transfer {
                        kind,
                        bytes,
                        data: Register::Zero,
                        base,
                    };
                    assert_eq!(
                        requires_atomic_load16(&operand),
                        kind != Kind::Release && bytes != BYTE_BYTES && base != Register::Sp
                    );
                }
            }
        }
        assert!(!requires_atomic_load16(&Operand::Barrier {
            option: 15,
            requirement: Barrier::All,
        }));
    }
}
