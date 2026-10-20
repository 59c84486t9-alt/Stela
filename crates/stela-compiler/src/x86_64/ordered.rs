//! Acquire/release accesses and DMB on write-back memory.
//!
//! Release stores use XCHG so a later acquire load cannot pass them, and a
//! full DMB is MFENCE. Checked loads crossing eight bytes read one aligned
//! 16-byte snapshot. For a single agent or PSTATE.DIT
//! ([`super::plain_ordering`]) every access is a plain load or store and a
//! DMB emits nothing: no other agent observes guest memory, and one PE
//! observes its own accesses in program order.
use super::atomic::{address_offset, commit_rax, input_rcx, read_rax, store_rcx};
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
/// The high quadword to the low one. (MOVHLPS is not on Intel's data operand
/// independent timing list.)
const PUNPCKHQDQ_XMM0_XMM0: &[u8] = &[0x66, 0x0f, 0x6d, 0xc0];
const MOVQ_R8_XMM0: &[u8] = &[0x66, 0x49, 0x0f, 0x7e, 0xc0];
const SHRD_RAX_R8_CL: &[u8] = &[0x4c, 0x0f, 0xad, 0xc0];
const SHRD_RAX_R8_IMM8: &[u8] = &[0x4c, 0x0f, 0xac, 0xc0];
const MOVZX_EAX_AX: &[u8] = &[0x0f, 0xb7, 0xc0];
const MOV_EAX_EAX: &[u8] = &[0x89, 0xc0];
const MOV_EAX_EDX: &[u8] = &[0x89, 0xd0];
const AND_EAX_IMM8: &[u8] = &[0x83, 0xe0];
const CMP_AL_IMM8: u8 = 0x3c;
const JBE_REL8: u8 = 0x76;
const ATOMIC_QUANTITY_MASK: u8 = ATOMIC_QUANTITY_BYTES - 1;

/// Whether an ordered access crosses its 16-byte granule, which it may only
/// with SCTLR_ELx.nAA set (no granule check).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Crossing {
    Never,
    Always,
    /// Decided at run time from the address.
    Maybe,
}

fn crossing(base: Register, bytes: u8, displacement: i32, checks: super::MemoryChecks) -> Crossing {
    if checks.ordered_granule || bytes == BYTE_BYTES {
        Crossing::Never
    } else if base == Register::Sp && checks.stack_alignment {
        if displacement.rem_euclid(i32::from(ATOMIC_QUANTITY_BYTES))
            > i32::from(ATOMIC_QUANTITY_BYTES - bytes)
        {
            Crossing::Always
        } else {
            Crossing::Never
        }
    } else {
        Crossing::Maybe
    }
}

/// Jump, by a rel8 the caller patches, when the access at RDX lies inside
/// its 16-byte granule. EAX is scratch.
fn branch_within_granule(code: &mut Vec<u8>, bytes: u8) -> usize {
    code.extend(MOV_EAX_EDX);
    code.extend(AND_EAX_IMM8);
    code.push(ATOMIC_QUANTITY_MASK);
    code.extend([CMP_AL_IMM8, ATOMIC_QUANTITY_BYTES - bytes, JBE_REL8]);
    code.push(0);
    code.len() - 1
}

fn jump_over(code: &mut Vec<u8>) -> usize {
    code.extend([JMP_REL8, 0]);
    code.len() - 1
}

fn patch(code: &mut [u8], at: usize) {
    code[at] = i8::try_from(code.len() - at - 1)
        .expect("ordered path fits rel8")
        .to_le_bytes()[0];
}

/// Generic wider loads can cross eight bytes. A checked, so aligned, SP makes
/// the effective residue known; a statically faulting access never needs a
/// snapshot capability, and neither does a plain load
/// ([`super::plain_ordering`]) or a load on an Intel host, where a load
/// inside its 16-byte granule, so inside one cache line, is single-copy
/// atomic ([`TargetCpu::LineAtomic`]).
pub(super) fn requires_atomic_load16(
    operand: &Operand,
    target: TargetCpu,
    checks: super::MemoryChecks,
) -> bool {
    if super::plain_ordering(target, checks) || target.supports(TargetCpu::LineAtomic) {
        return false;
    }
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
        || !checks.stack_alignment
        || (displacement.rem_euclid(i32::from(ATOMIC_QUANTITY_BYTES))
            <= i32::from(ATOMIC_QUANTITY_BYTES - bytes)
            && displacement.rem_euclid(i32::from(BASELINE_ATOMIC_BYTES))
                > i32::from(BASELINE_ATOMIC_BYTES - bytes))
}

pub(super) fn emit(
    code: &mut Vec<u8>,
    operand: &Operand,
    target: TargetCpu,
    checks: super::MemoryChecks,
) {
    let plain = super::plain_ordering(target, checks);
    match *operand {
        Operand::Barrier { requirement, .. } => {
            // Cached ordinary WB accesses already preserve reads→reads/writes
            // and writes→writes. Full barriers additionally close store→load,
            // which only another agent could observe.
            match requirement {
                Barrier::All if !plain => code.extend(MFENCE),
                Barrier::All | Barrier::Reads | Barrier::Writes => code.push(NOP),
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
            address_offset(
                code,
                base,
                bytes,
                displacement,
                checks,
                checks.ordered_granule,
                super::Access::of(kind == Kind::Release, bytes.into()),
            );
            // An access that crosses its granule needs no single-copy
            // atomicity: it takes a plain load, or a store and a full fence.
            let crossing = crossing(base, bytes, displacement, checks);
            if plain {
                // With no other agent, a plain access is single-copy atomic
                // and ordered after every earlier access and before every
                // later one, wherever it lies in its granule. (XCHG and
                // MFENCE are also not on Intel's data operand independent
                // timing list.)
                if kind == Kind::Release {
                    input_rcx(code, bytes, data);
                    store_rcx(code, bytes);
                } else {
                    read_extended(code, bytes, extension);
                    commit_rax(code, bytes, data);
                }
            } else if kind == Kind::Release {
                input_rcx(code, bytes, data);
                match crossing {
                    Crossing::Never => release(code, bytes),
                    Crossing::Always => crossing_release(code, bytes),
                    Crossing::Maybe => {
                        let within = branch_within_granule(code, bytes);
                        crossing_release(code, bytes);
                        let done = jump_over(code);
                        patch(code, within);
                        release(code, bytes);
                        patch(code, done);
                    }
                }
            } else {
                let mut done = None;
                if crossing == Crossing::Maybe {
                    let within = branch_within_granule(code, bytes);
                    read_extended(code, bytes, extension);
                    done = Some(jump_over(code));
                    patch(code, within);
                }
                if crossing == Crossing::Always {
                    read_extended(code, bytes, extension);
                } else if requires_atomic_load16(operand, target, checks) {
                    // The compiler validates this requirement before emission.
                    debug_assert!(target.supports(TargetCpu::AtomicLoad16));
                    if base == Register::Sp && checks.stack_alignment {
                        let offset =
                            displacement.rem_euclid(i32::from(BASELINE_ATOMIC_BYTES)) as u8;
                        snapshot_value(code, bytes, extension, Some(offset << BITS_PER_BYTE_SHIFT));
                    } else {
                        acquire_snapshot(code, bytes, extension);
                    }
                } else {
                    read_extended(code, bytes, extension);
                }
                if let Some(done) = done {
                    patch(code, done);
                }
                // ZR still performs the access, including its acquire order.
                commit_rax(code, bytes, data);
            }
        }
    }
}

/// A store-release that crosses its granule: a plain store, which x86 keeps
/// in order after earlier accesses, and MFENCE, which keeps later
/// load-acquires after it (RCsc).
fn crossing_release(code: &mut Vec<u8>, bytes: u8) {
    store_rcx(code, bytes);
    code.extend(MFENCE);
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
    code.extend(PUNPCKHQDQ_XMM0_XMM0);
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
mod tests {
    use super::*;
    use crate::x86_64::MemoryChecks;

    const UNCHECKED: MemoryChecks = MemoryChecks {
        stack_alignment: false,
        ..MemoryChecks::DEFAULT
    };

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
                        displacement: 0,
                        extension: LoadExtension::Zero,
                    };
                    assert_eq!(
                        requires_atomic_load16(
                            &operand,
                            TargetCpu::detect(),
                            MemoryChecks::DEFAULT
                        ),
                        kind != Kind::Release && bytes != BYTE_BYTES && base != Register::Sp
                    );
                    // An unchecked SP is an ordinary base.
                    assert_eq!(
                        requires_atomic_load16(&operand, TargetCpu::detect(), UNCHECKED),
                        kind != Kind::Release && bytes != BYTE_BYTES
                    );
                }
            }
        }
        for bytes in [HALFWORD_BYTES, DWORD_BYTES, QWORD_BYTES] {
            for displacement in -256..=255 {
                let operand = Operand::Transfer {
                    kind: Kind::AcquirePc,
                    bytes,
                    data: Register::X(0),
                    base: Register::Sp,
                    displacement,
                    extension: LoadExtension::Sign(Width::X64),
                };
                let effective = (256 + displacement) as usize;
                let last = effective + usize::from(bytes) - 1;
                let inside_quantity = effective / 16 == last / 16;
                let crosses_baseline = effective / 8 != last / 8;
                assert_eq!(
                    requires_atomic_load16(&operand, TargetCpu::detect(), MemoryChecks::DEFAULT),
                    inside_quantity && crosses_baseline
                );
            }
        }
        assert!(!requires_atomic_load16(
            &Operand::Barrier {
                option: 15,
                requirement: Barrier::All,
            },
            TargetCpu::detect(),
            MemoryChecks::DEFAULT,
        ));
        // A single agent's acquire loads are plain loads.
        let single = MemoryChecks {
            single_agent: true,
            ..MemoryChecks::DEFAULT
        };
        let operand = Operand::Transfer {
            kind: Kind::Acquire,
            bytes: QWORD_BYTES,
            data: Register::X(0),
            base: Register::X(1),
            displacement: 0,
            extension: LoadExtension::Zero,
        };
        assert!(!requires_atomic_load16(
            &operand,
            TargetCpu::detect(),
            single
        ));
    }

    #[test]
    fn a_single_agent_takes_plain_ordered_accesses_and_drops_dmb() {
        let single = MemoryChecks {
            single_agent: true,
            ordered_granule: false,
            ..MemoryChecks::DEFAULT
        };
        let has =
            |code: &[u8], bytes: &[u8]| code.windows(bytes.len()).any(|window| window == bytes);
        let mut barrier = Vec::new();
        emit(
            &mut barrier,
            &Operand::Barrier {
                option: 15,
                requirement: Barrier::All,
            },
            TargetCpu::detect(),
            single,
        );
        assert_eq!(barrier, [NOP]);
        for kind in [Kind::Acquire, Kind::AcquirePc, Kind::Release] {
            let operand = Operand::Transfer {
                kind,
                bytes: QWORD_BYTES,
                data: Register::X(1),
                base: Register::X(2),
                displacement: 0,
                extension: LoadExtension::Zero,
            };
            let mut code = Vec::new();
            emit(&mut code, &operand, TargetCpu::detect(), single);
            // No XCHG, MFENCE, 16-byte snapshot or granule branch.
            assert!(!has(&code, &[0x48, 0x87, 0x0a]) && !has(&code, MFENCE));
            assert!(!has(&code, MOVDQA_XMM0_RDX) && !has(&code, &[0x89, 0xd0, 0x83, 0xe0]));
            if kind == Kind::Release {
                assert!(code.ends_with(&[0x48, 0x89, 0x0a]));
            } else {
                // mov rax,[rdx], then the commit to X1.
                assert!(code.ends_with(&[0x48, 0x8b, 0x02, 0x48, 0x89, 0x87, 8, 0, 0, 0]));
            }
        }
    }

    #[test]
    fn with_naa_set_a_granule_crossing_takes_a_plain_path_instead_of_faulting() {
        const UD2: [u8; 2] = [0x0f, 0x0b];
        let relaxed = MemoryChecks {
            ordered_granule: false,
            ..MemoryChecks::DEFAULT
        };
        let emitted = |kind, base, displacement, checks| {
            let mut code = Vec::new();
            let operand = Operand::Transfer {
                kind,
                bytes: DWORD_BYTES,
                data: Register::X(1),
                base,
                displacement,
                extension: LoadExtension::Zero,
            };
            emit(&mut code, &operand, TargetCpu::detect(), checks);
            code
        };
        let has =
            |code: &[u8], bytes: &[u8]| code.windows(bytes.len()).any(|window| window == bytes);
        // mov eax,edx; and eax,15; cmp al,12; jbe: the run-time granule test.
        let within = [0x89, 0xd0, 0x83, 0xe0, 0x0f, 0x3c, 12, 0x76];
        for kind in [Kind::Acquire, Kind::AcquirePc, Kind::Release] {
            let checked = emitted(kind, Register::X(2), 0, MemoryChecks::DEFAULT);
            assert!(has(&checked, &UD2) && !has(&checked, &within));
            let code = emitted(kind, Register::X(2), 0, relaxed);
            assert!(!has(&code, &UD2) && has(&code, &within));
            // A crossing store-release is a plain store and a full fence.
            assert_eq!(
                kind == Kind::Release,
                has(&code, &[0x89, 0x0a, 0x0f, 0xae, 0xf0])
            );
        }
        // A checked SP settles the residue: SP+14 always crosses, and with
        // the granule check it always faults.
        let crossing = emitted(Kind::Release, Register::Sp, 14, relaxed);
        assert!(!has(&crossing, &within) && has(&crossing, &[0x89, 0x0a, 0x0f, 0xae, 0xf0]));
        assert!(has(
            &emitted(Kind::Release, Register::Sp, 14, MemoryChecks::DEFAULT),
            &UD2
        ));
        let inside = emitted(Kind::Release, Register::Sp, 4, relaxed);
        assert!(!has(&inside, &within) && !has(&inside, &[0x0f, 0xae, 0xf0]));
    }

    #[test]
    fn data_independent_timing_store_releases_are_plain_stores() {
        let relaxed = MemoryChecks {
            ordered_granule: false,
            ..MemoryChecks::DEFAULT
        };
        let has =
            |code: &[u8], bytes: &[u8]| code.windows(bytes.len()).any(|window| window == bytes);
        for (bytes, store) in [
            (BYTE_BYTES, &[0x88, 0x0a][..]),
            (HALFWORD_BYTES, &[0x66, 0x89, 0x0a]),
            (DWORD_BYTES, &[0x89, 0x0a]),
            (QWORD_BYTES, &[0x48, 0x89, 0x0a]),
        ] {
            for checks in [MemoryChecks::DEFAULT, relaxed] {
                let operand = Operand::Transfer {
                    kind: Kind::Release,
                    bytes,
                    data: Register::X(1),
                    base: Register::X(2),
                    displacement: 0,
                    extension: LoadExtension::Zero,
                };
                let mut code = Vec::new();
                emit(
                    &mut code,
                    &operand,
                    TargetCpu::DataIndependentTiming,
                    checks,
                );
                // No XCHG with [rdx] and no MFENCE, even for a crossing.
                assert!(code.ends_with(store), "{bytes}");
                assert!(!has(&code, &[0x86, 0x0a]) && !has(&code, &[0x87, 0x0a]));
                assert!(!has(&code, MFENCE));
            }
        }
    }
}
