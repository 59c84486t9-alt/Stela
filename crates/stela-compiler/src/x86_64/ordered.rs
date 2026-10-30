//! Acquire/release accesses and DMB on write-back memory.
//!
//! Release stores use XCHG so a later acquire load cannot pass them, and a
//! full DMB is MFENCE. Checked loads crossing eight bytes read one aligned
//! 16-byte snapshot. For a single agent or PSTATE.DIT
//! ([`super::plain_ordering`]) every access is a plain load or store and a
//! DMB emits nothing: no other agent observes guest memory, and one PE
//! observes its own accesses in program order.
use super::atomic::{address_offset, commit_rax, input_rcx, read_rax, store_rcx};
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, Mem, Patch, Rm, ShiftOp, Size};
use crate::x86_64::isa::SimdOpcode;
use crate::{
    TargetCpu,
    aarch64::{
        Register, Width,
        ordered::{Barrier, Kind, LoadExtension, Operand},
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
const ATOMIC_QUANTITY_MASK: u8 = ATOMIC_QUANTITY_BYTES - 1;
/// `[rdx]`, the checked guest address.
const ADDRESS: Mem = Mem::base(Gpr::Rdx, 0);

/// The operand size of a `bytes`-wide access.
fn size(bytes: u8) -> Size {
    match bytes {
        BYTE_BYTES => Size::Byte,
        HALFWORD_BYTES => Size::Word,
        DWORD_BYTES => Size::Dword,
        _ => Size::Qword,
    }
}

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

/// Jump, by a rel8 the caller binds, when the access at RDX lies inside
/// its 16-byte granule. EAX is scratch.
fn branch_within_granule(code: &mut Code, bytes: u8) -> Patch {
    let mut asm = code.asm();
    asm.mov(Size::Dword, Gpr::Rax, Gpr::Rdx);
    asm.alu_imm8(Alu::And, Size::Dword, Gpr::Rax, ATOMIC_QUANTITY_MASK as i8);
    asm.alu_accumulator_imm8(Alu::Cmp, ATOMIC_QUANTITY_BYTES - bytes);
    asm.jcc8(Cond::Be)
}

fn jump_over(code: &mut Code) -> Patch {
    code.asm().jmp8()
}

fn patch(code: &mut Code, branch: Patch) {
    code.asm().bind(branch);
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
    code: &mut Code,
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
                Barrier::All if !plain => code.asm().mfence(),
                Barrier::All | Barrier::Reads | Barrier::Writes => code.asm().nop(),
            }
        }
        Operand::Transfer {
            kind,
            bytes,
            data,
            base,
            displacement,
            extension,
            ..
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
                        snapshot_value(
                            code,
                            bytes,
                            extension,
                            Some(offset << BITS_PER_BYTE_SHIFT),
                            target,
                        );
                    } else {
                        acquire_snapshot(code, bytes, extension, target);
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
fn crossing_release(code: &mut Code, bytes: u8) {
    store_rcx(code, bytes);
    code.asm().mfence();
}

fn release(code: &mut Code, bytes: u8) {
    code.asm()
        .guest_access(|asm| asm.xchg(size(bytes), ADDRESS, Gpr::Rcx));
}

fn read_extended(code: &mut Code, bytes: u8, extension: LoadExtension) {
    match extension {
        LoadExtension::Zero => read_rax(code, bytes),
        LoadExtension::Sign(width) => sign_extend(code, bytes, width, ADDRESS.into()),
    }
}

/// The memory and register forms share the same extension semantics. A W result
/// clears upper X bits through its 32-bit destination; an X result sign-fills them.
fn sign_extend(code: &mut Code, bytes: u8, width: Width, operand: Rm) {
    let wide = Size::of(width == Width::X64);
    let mut asm = code.asm();
    let emit = |asm: &mut crate::x86_64::asm::Asm<'_>| match bytes {
        BYTE_BYTES | HALFWORD_BYTES => asm.movsx(wide, Gpr::Rax, size(bytes), operand),
        DWORD_BYTES if width == Width::X64 => asm.movsxd(Gpr::Rax, operand),
        _ => unreachable!("decoder validates ordered signed widths"),
    };
    if matches!(operand, Rm::Mem(_)) {
        asm.guest_access(emit)
    } else {
        emit(&mut asm)
    }
}

/// A legal ordered access is contained inside 16 bytes. Exact reads contained inside eight bytes
/// use the baseline guarantee; only the crossing path reads the containing 16 bytes.
fn acquire_snapshot(code: &mut Code, bytes: u8, extension: LoadExtension, target: TargetCpu) {
    let mut asm = code.asm();
    asm.mov(Size::Dword, Gpr::Rcx, Gpr::Rdx);
    asm.alu_imm8(Alu::And, Size::Dword, Gpr::Rcx, BASELINE_ATOMIC_MASK as i8);
    asm.alu_byte_imm(Alu::Cmp, Gpr::Rcx, BASELINE_ATOMIC_BYTES - bytes);
    let snapshot = asm.jcc8(Cond::A);
    read_extended(code, bytes, extension);
    let done = jump_over(code);
    patch(code, snapshot);
    snapshot_value(code, bytes, extension, None, target);
    patch(code, done);
}

/// A known SP residue avoids a runtime boundary branch and variable shift setup.
/// Generic crossings keep their established CL recipe and output bytes.
fn snapshot_value(
    code: &mut Code,
    bytes: u8,
    extension: LoadExtension,
    shift: Option<u8>,
    target: TargetCpu,
) {
    let mut asm = code.asm();
    if shift.is_none() {
        asm.shift_imm(ShiftOp::Shl, Size::Dword, Gpr::Rcx, BITS_PER_BYTE_SHIFT);
    }
    asm.alu_imm8(
        Alu::And,
        Size::Qword,
        Gpr::Rdx,
        -i8::try_from(ATOMIC_QUANTITY_BYTES).expect("granule fits imm8"),
    );
    asm.guest_access(|asm| asm.simd(SimdOpcode::MoveAligned, 0, ADDRESS, target));
    asm.movq_from_xmm(Gpr::Rax, 0);
    // The high quadword to the low one. (MOVHLPS is not on Intel's data
    // operand independent timing list.)
    asm.simd(SimdOpcode::UnpackHighQword, 0, Rm::Xmm(0), target);
    asm.movq_from_xmm(Gpr::R8, 0);
    match shift {
        Some(shift) => asm.shrd_imm(Size::Qword, Gpr::Rax, Gpr::R8, shift),
        None => asm.shrd_cl(Size::Qword, Gpr::Rax, Gpr::R8),
    }
    match extension {
        LoadExtension::Sign(width) => sign_extend(code, bytes, width, Gpr::Rax.into()),
        LoadExtension::Zero => match bytes {
            HALFWORD_BYTES => asm.movzx(Size::Dword, Gpr::Rax, Size::Word, Gpr::Rax),
            DWORD_BYTES => asm.mov(Size::Dword, Gpr::Rax, Gpr::Rax),
            QWORD_BYTES => {}
            _ => unreachable!("only wider ordered loads can cross eight bytes"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86_64::MemoryChecks;

    const MFENCE: &[u8] = &[0x0f, 0xae, 0xf0];
    const MOVDQA_XMM0_RDX: &[u8] = &[0x66, 0x0f, 0x6f, 0x02];
    const UNCHECKED: MemoryChecks = MemoryChecks {
        stack_alignment: false,
        ..MemoryChecks::DEFAULT
    };

    #[test]
    fn only_potentially_crossing_loads_require_atomic_load16() {
        // A line-atomic (Intel) host never needs the granule load.
        let target = TargetCpu::X86_64_V3;
        for kind in [Kind::Acquire, Kind::Release, Kind::AcquirePc] {
            for bytes in [BYTE_BYTES, HALFWORD_BYTES, DWORD_BYTES, QWORD_BYTES] {
                for base in [Register::X(0), Register::X(30), Register::Sp] {
                    let operand = Operand::Transfer {
                        feature: crate::aarch64::ordered::Feature::Base,
                        kind,
                        bytes,
                        data: Register::Zero,
                        base,
                        displacement: 0,
                        extension: LoadExtension::Zero,
                    };
                    assert_eq!(
                        requires_atomic_load16(&operand, target, MemoryChecks::DEFAULT),
                        kind != Kind::Release && bytes != BYTE_BYTES && base != Register::Sp
                    );
                    // An unchecked SP is an ordinary base.
                    assert_eq!(
                        requires_atomic_load16(&operand, target, UNCHECKED),
                        kind != Kind::Release && bytes != BYTE_BYTES
                    );
                }
            }
        }
        for bytes in [HALFWORD_BYTES, DWORD_BYTES, QWORD_BYTES] {
            for displacement in -256..=255 {
                let operand = Operand::Transfer {
                    feature: crate::aarch64::ordered::Feature::Base,
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
                    requires_atomic_load16(&operand, target, MemoryChecks::DEFAULT),
                    inside_quantity && crosses_baseline
                );
            }
        }
        assert!(!requires_atomic_load16(
            &Operand::Barrier {
                option: 15,
                requirement: Barrier::All,
            },
            target,
            MemoryChecks::DEFAULT,
        ));
        // A single agent's acquire loads are plain loads.
        let single = MemoryChecks {
            single_agent: true,
            ..MemoryChecks::DEFAULT
        };
        let operand = Operand::Transfer {
            feature: crate::aarch64::ordered::Feature::Base,
            kind: Kind::Acquire,
            bytes: QWORD_BYTES,
            data: Register::X(0),
            base: Register::X(1),
            displacement: 0,
            extension: LoadExtension::Zero,
        };
        assert!(!requires_atomic_load16(&operand, target, single));
        assert!(!requires_atomic_load16(
            &operand,
            target.with_line_atomic(),
            MemoryChecks::DEFAULT
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
        let mut barrier = Code::new();
        emit(
            &mut barrier,
            &Operand::Barrier {
                option: 15,
                requirement: Barrier::All,
            },
            TargetCpu::detect(),
            single,
        );
        assert_eq!(barrier, [0x90]);
        for kind in [Kind::Acquire, Kind::AcquirePc, Kind::Release] {
            let operand = Operand::Transfer {
                feature: crate::aarch64::ordered::Feature::Base,
                kind,
                bytes: QWORD_BYTES,
                data: Register::X(1),
                base: Register::X(2),
                displacement: 0,
                extension: LoadExtension::Zero,
            };
            let mut code = Code::new();
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
            let mut code = Code::new();
            let operand = Operand::Transfer {
                feature: crate::aarch64::ordered::Feature::Base,
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
                    feature: crate::aarch64::ordered::Feature::Base,
                    kind: Kind::Release,
                    bytes,
                    data: Register::X(1),
                    base: Register::X(2),
                    displacement: 0,
                    extension: LoadExtension::Zero,
                };
                let mut code = Code::new();
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
