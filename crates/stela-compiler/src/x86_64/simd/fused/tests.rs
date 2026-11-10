//! Scalar FMADD, FMSUB, FNMADD and FNMSUB on the host against the reference
//! `FPMulAdd` (`aarch64::floating::fused`), with FPSR.IXC clear and set.
use crate::{
    GuestAddress, GuestState, Lifter, TargetCpu,
    aarch64::{
        Decoder,
        floating::{
            FPCR_DN, FPCR_FZ, FPCR_NEP, FPCR_ROUNDING_SHIFT, Format,
            fused::{FusedOperation, evaluate},
        },
    },
    block::ExitKind,
};
use alloc::vec::Vec;
use core::ffi::c_void;
unsafe extern "C" {
    fn mmap(
        address: *mut c_void,
        bytes: usize,
        protection: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut c_void;
    fn mprotect(address: *mut c_void, bytes: usize, protection: i32) -> i32;
    fn munmap(address: *mut c_void, bytes: usize) -> i32;
}
#[cfg(target_os = "macos")]
const MAP_ANONYMOUS: i32 = 0x1000;
#[cfg(target_os = "linux")]
const MAP_ANONYMOUS: i32 = 0x20;
const PAGE: usize = 4096;
const IXC: u32 = 1 << 4;
const PC: GuestAddress = GuestAddress(0x1000);
const UPPER: u64 = 0xa5a5_5a5a_c3c3_3c3c;
/// Vd, Vn, Vm and Va.
const D: u8 = 3;
const N: u8 = 4;
const M: u8 = 5;
const A: u8 = 6;

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
struct Exit {
    pc: u64,
    kind: u64,
}

/// The block of the instruction at [`PC`], run on the host.
struct Native {
    page: *mut c_void,
    bytes: usize,
}

impl Native {
    fn new(code: &[u8]) -> Self {
        let bytes = code.len().next_multiple_of(PAGE);
        // SAFETY: private anonymous memory, RX after the copy; Drop unmaps it.
        unsafe {
            let page = mmap(core::ptr::null_mut(), bytes, 3, 2 | MAP_ANONYMOUS, -1, 0);
            assert_ne!(page as usize, usize::MAX);
            core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
            assert_eq!(mprotect(page, bytes, 5), 0);
            Self { page, bytes }
        }
    }

    fn run(&self, state: &mut GuestState) -> Exit {
        // SAFETY: the block has the frame ABI and writes only `state` and its
        // own stack slots.
        unsafe {
            let entry: unsafe extern "sysv64" fn(*mut GuestState) -> Exit =
                core::mem::transmute(self.page);
            entry(state)
        }
    }
}

impl Drop for Native {
    fn drop(&mut self) {
        // SAFETY: unique mapping; every run returned.
        assert_eq!(unsafe { munmap(self.page, self.bytes) }, 0);
    }
}

fn word(format: Format, operation: FusedOperation) -> u32 {
    let (o1, o0) = match operation {
        FusedOperation::Add => (0, 0),
        FusedOperation::Subtract => (0, 1),
        FusedOperation::NegatedAdd => (1, 0),
        FusedOperation::NegatedSubtract => (1, 1),
    };
    let kind = u32::from(format == Format::Double);
    0x1f00_0000
        | kind << 22
        | o1 << 21
        | u32::from(M) << 16
        | o0 << 15
        | u32::from(A) << 10
        | u32::from(N) << 5
        | u32::from(D)
}

fn single(value: f32) -> u64 {
    u64::from(value.to_bits())
}

/// Inputs of every class the full path takes or declines: signed zeros,
/// normals near 1, the smallest and largest normals, a subnormal, an
/// infinity and a NaN.
fn inputs(format: Format) -> Vec<u64> {
    match format {
        Format::Single => [
            0.0,
            -0.0,
            1.5,
            -2.25,
            3.0,
            1.0e-3,
            f32::MIN_POSITIVE,
            f32::MAX,
            -f32::MAX,
            1.0e-40,
            f32::INFINITY,
            f32::NAN,
        ]
        .map(single)
        .to_vec(),
        Format::Double => [
            0.0,
            -0.0,
            1.5,
            -2.25,
            3.0,
            1.0e-3,
            f64::MIN_POSITIVE,
            f64::MAX,
            -f64::MAX,
            1.0e-310,
            f64::INFINITY,
            f64::NAN,
        ]
        .map(f64::to_bits)
        .to_vec(),
        Format::Half => unreachable!("S/D only"),
    }
}

/// Every completed operation's result and status are the reference's; every
/// other one exits to the helper at its PC with the state unchanged. Zero
/// inputs and exact zero results complete in the block with IXC clear.
#[test]
fn scalar_fused_forms_match_fp_mul_add_in_every_control() {
    let targets = [TargetCpu::Baseline, TargetCpu::detect()];
    let mut completed_zero = [0usize; 2];
    let mut cases = 0;
    for (index, &target) in targets.iter().enumerate() {
        for format in [Format::Single, Format::Double] {
            for operation in [
                FusedOperation::Add,
                FusedOperation::Subtract,
                FusedOperation::NegatedAdd,
                FusedOperation::NegatedSubtract,
            ] {
                let instruction = Decoder.lift(PC, word(format, operation)).unwrap();
                let fallthrough = GuestAddress(PC.0 + 4);
                let code = crate::x86_64::block::emit_for_target(
                    core::slice::from_ref(&instruction),
                    None,
                    fallthrough,
                    target,
                    crate::x86_64::MemoryChecks::DEFAULT,
                )
                .x86_64_code;
                let native = Native::new(&code);
                let values = inputs(format);
                for rounding in 0..4 {
                    for flags in [0, FPCR_FZ, FPCR_DN, FPCR_NEP] {
                        let fpcr = rounding << FPCR_ROUNDING_SHIFT | flags;
                        for &addend in &values {
                            for &left in &values {
                                for &right in &values[..8] {
                                    for fpsr in [0, IXC] {
                                        let mut state = GuestState {
                                            fpcr,
                                            fpsr,
                                            ..GuestState::default()
                                        };
                                        state.v[usize::from(N)] = [left, UPPER];
                                        state.v[usize::from(M)] = [right, UPPER];
                                        state.v[usize::from(A)] = [addend, UPPER];
                                        state.v[usize::from(D)] = [UPPER, UPPER];
                                        let before = state.clone();
                                        let exit = native.run(&mut state);
                                        let case = (
                                            target, format, operation, fpcr, fpsr, addend, left,
                                            right,
                                        );
                                        cases += 1;
                                        if exit.kind == ExitKind::FloatingPoint as u64 {
                                            assert_eq!(exit.pc, PC.0, "{case:x?}");
                                            assert_eq!(state, before, "{case:x?}");
                                            continue;
                                        }
                                        assert_eq!(
                                            exit,
                                            Exit {
                                                pc: fallthrough.0,
                                                kind: ExitKind::Fallthrough as u64
                                            },
                                            "{case:x?}"
                                        );
                                        let outcome =
                                            evaluate(format, operation, fpcr, addend, left, right)
                                                .unwrap();
                                        let mut expected = before.clone();
                                        let upper = if flags == FPCR_NEP {
                                            [addend, UPPER]
                                        } else {
                                            [0, 0]
                                        };
                                        let mask = if format == Format::Single {
                                            u64::from(u32::MAX)
                                        } else {
                                            u64::MAX
                                        };
                                        expected.v[usize::from(D)] =
                                            [outcome.bits | (upper[0] & !mask), upper[1]];
                                        expected.fpsr |= outcome.exceptions;
                                        assert_eq!(state, expected, "{case:x?}");
                                        let zero =
                                            |bits: u64| bits & mask & !(mask ^ mask >> 1) == 0;
                                        if fpsr == 0 && (zero(addend) || zero(left) || zero(right))
                                        {
                                            completed_zero[index] += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(cases > 0);
    // Zero inputs no longer take the helper with IXC clear, on either host
    // recipe.
    for (target, completed) in targets.iter().zip(completed_zero) {
        assert!(completed > 1000, "{target:?}: {completed}");
    }
}

/// The FMADDs seen most at helper exits complete in their block with FPSR
/// clear: a product with a zero addend, a zero product, and normal sums.
#[test]
fn common_fused_multiply_adds_stay_in_the_block_with_ixc_clear() {
    // fmadd s0, s2, s0, s1; fmadd d3, d4, d0, d3; fmadd d0, d3, d0, d2
    for (word, format) in [
        (0x1f00_0440_u32, Format::Single),
        (0x1f40_0c83, Format::Double),
        (0x1f40_0860, Format::Double),
    ] {
        let instruction = Decoder.lift(PC, word).unwrap();
        let fallthrough = GuestAddress(PC.0 + 4);
        let (d, n, m, a) = (
            word as usize & 31,
            (word >> 5) as usize & 31,
            (word >> 16) as usize & 31,
            (word >> 10) as usize & 31,
        );
        for target in [TargetCpu::Baseline, TargetCpu::detect()] {
            let code = crate::x86_64::block::emit_for_target(
                core::slice::from_ref(&instruction),
                None,
                fallthrough,
                target,
                crate::x86_64::MemoryChecks::DEFAULT,
            )
            .x86_64_code;
            let native = Native::new(&code);
            let encode = |value: f64| match format {
                Format::Single => single(value as f32),
                _ => value.to_bits(),
            };
            for (left, right, addend) in [(1.5, 2.0, 0.0), (0.0, 3.0, 1.25), (1.5, 2.0, 0.25)] {
                let mut state = GuestState::default();
                state.v[n][0] = encode(left);
                state.v[m][0] = encode(right);
                state.v[a][0] = encode(addend);
                let (left, right, addend) = (state.v[n][0], state.v[m][0], state.v[a][0]);
                let exit = native.run(&mut state);
                assert_eq!(
                    exit,
                    Exit {
                        pc: fallthrough.0,
                        kind: ExitKind::Fallthrough as u64
                    },
                    "{word:08x} {target:?}"
                );
                let outcome =
                    evaluate(format, FusedOperation::Add, 0, addend, left, right).unwrap();
                assert_eq!(state.v[d], [outcome.bits, 0], "{word:08x} {target:?}");
                assert_eq!(state.fpsr, outcome.exceptions);
            }
        }
    }
}
