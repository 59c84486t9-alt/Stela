//! S/D FDIV with zero divisors against the Arm reference, compiled as
//! blocks for every tier this host has: every inline completion matches
//! the reference in every V register and FPSR, every exit leaves the state
//! unchanged, and a finite normal dividend over a zero divisor completes
//! with DZC.
use crate::{
    GuestAddress, GuestState, Options, TargetCpu,
    aarch64::floating::{
        self, BinaryOperation, FPCR_AH, FPCR_DN, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FIZ, FPCR_FZ,
        FPCR_NEP, FPCR_ROUNDING_SHIFT, Format,
    },
    block::{BlockProfile, CompilationPlan},
    x86_64::native::run,
};
use alloc::vec::Vec;

const PC: GuestAddress = GuestAddress(0x1000_0000);
const RETURN: u64 = 0x4000;
const D: u32 = 3;
const N: u32 = 4;
const M: u32 = 17;

fn targets() -> Vec<TargetCpu> {
    let host = TargetCpu::detect();
    [
        TargetCpu::Baseline,
        TargetCpu::Sse41,
        TargetCpu::X86_64_V2,
        TargetCpu::X86_64_V3,
        TargetCpu::X86_64_V4,
        TargetCpu::X86_64_V4.with_data_independent_timing(),
        host,
    ]
    .into_iter()
    .filter(|target| host.supports(*target))
    .collect()
}

fn compile(word: u32, target: TargetCpu) -> Vec<u8> {
    let source = [word, 0xd65f_03c0].map(u32::to_le_bytes).concat();
    CompilationPlan::new(&source, PC, &Options::new(BlockProfile::ORDINARY, target))
        .unwrap()
        .compile()
        .unwrap()
        .native
        .x86_64_code
}

fn controls() -> [u32; 8] {
    [
        0,
        2 << FPCR_ROUNDING_SHIFT,
        FPCR_FZ,
        FPCR_FIZ,
        FPCR_DN,
        FPCR_FZ | FPCR_NEP,
        FPCR_AH,
        FPCR_EXCEPTION_ENABLE_MASK,
    ]
}

fn lane(vector: [u64; 2], format: Format, index: usize) -> u64 {
    if format == Format::Double {
        vector[index]
    } else {
        vector[index / 2] >> (32 * (index % 2)) & 0xffff_ffff
    }
}

fn set_lane(vector: &mut [u64; 2], format: Format, index: usize, bits: u64) {
    if format == Format::Double {
        vector[index] = bits;
    } else {
        let shift = 32 * (index % 2);
        vector[index / 2] = vector[index / 2] & !(0xffff_ffff << shift) | bits << shift;
    }
}

fn divide_word(format: Format, lanes: u32) -> u32 {
    let double = u32::from(format == Format::Double);
    let registers = M << 16 | N << 5 | D;
    if lanes == 0 {
        return 0x1e20_1800 | double << 22 | registers;
    }
    0x2e20_fc00 | u32::from(lanes * format.bits() == 128) << 30 | double << 22 | registers
}

#[allow(clippy::too_many_arguments)]
fn check(
    word: u32,
    target: TargetCpu,
    format: Format,
    lanes: u32,
    initial: &GuestState,
    reference: impl Fn(u64, u64) -> Option<floating::Outcome>,
    merge: Option<[u64; 2]>,
    must_inline: bool,
    runs: &mut usize,
) {
    let code = compile(word, target);
    let mut actual = initial.clone();
    let exit = run(&code, &mut actual);
    *runs += 1;
    let label = alloc::format!(
        "{word:08x} {:x?} {:x?} {:#x} {target:?}",
        initial.v[N as usize],
        initial.v[M as usize],
        initial.fpcr
    );
    if exit == PC.0 {
        assert_eq!(&actual, initial, "{label}");
        assert!(!must_inline, "exited: {label}");
        return;
    }
    assert_eq!(exit, RETURN, "{label}");
    let mut expected = initial.clone();
    let mut result = merge.unwrap_or([0; 2]);
    for index in 0..lanes.max(1) as usize {
        let outcome = reference(
            lane(initial.v[N as usize], format, index),
            lane(initial.v[M as usize], format, index),
        )
        .expect("completed with traps");
        expected.fpsr |= outcome.exceptions;
        set_lane(&mut result, format, index, outcome.bits);
    }
    expected.v[D as usize] = result;
    assert_eq!(actual, expected, "{label}");
}

fn shapes(format: Format) -> &'static [u32] {
    if format == Format::Double {
        &[0, 2]
    } else {
        &[0, 2, 4]
    }
}

#[test]
fn zero_divisors_complete_with_divide_by_zero() {
    let mut runs = 0;
    for target in targets() {
        for format in [Format::Single, Format::Double] {
            let one = u64::from(format.exponent_bias()) << format.fraction_bits();
            let sign = format.sign_mask();
            let dividends = [one, (3 * one / 2) | sign, 0, sign];
            for &lanes in shapes(format) {
                let word = divide_word(format, lanes);
                for (start, _) in dividends.iter().enumerate() {
                    let mut n = [0; 2];
                    let mut m = [0; 2];
                    for index in 0..lanes.max(1) as usize {
                        set_lane(&mut n, format, index, dividends[(start + index) % 4]);
                        // Zero divisors of both signs, and normal ones.
                        let divisor = [0, sign, one, 0][(start + 2 * index) % 4];
                        set_lane(&mut m, format, index, divisor);
                    }
                    let zero_over_zero = (0..lanes.max(1) as usize).any(|index| {
                        lane(n, format, index) & !sign == 0 && lane(m, format, index) & !sign == 0
                    });
                    for fpcr in controls() {
                        let mut initial = GuestState {
                            fpcr,
                            fpsr: 0x0800_0000,
                            ..GuestState::default()
                        };
                        initial.x[30] = RETURN;
                        initial.v[N as usize] = n;
                        initial.v[M as usize] = m;
                        initial.v[D as usize] = [0xdead_beef_0bad_f00d, 0xfeed_face_cafe_d00d];
                        let merge = (lanes == 0 && fpcr & FPCR_NEP != 0).then_some(n);
                        let must_inline = !zero_over_zero
                            && fpcr & FPCR_EXCEPTION_ENABLE_MASK == 0
                            && !target.data_independent_timing();
                        check(
                            word,
                            target,
                            format,
                            lanes,
                            &initial,
                            |left, right| {
                                floating::evaluate(
                                    format,
                                    BinaryOperation::Divide,
                                    fpcr,
                                    left,
                                    right,
                                )
                                .ok()
                            },
                            merge,
                            must_inline,
                            &mut runs,
                        );
                    }
                }
            }
        }
    }
    assert!(runs > 0);
}
