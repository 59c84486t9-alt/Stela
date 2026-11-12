//! S/D FMLA, FMLS (vector and by element) and FMADD with subnormal inputs
//! under FZ or FIZ (AH clear) against the Arm reference, compiled as blocks
//! for every tier this host has: the subnormal inputs flush inline (IDC
//! under FZ) and a normal result completes without an exit.
use crate::{
    GuestAddress, GuestState, Options, TargetCpu,
    aarch64::floating::{
        self, FPCR_DN, FPCR_FIZ, FPCR_FZ, FPCR_NEP, Format, fused::FusedOperation,
    },
    block::{BlockProfile, CompilationPlan},
    x86_64::native::run,
};
use alloc::vec::Vec;

const PC: GuestAddress = GuestAddress(0x1000_0000);
const RETURN: u64 = 0x4000;
const D: u32 = 3;
const N: u32 = 4;
const M: u32 = 9;
const A: u32 = 12;

fn targets() -> Vec<TargetCpu> {
    let host = TargetCpu::detect();
    [
        TargetCpu::Baseline,
        TargetCpu::Sse41,
        TargetCpu::X86_64_V2,
        TargetCpu::X86_64_V3,
        TargetCpu::X86_64_V4,
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

#[derive(Clone, Copy, Debug)]
enum Form {
    /// FMLA (false) or FMLS (true) by vector, lanes.
    Vector(bool, u32),
    /// FMLA by element 1 of Vm, lanes.
    Element(u32),
    /// FMADD Dd, Dn, Dm, Da.
    Scalar,
}

fn word(form: Form, format: Format) -> u32 {
    let double = u32::from(format == Format::Double);
    let q = |lanes: u32| u32::from(lanes * format.bits() == 128);
    match form {
        Form::Vector(subtract, lanes) => {
            0x0e20_cc00
                | q(lanes) << 30
                | u32::from(subtract) << 23
                | double << 22
                | M << 16
                | N << 5
                | D
        }
        Form::Element(lanes) => {
            // Element 1: H:L = 0:1 for S, H = 1 for D.
            let index = if double == 1 { 1 << 11 } else { 1 << 21 };
            0x0f80_1000 | q(lanes) << 30 | double << 22 | index | M << 16 | N << 5 | D
        }
        Form::Scalar => 0x1f00_0000 | double << 22 | M << 16 | A << 10 | N << 5 | D,
    }
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

fn reference(form: Form, format: Format, initial: &GuestState) -> GuestState {
    let mut expected = initial.clone();
    let (operation, lanes) = match form {
        Form::Vector(true, lanes) => (FusedOperation::Subtract, lanes),
        Form::Vector(false, lanes) | Form::Element(lanes) => (FusedOperation::Add, lanes),
        Form::Scalar => (FusedOperation::Add, 1),
    };
    let addend = match form {
        Form::Scalar => initial.v[A as usize],
        _ => initial.v[D as usize],
    };
    let mut result = if matches!(form, Form::Scalar) && initial.fpcr & FPCR_NEP != 0 {
        addend
    } else {
        [0; 2]
    };
    for index in 0..lanes as usize {
        let right = match form {
            Form::Element(_) => lane(initial.v[M as usize], format, 1),
            _ => lane(initial.v[M as usize], format, index),
        };
        let outcome = floating::fused::evaluate(
            format,
            operation,
            initial.fpcr,
            lane(addend, format, index),
            lane(initial.v[N as usize], format, index),
            right,
        )
        .unwrap();
        expected.fpsr |= outcome.exceptions;
        set_lane(&mut result, format, index, outcome.bits);
    }
    expected.v[D as usize] = result;
    expected
}

#[test]
fn subnormal_inputs_flush_inline_under_fz() {
    for target in targets() {
        for format in [Format::Single, Format::Double] {
            let one = u64::from(format.exponent_bias()) << format.fraction_bits();
            let subnormal = (1u64 << format.fraction_bits()) - 3;
            let sign = format.sign_mask();
            let values = [one, one | sign, subnormal, subnormal | sign, 3 * one / 2, 0];
            let lanes = if format == Format::Double { 2 } else { 4 };
            let forms = [
                Form::Vector(false, lanes),
                Form::Vector(true, lanes),
                Form::Vector(false, 2),
                Form::Element(lanes),
                Form::Scalar,
            ];
            for form in forms {
                let code = compile(word(form, format), target);
                for start in 0..values.len() {
                    let mut vectors = [[0u64; 2]; 3];
                    for index in 0..lanes as usize {
                        for (which, vector) in vectors.iter_mut().enumerate() {
                            let bits = values[(start + index + which * 2) % values.len()];
                            set_lane(vector, format, index, bits);
                        }
                    }
                    for fpcr in [FPCR_FZ, FPCR_FIZ, FPCR_FZ | FPCR_DN, FPCR_FZ | FPCR_NEP] {
                        let mut initial = GuestState {
                            fpcr,
                            ..GuestState::default()
                        };
                        initial.x[30] = RETURN;
                        initial.v[D as usize] = vectors[0];
                        initial.v[A as usize] = vectors[0];
                        initial.v[N as usize] = vectors[1];
                        initial.v[M as usize] = vectors[2];
                        let mut actual = initial.clone();
                        let label =
                            alloc::format!("{form:?} {format:?} {vectors:x?} {fpcr:#x} {target:?}");
                        assert_eq!(run(&code, &mut actual), RETURN, "exited: {label}");
                        assert_eq!(actual, reference(form, format, &initial), "{label}");
                    }
                }
            }
        }
    }
}
