use super::*;
use stela_compiler::aarch64::{
    floating::{
        FPCR_AH, FPCR_AHP, FPCR_DN, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FIZ, FPCR_FZ, FPCR_FZ16,
        FPCR_NEP, FPCR_ROUNDING_SHIFT, FPSR_QC, Format, INEXACT, INPUT_DENORMAL, INVALID,
        UnsupportedControl, features::NumericalFeatures,
    },
    scalable::{
        LOOKUP_TABLE_BYTES, PREDICATE_REGISTER_COUNT, ScalableMode, VECTOR_REGISTER_COUNT,
        VectorLength,
    },
};

const FIRST_REGISTER: u8 = 0;
const LAST_REGISTER: u8 = VECTOR_REGISTER_COUNT - 1;
const LAST_GOVERNING: u8 = 7;
const RETAINED_FPSR: u32 = FPSR_QC | (1 << 31);
const SOURCE_SENTINEL: u8 = 0x75;
const CONTROL_SENTINEL: u64 = 0x19ab_43cd_87ef_6501;
const LENGTHS: [usize; 5] = [16, 32, 64, 128, 256];
const OPERATIONS: [RoundingOperation; 7] = [
    RoundingOperation::NearestEven,
    RoundingOperation::NearestAway,
    RoundingOperation::TowardPositive,
    RoundingOperation::TowardNegative,
    RoundingOperation::TowardZero,
    RoundingOperation::Current,
    RoundingOperation::CurrentExact,
];
// Each row is format, +2.5, +2, +3, signaling NaN, quieted NaN.
const FORMATS: [(Format, u64, u64, u64, u64, u64); 3] = [
    (Format::Half, 0x4100, 0x4000, 0x4200, 0x7c01, 0x7e01),
    (
        Format::Single,
        0x4020_0000,
        0x4000_0000,
        0x4040_0000,
        0x7f80_0001,
        0x7fc0_0001,
    ),
    (
        Format::Double,
        0x4004_0000_0000_0000,
        0x4000_0000_0000_0000,
        0x4008_0000_0000_0000,
        0x7ff0_0000_0000_0001,
        0x7ff8_0000_0000_0001,
    ),
];

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    registers: GuestState,
    vectors: Vec<Vec<u8>>,
    predicates: Vec<Vec<u8>>,
    ffr: Vec<u8>,
    za: Vec<u8>,
    zt0: [u8; LOOKUP_TABLE_BYTES],
    mode: ScalableMode,
    tpidr2: u64,
    fpmr: u64,
}

fn numerical_controls(state: &GuestState, full_a64: bool) -> NumericalControls {
    NumericalControls::new(
        state.fpcr,
        true,
        NumericalFeatures::new(full_a64, false, false),
    )
}

fn snapshot(state: &GuestState, scalable: &ScalableState) -> Snapshot {
    let length = scalable.vector_length().bytes();
    let predicate_bytes = scalable.vector_length().predicate_bytes();
    let vectors = (0..VECTOR_REGISTER_COUNT)
        .map(|register| {
            let mut bytes = vec![0; length];
            scalable.read_z(state, register, &mut bytes).unwrap();
            bytes
        })
        .collect();
    let predicates = (0..PREDICATE_REGISTER_COUNT)
        .map(|register| {
            let mut bytes = vec![0; predicate_bytes];
            scalable.read_predicate(register, &mut bytes).unwrap();
            bytes
        })
        .collect();
    let mut ffr = vec![0; predicate_bytes];
    scalable.read_ffr(&mut ffr).unwrap();
    let mut za = vec![0; length * length];
    scalable.read_za(0, &mut za).unwrap();
    let mut zt0 = [0; LOOKUP_TABLE_BYTES];
    scalable.read_zt0(0, &mut zt0).unwrap();
    Snapshot {
        registers: state.clone(),
        vectors,
        predicates,
        ffr,
        za,
        zt0,
        mode: scalable.mode(),
        tpidr2: scalable.tpidr2_el0(),
        fpmr: scalable.fpmr(),
    }
}

fn setup(length: usize) -> (GuestState, ScalableState) {
    let mut state = GuestState {
        x: std::array::from_fn(|index| CONTROL_SENTINEL ^ index as u64),
        sp: CONTROL_SENTINEL,
        nzcv: 0xa000_0000,
        exclusive_bytes: 0x8157_31ab,
        exclusive_address: 0,
        exclusive_value: 0,
        daif: 0,
        pending: 0,
        ..GuestState::default()
    };
    let mut scalable = ScalableState::new(VectorLength::from_bytes(length).unwrap(), true);
    scalable
        .apply_mode(&mut state, ScalableMode::new(true, true))
        .unwrap();
    state.fpsr = RETAINED_FPSR;
    for register in 0..VECTOR_REGISTER_COUNT {
        scalable
            .write_z(
                &mut state,
                register,
                &vec![SOURCE_SENTINEL ^ register; length],
            )
            .unwrap();
    }
    let predicate_bytes = scalable.vector_length().predicate_bytes();
    for register in 0..PREDICATE_REGISTER_COUNT {
        scalable
            .write_predicate(register, &vec![0xa5 ^ register; predicate_bytes])
            .unwrap();
    }
    scalable.write_ffr(&vec![0x39; predicate_bytes]).unwrap();
    scalable.write_za(0, &vec![0x47; length * length]).unwrap();
    scalable.write_zt0(0, &[0x93; LOOKUP_TABLE_BYTES]).unwrap();
    scalable.set_tpidr2_el0(CONTROL_SENTINEL);
    scalable.set_fpmr(!CONTROL_SENTINEL);
    (state, scalable)
}

fn put_lanes(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    register: u8,
    format: Format,
    values: impl Fn(usize) -> u64,
) {
    let length = scalable.vector_length().bytes();
    let element_bytes = format.bits() as usize / BITS_PER_BYTE;
    let mut bytes = vec![0; length];
    for (lane, destination) in bytes.chunks_exact_mut(element_bytes).enumerate() {
        destination.copy_from_slice(&values(lane).to_le_bytes()[..element_bytes]);
    }
    scalable.write_z(state, register, &bytes).unwrap();
}

fn predicate(scalable: &mut ScalableState, element_bytes: usize, active: impl Fn(usize) -> bool) {
    let length = scalable.vector_length().bytes();
    let mut bytes = vec![0; scalable.vector_length().predicate_bytes()];
    for (lane, offset) in (0..length).step_by(element_bytes).enumerate() {
        if active(lane) {
            bytes[offset / BITS_PER_BYTE] |= 1 << (offset % BITS_PER_BYTE);
        }
        // Non-governing bits remain poison and must never activate lanes.
        let ignored = offset + 1;
        bytes[ignored / BITS_PER_BYTE] |= 1 << (ignored % BITS_PER_BYTE);
    }
    scalable.write_predicate(LAST_GOVERNING, &bytes).unwrap();
}

fn operand(operation: RoundingOperation, format: Format, source: u8) -> Operand {
    Operand {
        operation,
        format,
        destination: LAST_REGISTER,
        governing: LAST_GOVERNING,
        source,
    }
}

fn expected(
    state: &GuestState,
    scalable: &ScalableState,
    operand: &Operand,
    values: impl Fn(usize) -> Option<u64>,
    exceptions: u32,
) -> Snapshot {
    let mut expected = snapshot(state, scalable);
    let destination = usize::from(operand.destination);
    let element_bytes = operand.format.bits() as usize / BITS_PER_BYTE;
    for (lane, bytes) in expected.vectors[destination]
        .chunks_exact_mut(element_bytes)
        .enumerate()
    {
        if let Some(value) = values(lane) {
            bytes.copy_from_slice(&value.to_le_bytes()[..element_bytes]);
        }
    }
    for (limb, source) in expected.registers.v[destination].iter_mut().zip(
        expected.vectors[destination][..size_of::<[u64; 2]>()]
            .as_chunks::<{ size_of::<u64>() }>()
            .0,
    ) {
        *limb = u64::from_le_bytes(*source);
    }
    expected.registers.fpsr |= exceptions;
    expected
}

#[test]
fn all_operations_merge_inactive_nan_poison_and_preserve_whole_state() {
    for length in LENGTHS {
        for (format, halfway, two, three, snan, _) in FORMATS {
            for operation in OPERATIONS {
                for source in [FIRST_REGISTER, LAST_REGISTER] {
                    let (mut state, mut scalable) = setup(length);
                    state.fpcr = FPCR_AHP | FPCR_NEP | (1 << FPCR_ROUNDING_SHIFT);
                    put_lanes(&mut state, &mut scalable, source, format, |lane| {
                        if lane % 2 == 0 { halfway } else { snan }
                    });
                    predicate(
                        &mut scalable,
                        format.bits() as usize / BITS_PER_BYTE,
                        |lane| lane % 2 == 0,
                    );
                    let operand = operand(operation, format, source);
                    let rounded = if matches!(
                        operation,
                        RoundingOperation::NearestAway
                            | RoundingOperation::TowardPositive
                            | RoundingOperation::Current
                            | RoundingOperation::CurrentExact
                    ) {
                        three
                    } else {
                        two
                    };
                    let exceptions = if operation == RoundingOperation::CurrentExact {
                        INEXACT
                    } else {
                        0
                    };
                    let expected = expected(
                        &state,
                        &scalable,
                        &operand,
                        |lane| (lane % 2 == 0).then_some(rounded),
                        exceptions,
                    );
                    let controls = numerical_controls(&state, false);
                    complete(&mut state, &mut scalable, &operand, controls).unwrap();
                    assert_eq!(snapshot(&state, &scalable), expected);
                }
            }
        }
    }
}

#[test]
fn active_nan_and_fractional_lanes_contribute_independent_sticky_status() {
    for length in LENGTHS {
        for (format, halfway, two, _, snan, qnan) in FORMATS {
            let (mut state, mut scalable) = setup(length);
            let operand = operand(RoundingOperation::CurrentExact, format, LAST_REGISTER);
            put_lanes(&mut state, &mut scalable, LAST_REGISTER, format, |lane| {
                if lane % 2 == 0 { halfway } else { snan }
            });
            predicate(
                &mut scalable,
                format.bits() as usize / BITS_PER_BYTE,
                |_| true,
            );
            let expected = expected(
                &state,
                &scalable,
                &operand,
                |lane| Some(if lane % 2 == 0 { two } else { qnan }),
                INEXACT | INVALID,
            );
            let controls = numerical_controls(&state, false);
            complete(&mut state, &mut scalable, &operand, controls).unwrap();
            assert_eq!(snapshot(&state, &scalable), expected);
        }
    }
}

#[test]
fn ordinary_streaming_masks_enables_without_normalizing_raw_fpcr() {
    for (format, halfway, two, _, _, _) in FORMATS {
        let (mut state, mut scalable) = setup(MAX_VECTOR_BYTES);
        state.fpcr = FPCR_EXCEPTION_ENABLE_MASK
            | FPCR_AH
            | FPCR_AHP
            | FPCR_NEP
            | FPCR_DN
            | FPCR_FIZ
            | FPCR_FZ
            | FPCR_FZ16;
        let operand = operand(RoundingOperation::CurrentExact, format, FIRST_REGISTER);
        put_lanes(&mut state, &mut scalable, FIRST_REGISTER, format, |_| {
            halfway
        });
        predicate(
            &mut scalable,
            format.bits() as usize / BITS_PER_BYTE,
            |_| true,
        );
        let expected = expected(&state, &scalable, &operand, |_| Some(two), INEXACT);
        let controls = numerical_controls(&state, false);
        complete(&mut state, &mut scalable, &operand, controls).unwrap();
        assert_eq!(snapshot(&state, &scalable), expected);
    }
}

#[test]
fn fa64_enabled_controls_decline_before_commit_even_for_exact_zero() {
    for length in LENGTHS {
        for (format, _, _, _, _, _) in FORMATS {
            let (mut state, mut scalable) = setup(length);
            state.fpcr = FPCR_EXCEPTION_ENABLE_MASK | FPCR_NEP;
            let operand = operand(RoundingOperation::CurrentExact, format, LAST_REGISTER);
            put_lanes(&mut state, &mut scalable, LAST_REGISTER, format, |_| 0);
            predicate(
                &mut scalable,
                format.bits() as usize / BITS_PER_BYTE,
                |lane| lane == 1,
            );
            let before = snapshot(&state, &scalable);
            let controls = numerical_controls(&state, true);
            assert!(matches!(
                complete(&mut state, &mut scalable, &operand, controls),
                Err(CompletionError::UnsupportedControl(
                    UnsupportedControl { .. }
                ))
            ));
            assert_eq!(snapshot(&state, &scalable), before);
        }
    }
}

#[test]
fn all_inactive_does_not_invoke_numerical_control_checks() {
    for length in LENGTHS {
        for (format, _, _, _, snan, _) in FORMATS {
            let (mut state, mut scalable) = setup(length);
            state.fpcr = u32::MAX;
            let operand = operand(RoundingOperation::CurrentExact, format, LAST_REGISTER);
            put_lanes(&mut state, &mut scalable, LAST_REGISTER, format, |_| snan);
            predicate(
                &mut scalable,
                format.bits() as usize / BITS_PER_BYTE,
                |_| false,
            );
            let before = snapshot(&state, &scalable);
            let controls = numerical_controls(&state, true);
            complete(&mut state, &mut scalable, &operand, controls).unwrap();
            assert_eq!(snapshot(&state, &scalable), before);
        }
    }
}

#[test]
fn current_modes_handle_signed_ties_and_only_exact_reports_inexact() {
    for (format, halfway, two, three, _, _) in FORMATS {
        let sign_mask = 1 << (format.bits() - 1);
        for (mode, positive, negative) in [
            (0, two, two),
            (1, three, two),
            (2, two, three),
            (3, two, two),
        ] {
            for operation in [RoundingOperation::Current, RoundingOperation::CurrentExact] {
                let (mut state, mut scalable) = setup(MAX_VECTOR_BYTES);
                state.fpcr = mode << FPCR_ROUNDING_SHIFT;
                let operand = operand(operation, format, LAST_REGISTER);
                put_lanes(&mut state, &mut scalable, LAST_REGISTER, format, |lane| {
                    halfway | if lane % 2 == 0 { 0 } else { sign_mask }
                });
                predicate(
                    &mut scalable,
                    format.bits() as usize / BITS_PER_BYTE,
                    |_| true,
                );
                let exceptions = if operation == RoundingOperation::CurrentExact {
                    INEXACT
                } else {
                    0
                };
                let expected = expected(
                    &state,
                    &scalable,
                    &operand,
                    |lane| {
                        Some(if lane % 2 == 0 {
                            positive
                        } else {
                            negative | sign_mask
                        })
                    },
                    exceptions,
                );
                let controls = numerical_controls(&state, true);
                complete(&mut state, &mut scalable, &operand, controls).unwrap();
                assert_eq!(snapshot(&state, &scalable), expected);
            }
        }
    }
}

#[test]
fn active_subnormal_controls_preserve_zero_sign_and_exact_status() {
    for (format, _, _, _, _, _) in FORMATS {
        let controls = if format == Format::Half {
            vec![
                (0, INEXACT),
                (FPCR_FZ16, 0),
                (FPCR_FIZ | FPCR_FZ, INEXACT),
                (FPCR_AH | FPCR_FIZ | FPCR_FZ, INEXACT),
            ]
        } else {
            vec![
                (0, INEXACT),
                (FPCR_AH | FPCR_FZ, INEXACT),
                (FPCR_FZ, INPUT_DENORMAL),
                (FPCR_FIZ, 0),
                (FPCR_FIZ | FPCR_FZ, INPUT_DENORMAL),
                (FPCR_AH | FPCR_FIZ | FPCR_FZ, 0),
            ]
        };
        let sign_mask = 1 << (format.bits() - 1);
        for (control, exceptions) in controls {
            let (mut state, mut scalable) = setup(MAX_VECTOR_BYTES);
            state.fpcr = control | FPCR_AHP | FPCR_NEP;
            let operand = operand(RoundingOperation::CurrentExact, format, LAST_REGISTER);
            put_lanes(&mut state, &mut scalable, LAST_REGISTER, format, |lane| {
                1 | if lane % 2 == 0 { 0 } else { sign_mask }
            });
            predicate(
                &mut scalable,
                format.bits() as usize / BITS_PER_BYTE,
                |_| true,
            );
            let expected = expected(
                &state,
                &scalable,
                &operand,
                |lane| Some(if lane % 2 == 0 { 0 } else { sign_mask }),
                exceptions,
            );
            let controls = numerical_controls(&state, true);
            complete(&mut state, &mut scalable, &operand, controls).unwrap();
            assert_eq!(snapshot(&state, &scalable), expected);
        }
    }
}

#[test]
fn default_nan_follows_ah_sign_without_changing_raw_controls() {
    for (format, _, _, _, snan, qnan) in FORMATS {
        for alternative in [false, true] {
            let (mut state, mut scalable) = setup(MAX_VECTOR_BYTES);
            state.fpcr = FPCR_DN | if alternative { FPCR_AH } else { 0 };
            let operand = operand(RoundingOperation::NearestEven, format, LAST_REGISTER);
            put_lanes(&mut state, &mut scalable, LAST_REGISTER, format, |_| snan);
            predicate(
                &mut scalable,
                format.bits() as usize / BITS_PER_BYTE,
                |_| true,
            );
            let default_nan = (qnan & !1)
                | if alternative {
                    1 << (format.bits() - 1)
                } else {
                    0
                };
            let expected = expected(&state, &scalable, &operand, |_| Some(default_nan), INVALID);
            let controls = numerical_controls(&state, false);
            complete(&mut state, &mut scalable, &operand, controls).unwrap();
            assert_eq!(snapshot(&state, &scalable), expected);
        }
    }
}

#[test]
fn invalid_operands_decline_without_mutating_any_bank() {
    let (mut state, mut scalable) = setup(MAX_VECTOR_BYTES);
    for operand in [
        Operand {
            source: VECTOR_REGISTER_COUNT,
            ..operand(
                RoundingOperation::NearestEven,
                Format::Single,
                FIRST_REGISTER,
            )
        },
        Operand {
            destination: VECTOR_REGISTER_COUNT,
            ..operand(
                RoundingOperation::NearestEven,
                Format::Single,
                FIRST_REGISTER,
            )
        },
        Operand {
            governing: PREDICATE_REGISTER_COUNT,
            ..operand(
                RoundingOperation::NearestEven,
                Format::Single,
                FIRST_REGISTER,
            )
        },
        operand(
            RoundingOperation::Signed32Current,
            Format::Half,
            FIRST_REGISTER,
        ),
    ] {
        let before = snapshot(&state, &scalable);
        let controls = numerical_controls(&state, false);
        assert!(matches!(
            complete(&mut state, &mut scalable, &operand, controls),
            Err(CompletionError::State(_))
        ));
        assert_eq!(snapshot(&state, &scalable), before);
    }
}
