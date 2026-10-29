use super::*;
use stela_compiler::aarch64::{
    floating::{
        FPCR_EXCEPTION_ENABLE_MASK, FPCR_ROUNDING_SHIFT, FPSR_QC, INEXACT, INVALID,
        features::NumericalFeatures, integer::IntegerFormat,
    },
    scalable::{ScalableMode, VectorLength},
};

const DESTINATION: u8 = 7;
const SOURCE: u8 = 1;
const GOVERNING: u8 = 0;
const SENTINEL: u8 = 0xa5;
const DOUBLE_NEGATIVE_ONE_AND_HALF: u64 = 0xbff8_0000_0000_0000;
const DOUBLE_ONE_AND_HALF: u64 = 0x3ff8_0000_0000_0000;
const SINGLE_ONE_AND_HALF: u32 = 0x3fc0_0000;
const SINGLE_NEGATIVE_THREE_QUARTERS: u32 = 0xbf40_0000;
const SINGLE_QUIET_NAN: u32 = 0x7fc0_0001;
const SINGLE_INFINITY: u32 = 0x7f80_0000;
const SINGLE_EXACT_INTEGER_LIMIT: i64 = 1 << 24;
const SINGLE_EXACT_LIMIT_BITS: u64 = 0x4b80_0000;
const SINGLE_NEGATIVE_EXACT_LIMIT_BITS: u64 = 0xcb80_0000;

fn setup(length: usize) -> (GuestState, ScalableState) {
    let mut state = GuestState::default();
    let mut scalable = ScalableState::new(VectorLength::from_bytes(length).unwrap(), true);
    scalable
        .apply_mode(&mut state, ScalableMode::new(true, true))
        .unwrap();
    scalable
        .write_z(&mut state, DESTINATION, &vec![SENTINEL; length])
        .unwrap();
    state.fpsr = FPSR_QC;
    (state, scalable)
}

fn controls(state: &GuestState, full_a64: bool) -> NumericalControls {
    NumericalControls::new(
        state.fpcr,
        true,
        NumericalFeatures::new(full_a64, false, false),
    )
}

fn predicate(scalable: &mut ScalableState, positions: &[usize]) {
    let mut bytes = vec![0; scalable.vector_length().predicate_bytes()];
    for byte in positions {
        bytes[byte / BITS_PER_BYTE] |= 1 << (byte % BITS_PER_BYTE);
    }
    scalable.write_predicate(GOVERNING, &bytes).unwrap();
}

fn destination(scalable: &ScalableState, state: &GuestState) -> Vec<u8> {
    let mut bytes = vec![0; scalable.vector_length().bytes()];
    scalable.read_z(state, DESTINATION, &mut bytes).unwrap();
    bytes
}

fn to_signed(source: Format, width: IntegerWidth) -> Operand {
    Operand {
        kind: Kind::ToInteger {
            source,
            destination: IntegerFormat {
                width,
                signed: true,
            },
        },
        source: SOURCE,
        destination: DESTINATION,
        governing: GOVERNING,
    }
}

#[test]
fn aliased_signed_narrowing_extends_slots_and_preserves_inactive_input() {
    let (mut state, mut scalable) = setup(32);
    let mut source = [0; 32];
    for (slot, value) in source
        .as_chunks_mut::<{ size_of::<u64>() }>()
        .0
        .iter_mut()
        .zip([
            DOUBLE_NEGATIVE_ONE_AND_HALF,
            DOUBLE_ONE_AND_HALF,
            DOUBLE_NEGATIVE_ONE_AND_HALF,
            DOUBLE_ONE_AND_HALF,
        ])
    {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    scalable.write_z(&mut state, DESTINATION, &source).unwrap();
    predicate(&mut scalable, &[0, 16, 24]);
    let mut operand = to_signed(Format::Double, IntegerWidth::Bits32);
    operand.source = DESTINATION;
    let numerical = controls(&state, false);
    complete(&mut state, &mut scalable, &operand, numerical).unwrap();
    let mut expected = source;
    expected[..8].copy_from_slice(&u64::MAX.to_le_bytes());
    expected[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
    expected[24..].copy_from_slice(&1_u64.to_le_bytes());
    assert_eq!(destination(&scalable, &state), expected);
    assert_eq!(state.fpsr, FPSR_QC | INEXACT);
}

#[test]
fn widening_uses_low_single_and_ignores_nan_in_high_source_half() {
    let (mut state, mut scalable) = setup(16);
    let mut source = [0; 16];
    for (slot, value) in source
        .as_chunks_mut::<{ size_of::<u64>() }>()
        .0
        .iter_mut()
        .zip([SINGLE_ONE_AND_HALF, SINGLE_NEGATIVE_THREE_QUARTERS])
    {
        slot[..4].copy_from_slice(&value.to_le_bytes());
        slot[4..].copy_from_slice(&SINGLE_QUIET_NAN.to_le_bytes());
    }
    scalable.write_z(&mut state, SOURCE, &source).unwrap();
    predicate(&mut scalable, &[0, 8]);
    let operand = to_signed(Format::Single, IntegerWidth::Bits64);
    let numerical = controls(&state, false);
    complete(&mut state, &mut scalable, &operand, numerical).unwrap();
    let expected: Vec<_> = [1_u64, 0].into_iter().flat_map(u64::to_le_bytes).collect();
    assert_eq!(destination(&scalable, &state), expected);
    assert_eq!(state.fpsr, FPSR_QC | INEXACT);
}

#[test]
fn core_saturation_and_nan_status_accumulate_with_other_inexact_lanes() {
    let (mut state, mut scalable) = setup(16);
    let source: Vec<_> = [
        SINGLE_ONE_AND_HALF,
        SINGLE_QUIET_NAN,
        SINGLE_INFINITY,
        SINGLE_INFINITY | (1 << 31),
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect();
    scalable.write_z(&mut state, SOURCE, &source).unwrap();
    predicate(&mut scalable, &[0, 4, 8, 12]);
    let operand = to_signed(Format::Single, IntegerWidth::Bits32);
    let numerical = controls(&state, false);
    complete(&mut state, &mut scalable, &operand, numerical).unwrap();
    let expected: Vec<_> = [1_i32, 0, i32::MAX, i32::MIN]
        .into_iter()
        .flat_map(i32::to_le_bytes)
        .collect();
    assert_eq!(destination(&scalable, &state), expected);
    assert_eq!(state.fpsr, FPSR_QC | INEXACT | INVALID);
}

#[test]
fn signed_x_to_single_rounds_once_and_zero_fills_each_wide_slot() {
    for (rounding, positive, negative) in [
        (0, SINGLE_EXACT_LIMIT_BITS, SINGLE_NEGATIVE_EXACT_LIMIT_BITS),
        (
            1,
            SINGLE_EXACT_LIMIT_BITS + 1,
            SINGLE_NEGATIVE_EXACT_LIMIT_BITS,
        ),
        (
            2,
            SINGLE_EXACT_LIMIT_BITS,
            SINGLE_NEGATIVE_EXACT_LIMIT_BITS + 1,
        ),
        (3, SINGLE_EXACT_LIMIT_BITS, SINGLE_NEGATIVE_EXACT_LIMIT_BITS),
    ] {
        let (mut state, mut scalable) = setup(16);
        let source: Vec<_> = [
            SINGLE_EXACT_INTEGER_LIMIT + 1,
            -SINGLE_EXACT_INTEGER_LIMIT - 1,
        ]
        .into_iter()
        .flat_map(i64::to_le_bytes)
        .collect();
        scalable.write_z(&mut state, DESTINATION, &source).unwrap();
        predicate(&mut scalable, &[0, 8]);
        state.fpcr = rounding << FPCR_ROUNDING_SHIFT;
        let operand = Operand {
            kind: Kind::FromInteger {
                source: IntegerFormat {
                    width: IntegerWidth::Bits64,
                    signed: true,
                },
                destination: Format::Single,
            },
            source: DESTINATION,
            destination: DESTINATION,
            governing: GOVERNING,
        };
        let numerical = controls(&state, false);
        complete(&mut state, &mut scalable, &operand, numerical).unwrap();
        let expected: Vec<_> = [positive, negative]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        assert_eq!(destination(&scalable, &state), expected);
        assert_eq!(state.fpsr, FPSR_QC | INEXACT);
        assert_eq!(state.fpcr, rounding << FPCR_ROUNDING_SHIFT);
    }
}

#[test]
fn central_controls_preserve_raw_storage_refuse_active_and_skip_inactive() {
    let (mut state, mut scalable) = setup(16);
    let source: Vec<_> = [SINGLE_ONE_AND_HALF; 4]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    scalable.write_z(&mut state, SOURCE, &source).unwrap();
    predicate(&mut scalable, &[0, 4, 8, 12]);
    state.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
    let operand = to_signed(Format::Single, IntegerWidth::Bits32);
    let before = state.clone();
    let old_destination = destination(&scalable, &state);
    let numerical = controls(&state, true);
    assert!(matches!(
        complete(&mut state, &mut scalable, &operand, numerical),
        Err(CompletionError::UnsupportedControl(_))
    ));
    assert_eq!(state, before);
    assert_eq!(destination(&scalable, &state), old_destination);

    predicate(&mut scalable, &[1, 5, 9, 13]);
    let numerical = controls(&state, true);
    complete(&mut state, &mut scalable, &operand, numerical).unwrap();
    assert_eq!(state, before);
    assert_eq!(destination(&scalable, &state), old_destination);

    predicate(&mut scalable, &[0, 4, 8, 12]);
    let numerical = controls(&state, false);
    complete(&mut state, &mut scalable, &operand, numerical).unwrap();
    assert_eq!(state.fpcr, FPCR_EXCEPTION_ENABLE_MASK);
    assert_eq!(state.fpsr, FPSR_QC | INEXACT);
}

#[test]
fn unallocated_integer_h_sd_and_invalid_predicate_leave_state_unchanged() {
    let (mut state, mut scalable) = setup(16);
    let before = state.clone();
    let old_destination = destination(&scalable, &state);
    let unadmitted = [
        to_signed(Format::Single, IntegerWidth::Bits16),
        Operand {
            kind: Kind::FromInteger {
                source: IntegerFormat {
                    width: IntegerWidth::Bits16,
                    signed: false,
                },
                destination: Format::Double,
            },
            ..to_signed(Format::Single, IntegerWidth::Bits32)
        },
    ];
    for operand in unadmitted {
        let numerical = controls(&state, false);
        assert!(matches!(
            complete(&mut state, &mut scalable, &operand, numerical),
            Err(CompletionError::State(_))
        ));
    }
    let mut invalid = to_signed(Format::Single, IntegerWidth::Bits32);
    invalid.governing = 16;
    let numerical = controls(&state, false);
    assert!(matches!(
        complete(&mut state, &mut scalable, &invalid, numerical),
        Err(CompletionError::State(_))
    ));
    assert_eq!(state, before);
    assert_eq!(destination(&scalable, &state), old_destination);
}

#[test]
fn half_top_source_ignores_low_nan_and_ieee_controls_preserve_raw_fpcr() {
    const HALF_SIGNALING_NAN: u16 = 0x7c01;
    const HALF_ONE: u16 = 0x3c00;
    const SINGLE_ONE: u32 = 0x3f80_0000;
    let (mut state, mut scalable) = setup(16);
    let source: Vec<_> = [HALF_SIGNALING_NAN, HALF_ONE]
        .repeat(4)
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect();
    scalable.write_z(&mut state, DESTINATION, &source).unwrap();
    predicate(&mut scalable, &[0, 4, 8, 12]);
    state.fpcr = FPCR_AHP | stela_compiler::aarch64::floating::FPCR_FZ16;
    let operand = Operand {
        kind: Kind::Precision {
            source: Format::Half,
            destination: Format::Single,
            rounding: PrecisionRounding::Fpcr,
            placement: Placement::UpperSource,
        },
        source: DESTINATION,
        destination: DESTINATION,
        governing: GOVERNING,
    };
    let numerical = controls(&state, false);
    complete(&mut state, &mut scalable, &operand, numerical).unwrap();
    assert_eq!(
        destination(&scalable, &state),
        SINGLE_ONE.to_le_bytes().repeat(4)
    );
    assert_eq!(state.fpsr, FPSR_QC);
    assert_eq!(
        state.fpcr,
        FPCR_AHP | stela_compiler::aarch64::floating::FPCR_FZ16
    );
}

#[test]
fn odd_top_narrowing_jams_only_inexact_lane_and_preserves_low_source_bits() {
    const INEXACT_DOUBLE: u64 = 0x3ff0_0000_0000_0001;
    const EXACT_DOUBLE: u64 = 0x4000_0000_0000_0000;
    const ODD_TOP_RESULT: u64 = 0x3f80_0001_0000_0001;
    let (mut state, mut scalable) = setup(16);
    let source: Vec<_> = [INEXACT_DOUBLE, EXACT_DOUBLE]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    scalable.write_z(&mut state, DESTINATION, &source).unwrap();
    predicate(&mut scalable, &[0, 8]);
    let operand = Operand {
        kind: Kind::Precision {
            source: Format::Double,
            destination: Format::Single,
            rounding: PrecisionRounding::ToOdd,
            placement: Placement::UpperDestination,
        },
        source: DESTINATION,
        destination: DESTINATION,
        governing: GOVERNING,
    };
    let numerical = controls(&state, false);
    complete(&mut state, &mut scalable, &operand, numerical).unwrap();
    let expected: Vec<_> = [ODD_TOP_RESULT, EXACT_DOUBLE]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    assert_eq!(destination(&scalable, &state), expected);
    assert_eq!(state.fpsr, FPSR_QC | INEXACT);
}

#[test]
fn bfloat_ah_top_alias_uses_nearest_even_and_suppresses_retained_enables() {
    use stela_compiler::aarch64::floating::FPCR_AH;
    const EVEN_MIDPOINT: u32 = 0x3f80_8000;
    const ODD_MIDPOINT: u32 = 0x3f81_8000;
    const ODD_ROUNDED_TOP: u32 = 0x3f82_8000;
    let (mut state, mut scalable) = setup(16);
    let source: Vec<_> = [EVEN_MIDPOINT, ODD_MIDPOINT]
        .repeat(2)
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    scalable.write_z(&mut state, DESTINATION, &source).unwrap();
    predicate(&mut scalable, &[0, 4, 8, 12]);
    state.fpcr = FPCR_AH | FPCR_EXCEPTION_ENABLE_MASK | (1 << FPCR_ROUNDING_SHIFT);
    let operand = Operand {
        kind: Kind::Bfloat16 { upper: true },
        source: DESTINATION,
        destination: DESTINATION,
        governing: GOVERNING,
    };
    let numerical = controls(&state, true);
    complete(&mut state, &mut scalable, &operand, numerical).unwrap();
    let expected: Vec<_> = [EVEN_MIDPOINT, ODD_ROUNDED_TOP]
        .repeat(2)
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    assert_eq!(destination(&scalable, &state), expected);
    assert_eq!(state.fpsr, FPSR_QC);
    assert_eq!(
        state.fpcr,
        FPCR_AH | FPCR_EXCEPTION_ENABLE_MASK | (1 << FPCR_ROUNDING_SHIFT)
    );
}
