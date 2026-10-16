use super::*;
use stela_compiler::aarch64::{
    floating::{
        FPCR_AH, FPCR_DN, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FIZ, FPCR_FZ, FPCR_FZ16, Format,
        INEXACT, INVALID, OVERFLOW, absolute_minmax::AbsoluteMinMaxOperation,
        features::NumericalFeatures,
    },
    scalable::{ScalableMode, VectorLength},
    sme::extrema_scale::Group,
};

const QC: u32 = 1 << 27;

fn fraction_bits(format: Format) -> u32 {
    match format {
        Format::Half => 10,
        Format::Single => 23,
        Format::Double => 52,
    }
}
fn sign(format: Format) -> u64 {
    1 << (format.bits() - 1)
}
fn infinity(format: Format) -> u64 {
    match format {
        Format::Half => 0x7c00,
        Format::Single => 0x7f80_0000,
        Format::Double => 0x7ff0_0000_0000_0000,
    }
}
fn one(format: Format) -> u64 {
    match format {
        Format::Half => 0x3c00,
        Format::Single => 0x3f80_0000,
        Format::Double => 0x3ff0_0000_0000_0000,
    }
}
fn quiet_bit(format: Format) -> u64 {
    1 << (fraction_bits(format) - 1)
}

fn setup(length: usize) -> (GuestState, ScalableState) {
    let mut state = GuestState::default();
    let mut scalable = ScalableState::new(VectorLength::from_bytes(length).unwrap(), true);
    scalable
        .apply_mode(&mut state, ScalableMode::new(true, true))
        .unwrap();
    scalable.set_fpmr(0x1234);
    state.nzcv = 0xa000_0000;
    state.fpsr = QC;
    (state, scalable)
}

fn fill(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    register: u8,
    format: Format,
    bits: u64,
) {
    let bytes = format.bits() as usize / BITS_PER_BYTE;
    let values = bits.to_le_bytes()[..bytes].repeat(scalable.vector_length().bytes() / bytes);
    scalable.write_z(state, register, &values).unwrap();
}

fn assert_filled(
    state: &GuestState,
    scalable: &ScalableState,
    register: u8,
    format: Format,
    bits: u64,
) {
    let mut values = vec![0; scalable.vector_length().bytes()];
    scalable.read_z(state, register, &mut values).unwrap();
    let bytes = format.bits() as usize / BITS_PER_BYTE;
    assert!(
        values
            .chunks_exact(bytes)
            .all(|value| value == &bits.to_le_bytes()[..bytes])
    );
}

#[test]
fn scale_broadcast_alias_reads_original_register_at_every_length_and_width() {
    for length in [16, 32, 64, 128, 256] {
        for format in [Format::Half, Format::Single, Format::Double] {
            for group in [Group::Pair, Group::Quartet] {
                let (mut state, mut scalable) = setup(length);
                let one = one(format);
                for register in 0..group.count() {
                    fill(&mut state, &mut scalable, register, format, one);
                }
                // First destination aliases the broadcast, so premature commit
                // would change subsequent scale factors from integer 1.
                fill(&mut state, &mut scalable, 0, format, 1);
                let operand = Operand {
                    kind: Kind::Scale,
                    destination: 0,
                    right: 0,
                    group,
                    format,
                    right_grouped: false,
                };
                complete(
                    &mut state,
                    &mut scalable,
                    &operand,
                    NumericalControls::new(0, true, NumericalFeatures::default()),
                )
                .unwrap();
                assert_filled(&state, &scalable, 0, format, 2);
                for register in 1..group.count() {
                    assert_filled(
                        &state,
                        &scalable,
                        register,
                        format,
                        one + (1 << fraction_bits(format)),
                    );
                }
                assert_eq!(state.fpsr, QC);
                assert_eq!(state.nzcv, 0xa000_0000);
                assert_eq!(scalable.fpmr(), 0x1234);
            }
        }
    }
}

#[test]
fn extrema_group_alias_and_specials_ignore_flush_and_keep_sticky_status() {
    for format in [Format::Half, Format::Single, Format::Double] {
        for operation in [
            AbsoluteMinMaxOperation::Minimum,
            AbsoluteMinMaxOperation::Maximum,
        ] {
            let (mut state, mut scalable) = setup(64);
            state.fpcr = FPCR_AH | FPCR_FIZ | FPCR_FZ | FPCR_FZ16;
            for register in 28..32 {
                fill(
                    &mut state,
                    &mut scalable,
                    register,
                    format,
                    sign(format) | 1,
                );
            }
            let operand = Operand {
                kind: Kind::AbsoluteMinMax(operation),
                destination: 28,
                right: 28,
                group: Group::Quartet,
                format,
                right_grouped: true,
            };
            let controls = NumericalControls::new(state.fpcr, true, NumericalFeatures::default());
            complete(&mut state, &mut scalable, &operand, controls).unwrap();
            for register in 28..32 {
                assert_filled(&state, &scalable, register, format, 1);
            }
            assert_eq!(state.fpsr, QC);
            let signaling = sign(format) | infinity(format) | 1;
            fill(&mut state, &mut scalable, 31, format, signaling);
            state.fpcr |= FPCR_DN;
            let controls = NumericalControls::new(state.fpcr, true, NumericalFeatures::default());
            complete(&mut state, &mut scalable, &operand, controls).unwrap();
            assert_filled(
                &state,
                &scalable,
                31,
                format,
                infinity(format) | quiet_bit(format),
            );
            assert_eq!(state.fpsr, QC | INVALID);
        }
    }
}

#[test]
fn scale_group_signed_factors_accumulate_rounding_status() {
    let (mut state, mut scalable) = setup(32);
    for register in 0..2 {
        fill(
            &mut state,
            &mut scalable,
            register,
            Format::Single,
            0x7f7f_ffff,
        );
    }
    fill(&mut state, &mut scalable, 30, Format::Single, 1);
    fill(
        &mut state,
        &mut scalable,
        31,
        Format::Single,
        u64::from(u32::MAX),
    );
    let operand = Operand {
        kind: Kind::Scale,
        destination: 0,
        right: 30,
        group: Group::Pair,
        format: Format::Single,
        right_grouped: true,
    };
    complete(
        &mut state,
        &mut scalable,
        &operand,
        NumericalControls::new(0, true, NumericalFeatures::default()),
    )
    .unwrap();
    assert_filled(&state, &scalable, 0, Format::Single, 0x7f80_0000);
    assert_filled(&state, &scalable, 1, Format::Single, 0x7eff_ffff);
    assert_eq!(state.fpsr, QC | OVERFLOW | INEXACT);
}

#[test]
fn failures_are_transactional_and_streaming_exception_enables_are_effective() {
    let (mut state, mut scalable) = setup(16);
    fill(&mut state, &mut scalable, 0, Format::Single, 0xbf80_0000);
    fill(&mut state, &mut scalable, 1, Format::Single, 0xff80_0001);
    let operand = Operand {
        kind: Kind::AbsoluteMinMax(AbsoluteMinMaxOperation::Maximum),
        destination: 0,
        right: 0,
        group: Group::Pair,
        format: Format::Single,
        right_grouped: true,
    };
    state.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
    let before = state.clone();
    let controls =
        NumericalControls::new(state.fpcr, true, NumericalFeatures::new(true, false, false));
    assert!(matches!(
        complete(&mut state, &mut scalable, &operand, controls),
        Err(CompletionError::UnsupportedControl(_))
    ));
    assert_eq!(state, before);
    let controls = NumericalControls::new(state.fpcr, true, NumericalFeatures::default());
    complete(&mut state, &mut scalable, &operand, controls).unwrap();
    assert_eq!(state.fpcr, FPCR_EXCEPTION_ENABLE_MASK);
    assert_eq!(state.fpsr, QC | INVALID);
    let bad = Operand {
        destination: 31,
        ..operand
    };
    let before = state.clone();
    assert!(complete(&mut state, &mut scalable, &bad, controls).is_err());
    assert_eq!(state, before);
    scalable
        .apply_mode(&mut state, ScalableMode::new(false, true))
        .unwrap();
    assert!(complete(&mut state, &mut scalable, &operand, controls).is_err());
}
