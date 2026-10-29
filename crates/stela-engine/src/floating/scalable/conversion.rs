//! Completion of the SVE predicated conversions.

use anyhow::anyhow;
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{
            FPCR_AHP, Format, Outcome, bfloat16,
            integer::{self, IntegerRounding, IntegerWidth},
            precision::{self, PrecisionRounding},
        },
        scalable::{BITS_PER_BYTE, MAX_VECTOR_BYTES},
        sve::floating::conversion::{Kind, Operand, Placement},
    },
};

use super::{CompletionError, NumericalControls};
use crate::scalable::ScalableState;

const MAX_PREDICATE_BYTES: usize = MAX_VECTOR_BYTES / BITS_PER_BYTE;

fn require(condition: bool, message: &'static str) -> Result<(), CompletionError> {
    if condition {
        Ok(())
    } else {
        Err(anyhow!(message).into())
    }
}

fn active(predicate: &[u8], byte: usize) -> bool {
    predicate[byte / BITS_PER_BYTE] & (1 << (byte % BITS_PER_BYTE)) != 0
}

/// The twenty-eight integer conversion shapes: an H integer pairs only with
/// half precision, W and X with half, single and double.
fn admitted_integer(kind: Kind) -> bool {
    match kind {
        Kind::FromInteger {
            source: integer,
            destination: float,
        }
        | Kind::ToInteger {
            source: float,
            destination: integer,
        } => match float {
            Format::Half => matches!(
                integer.width,
                IntegerWidth::Bits16 | IntegerWidth::Bits32 | IntegerWidth::Bits64
            ),
            Format::Single | Format::Double => {
                matches!(integer.width, IntegerWidth::Bits32 | IntegerWidth::Bits64)
            }
        },
        _ => false,
    }
}

/// Exact precision allocations; manually constructed unallocated shapes fail
/// before state reads or numerical work, including all-inactive instructions.
fn admitted_precision(kind: Kind) -> bool {
    let Kind::Precision {
        source,
        destination,
        rounding,
        placement,
    } = kind
    else {
        return false;
    };
    matches!(
        (source, destination, rounding, placement),
        (
            Format::Half,
            Format::Single | Format::Double,
            PrecisionRounding::Fpcr,
            Placement::Low
        ) | (
            Format::Single,
            Format::Half | Format::Double,
            PrecisionRounding::Fpcr,
            Placement::Low
        ) | (
            Format::Double,
            Format::Half | Format::Single,
            PrecisionRounding::Fpcr,
            Placement::Low
        ) | (
            Format::Half,
            Format::Single,
            PrecisionRounding::Fpcr,
            Placement::UpperSource
        ) | (
            Format::Single,
            Format::Double,
            PrecisionRounding::Fpcr,
            Placement::UpperSource
        ) | (
            Format::Single,
            Format::Half,
            PrecisionRounding::Fpcr,
            Placement::UpperDestination
        ) | (
            Format::Double,
            Format::Single,
            PrecisionRounding::Fpcr | PrecisionRounding::ToOdd,
            Placement::UpperDestination
        ) | (
            Format::Double,
            Format::Single,
            PrecisionRounding::ToOdd,
            Placement::Low
        )
    )
}

/// Only called after the instruction-wide shape guard. Controls are already
/// profile-effective; the mature integer core owns its IEEE/AHP adapter.
fn integer_lane(kind: Kind, fpcr: u32, bits: u64) -> Result<Outcome, CompletionError> {
    let mut outcome = match kind {
        Kind::FromInteger {
            source,
            destination,
        } => integer::from_integer(source, destination, 0, fpcr, bits)?,
        Kind::ToInteger {
            source,
            destination,
        } => integer::to_integer(
            source,
            destination,
            0,
            IntegerRounding::TowardZero,
            fpcr,
            bits,
        )?,
        _ => return Err(anyhow!("expected admitted integer conversion").into()),
    };
    if let Kind::ToInteger { destination, .. } = kind
        && destination.signed
    {
        // FPToFixed narrows to the integer width first, then the result is
        // sign-extended across the full SVE element.
        let shift = u64::BITS - destination.width.bits();
        outcome.bits = (((outcome.bits << shift) as i64) >> shift) as u64;
    }
    Ok(outcome)
}

/// Sources, old destination and governing predicate are captured before any
/// numerical evaluation. Status and the complete Z destination commit together.
/// Raw FPCR remains unchanged when ordinary streaming masks retained enables.
pub(super) fn complete(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    controls: NumericalControls,
) -> Result<(), CompletionError> {
    require(
        scalable.mode().streaming(),
        "scalable conversion requires streaming state",
    )?;
    let kind = operand.kind;
    require(
        admitted_integer(kind) || admitted_precision(kind) || matches!(kind, Kind::Bfloat16 { .. }),
        "unadmitted scalable conversion",
    )?;
    let slot_bytes = usize::from(kind.slot_bytes());
    let source_bytes = kind.source_bits() as usize / BITS_PER_BYTE;
    let source_offset = usize::from(kind.source_offset());
    let destination_offset = usize::from(kind.destination_offset());
    let written_bytes = usize::from(kind.written_bytes());
    require(
        source_offset + source_bytes <= slot_bytes
            && destination_offset + written_bytes <= slot_bytes,
        "scalable conversion placement exceeds its slot",
    )?;
    let length = scalable.vector_length().bytes();
    let predicate_bytes = scalable.vector_length().predicate_bytes();
    let mut source = [0; MAX_VECTOR_BYTES];
    let mut result = [0; MAX_VECTOR_BYTES];
    let mut predicate = [0; MAX_PREDICATE_BYTES];
    scalable.read_z(state, operand.source, &mut source[..length])?;
    scalable.read_z(state, operand.destination, &mut result[..length])?;
    scalable.read_predicate(operand.governing, &mut predicate[..predicate_bytes])?;

    let mut exceptions = 0;
    for slot in (0..length).step_by(slot_bytes) {
        if !active(&predicate, slot) {
            continue;
        }
        let start = slot + source_offset;
        let mut bits = [0; size_of::<u64>()];
        bits[..source_bytes].copy_from_slice(&source[start..start + source_bytes]);
        let outcome = match kind {
            Kind::Precision {
                source,
                destination,
                rounding,
                ..
            } => precision::evaluate(
                source,
                destination,
                rounding,
                controls.fpcr & !FPCR_AHP,
                u64::from_le_bytes(bits),
            )?,
            Kind::Bfloat16 { .. } => {
                bfloat16::convert(controls.fpcr, u64::from_le_bytes(bits) as u32)?
            }
            Kind::ToInteger { .. } | Kind::FromInteger { .. } => {
                integer_lane(kind, controls.fpcr, u64::from_le_bytes(bits))?
            }
        };
        exceptions |= outcome.exceptions;
        let start = slot + destination_offset;
        result[start..start + written_bytes]
            .copy_from_slice(&outcome.bits.to_le_bytes()[..written_bytes]);
    }
    scalable.write_z(state, operand.destination, &result[..length])?;
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests {
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
}
