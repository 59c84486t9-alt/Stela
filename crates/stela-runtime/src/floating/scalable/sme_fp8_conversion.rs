//! Transactional SME2 FP8 conversions over complete aligned vector groups.

use anyhow::anyhow;
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::fp8::{self, ConversionFormat},
        scalable::{MAX_VECTOR_BYTES, VECTOR_REGISTER_COUNT},
        sme::{
            fp_vector::VectorGroup,
            fp8_conversion::{Conversion, ElementFormat, Operand},
        },
    },
};

use super::{CompletionError, NumericalControls};
use crate::scalable::ScalableState;

const MAX_GROUP_COUNT: usize = 4;
const PAIR_COUNT: u8 = 2;
const HALF_BYTES: usize = size_of::<u16>();
type GroupBytes = [[u8; MAX_VECTOR_BYTES]; MAX_GROUP_COUNT];

fn require(condition: bool, message: &'static str) -> Result<(), CompletionError> {
    if condition {
        Ok(())
    } else {
        Err(anyhow!(message).into())
    }
}

fn validate_group(group: VectorGroup) -> Result<(), CompletionError> {
    require(
        matches!(group.count, 1 | 2 | 4)
            && group.first.is_multiple_of(group.count)
            && usize::from(group.first) + usize::from(group.count)
                <= usize::from(VECTOR_REGISTER_COUNT),
        "invalid SME FP8 vector group",
    )
}

fn snapshot_group(
    state: &GuestState,
    scalable: &ScalableState,
    group: VectorGroup,
) -> Result<GroupBytes, CompletionError> {
    validate_group(group)?;
    let length = scalable.vector_length().bytes();
    let mut result = [[0; MAX_VECTOR_BYTES]; MAX_GROUP_COUNT];
    for (index, output) in result.iter_mut().take(usize::from(group.count)).enumerate() {
        scalable.read_z(state, group.first + index as u8, &mut output[..length])?;
    }
    Ok(result)
}

fn conversion_format(format: ElementFormat) -> ConversionFormat {
    match format {
        ElementFormat::Half => ConversionFormat::Half,
        ElementFormat::BFloat16 => ConversionFormat::BFloat16,
        ElementFormat::Single => ConversionFormat::Single,
    }
}

/// Admission has established SME2, FP8 and FPMR access. Snapshot every source
/// before any destination write. Stage numerical status and full results so
/// unsupported controls leave all state untouched, including aliased V values.
pub(super) fn complete(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    controls: NumericalControls,
) -> Result<(), CompletionError> {
    require(
        scalable.mode().streaming(),
        "SME FP8 conversion requires streaming state",
    )?;
    let source = operand.source;
    let destination = operand.destination;
    match operand.conversion {
        Conversion::Widen { .. } => require(
            source.count == 1
                && destination.count == PAIR_COUNT
                && operand.format != ElementFormat::Single,
            "invalid SME FP8 widening shape",
        )?,
        Conversion::Narrow { interleaved } => require(
            usize::from(source.count) == operand.format.bytes()
                && destination.count == 1
                && (!interleaved || operand.format == ElementFormat::Single),
            "invalid SME FP8 narrowing shape",
        )?,
    }
    validate_group(destination)?;
    let sources = snapshot_group(state, scalable, source)?;
    let mut results = [[0; MAX_VECTOR_BYTES]; MAX_GROUP_COUNT];
    let length = scalable.vector_length().bytes();
    let format = conversion_format(operand.format);
    let fpmr = scalable.fpmr();
    let mut exceptions = 0;
    match operand.conversion {
        Conversion::Widen {
            source2,
            deinterleaved,
        } => {
            let output_lanes = length / HALF_BYTES;
            for (lane, &bits) in sources[0][..length].iter().enumerate() {
                let outcome = fp8::from_fp8(format, source2, controls.fpcr, fpmr, bits)?;
                let (register, output_lane) = if deinterleaved {
                    (
                        lane % usize::from(PAIR_COUNT),
                        lane / usize::from(PAIR_COUNT),
                    )
                } else {
                    (lane / output_lanes, lane % output_lanes)
                };
                let offset = output_lane * HALF_BYTES;
                results[register][offset..offset + HALF_BYTES]
                    .copy_from_slice(&(outcome.bits as u16).to_le_bytes());
                exceptions |= outcome.exceptions;
            }
        }
        Conversion::Narrow { interleaved } => {
            let bytes = operand.format.bytes();
            let lanes = length / bytes;
            for (register, input) in sources.iter().take(usize::from(source.count)).enumerate() {
                for lane in 0..lanes {
                    let offset = lane * bytes;
                    let mut bits = [0; size_of::<u64>()];
                    bits[..bytes].copy_from_slice(&input[offset..offset + bytes]);
                    let outcome =
                        fp8::to_fp8(format, controls.fpcr, fpmr, u64::from_le_bytes(bits))?;
                    let output_lane = if interleaved {
                        lane * usize::from(source.count) + register
                    } else {
                        register * lanes + lane
                    };
                    results[0][output_lane] = outcome.bits as u8;
                    exceptions |= outcome.exceptions;
                }
            }
        }
    }
    // Source snapshots checked the shared streaming backing and vector length;
    // destination bounds were validated before evaluation. Writes cannot allocate
    // or introduce numerical failure after the first register commit.
    for (index, result) in results
        .iter()
        .take(usize::from(destination.count))
        .enumerate()
    {
        scalable.write_z(state, destination.first + index as u8, &result[..length])?;
    }
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::aarch64::{
        floating::{FPCR_EXCEPTION_ENABLE_MASK, FPSR_QC, features::NumericalFeatures},
        scalable::{ScalableMode, VectorLength},
        sme::fp8_conversion::{self, F1CVT_MZ2_Z8, F1CVTL_MZ2_Z8, FCVT_Z8_MZ4, FCVTN_Z8_MZ4},
    };

    fn setup(length: usize) -> (GuestState, ScalableState) {
        let mut state = GuestState::default();
        let mut scalable = ScalableState::new(VectorLength::from_bytes(length).unwrap(), true);
        scalable
            .apply_mode(&mut state, ScalableMode::new(true, true))
            .unwrap();
        state.fpsr = FPSR_QC;
        (state, scalable)
    }

    fn read(state: &GuestState, scalable: &ScalableState, register: u8) -> Vec<u8> {
        let mut output = vec![0; scalable.vector_length().bytes()];
        scalable.read_z(state, register, &mut output).unwrap();
        output
    }

    fn controls(fpcr: u32, full_a64: bool) -> NumericalControls {
        NumericalControls::new(fpcr, true, NumericalFeatures::new(full_a64, false, false))
    }

    #[test]
    fn widening_aliases_snapshot_inputs_for_both_group_orders_at_all_lengths() {
        for length in [16, 32, 64, 128, 256] {
            for word in [F1CVT_MZ2_Z8, F1CVTL_MZ2_Z8] {
                let (mut state, mut scalable) = setup(length);
                let input: Vec<u8> = (0..length).map(|lane| lane as u8).collect();
                scalable.write_z(&mut state, 31, &input).unwrap();
                let operand = fp8_conversion::decode(word | 31 << 5 | 30).unwrap();
                complete(&mut state, &mut scalable, &operand, controls(0, false)).unwrap();
                let results = [read(&state, &scalable, 30), read(&state, &scalable, 31)];
                let mut status = FPSR_QC;
                for (lane, value) in input.iter().enumerate() {
                    let outcome =
                        fp8::from_fp8(ConversionFormat::Half, false, 0, 0, *value).unwrap();
                    let (register, index) = if word == F1CVTL_MZ2_Z8 {
                        (lane % 2, lane / 2)
                    } else {
                        (lane / (length / 2), lane % (length / 2))
                    };
                    assert_eq!(
                        &results[register][index * 2..index * 2 + 2],
                        &(outcome.bits as u16).to_le_bytes()
                    );
                    status |= outcome.exceptions;
                }
                assert_eq!(state.fpsr, status);
            }
        }
    }

    #[test]
    fn narrowing_quartet_alias_and_interleave_preserve_original_four_sources() {
        for word in [FCVT_Z8_MZ4, FCVTN_Z8_MZ4] {
            let (mut state, mut scalable) = setup(16);
            let inputs = [0x3f80_0000u32, 0x4000_0000, 0x4040_0000, 0x4080_0000];
            for (index, input) in inputs.iter().enumerate() {
                scalable
                    .write_z(&mut state, 28 + index as u8, &input.to_le_bytes().repeat(4))
                    .unwrap();
            }
            let operand = fp8_conversion::decode(word | 28 << 5 | 31).unwrap();
            complete(&mut state, &mut scalable, &operand, controls(0, false)).unwrap();
            let output = read(&state, &scalable, 31);
            for (register, input) in inputs.iter().enumerate() {
                let expected =
                    fp8::to_fp8(ConversionFormat::Single, 0, 0, u64::from(*input)).unwrap();
                for lane in 0..4 {
                    let index = if word == FCVTN_Z8_MZ4 {
                        lane * 4 + register
                    } else {
                        register * 4 + lane
                    };
                    assert_eq!(output[index], expected.bits as u8);
                }
                if register < 3 {
                    assert_eq!(
                        read(&state, &scalable, 28 + register as u8),
                        input.to_le_bytes().repeat(4)
                    );
                }
            }
            assert_eq!(state.fpsr, FPSR_QC);
        }
    }

    #[test]
    fn unsupported_controls_mode_and_forged_groups_have_no_effects() {
        let (mut state, mut scalable) = setup(16);
        state.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
        scalable.set_fpmr(u64::MAX);
        let operand = fp8_conversion::decode(F1CVT_MZ2_Z8).unwrap();
        let before = state.clone();
        let z_before: Vec<_> = (0..32).map(|r| read(&state, &scalable, r)).collect();
        let unsupported = controls(state.fpcr, true);
        assert!(complete(&mut state, &mut scalable, &operand, unsupported).is_err());
        assert_eq!(state, before);
        assert_eq!(scalable.fpmr(), u64::MAX);
        assert_eq!(
            (0..32)
                .map(|r| read(&state, &scalable, r))
                .collect::<Vec<_>>(),
            z_before
        );
        let mut forged = operand;
        forged.destination.first = 31;
        assert!(complete(&mut state, &mut scalable, &forged, controls(0, false)).is_err());
        scalable
            .apply_mode(&mut state, ScalableMode::new(false, true))
            .unwrap();
        let before = state.clone();
        assert!(complete(&mut state, &mut scalable, &operand, controls(0, false)).is_err());
        assert_eq!(state, before);
    }
}
