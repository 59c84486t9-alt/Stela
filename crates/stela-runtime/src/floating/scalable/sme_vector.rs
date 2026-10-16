//! Transactional SME2 floating-point completion for aligned Z-register groups.

use anyhow::anyhow;
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{
            FPCR_AHP, Format, Outcome, UnsupportedControl, bfloat16,
            integer::{self, IntegerFormat, IntegerRounding, IntegerWidth},
            minmax::{self, MinMaxOperation},
            precision::{self, PrecisionRounding},
            rounding,
        },
        scalable::{BITS_PER_BYTE, MAX_VECTOR_BYTES, VECTOR_REGISTER_COUNT},
        sme::fp_vector::{Conversion, ElementFormat, Kind, Operand, VectorGroup},
    },
};

use super::{CompletionError, NumericalControls};
use crate::scalable::ScalableState;

const MAX_GROUP_COUNT: usize = 4;
const PAIR_COUNT: u8 = 2;
const QUARTET_COUNT: u8 = 4;
const HALF_BYTES: usize = size_of::<u16>();
const SINGLE_BYTES: usize = size_of::<u32>();
const NO_FRACTION_BITS: u8 = 0;
type GroupBytes = [[u8; MAX_VECTOR_BYTES]; MAX_GROUP_COUNT];

fn require(condition: bool, message: &'static str) -> Result<(), CompletionError> {
    if condition {
        Ok(())
    } else {
        Err(anyhow!(message).into())
    }
}

fn snapshot_group(
    state: &GuestState,
    scalable: &ScalableState,
    group: VectorGroup,
) -> Result<GroupBytes, CompletionError> {
    require(
        matches!(group.count, 1 | PAIR_COUNT | QUARTET_COUNT)
            && group.first.is_multiple_of(group.count)
            && usize::from(group.first) + usize::from(group.count)
                <= usize::from(VECTOR_REGISTER_COUNT),
        "invalid scalable vector group",
    )?;
    let length = scalable.vector_length().bytes();
    let mut result = [[0; MAX_VECTOR_BYTES]; MAX_GROUP_COUNT];
    for (index, output) in result.iter_mut().take(usize::from(group.count)).enumerate() {
        scalable.read_z(state, group.first + index as u8, &mut output[..length])?;
    }
    Ok(result)
}

fn read_lane(source: &[u8], offset: usize, bytes: usize) -> u64 {
    let mut bits = [0; size_of::<u64>()];
    bits[..bytes].copy_from_slice(&source[offset..offset + bytes]);
    u64::from_le_bytes(bits)
}

fn write_lane(destination: &mut [u8], offset: usize, bytes: usize, bits: u64) {
    destination[offset..offset + bytes].copy_from_slice(&bits.to_le_bytes()[..bytes]);
}

fn format_bytes(format: ElementFormat) -> usize {
    match format {
        ElementFormat::Ieee(format) => format.bits() as usize / BITS_PER_BYTE,
        ElementFormat::BFloat => HALF_BYTES,
    }
}

/// A BF min/max selects an already representable BF value. Widening is exact,
/// and the shared Single kernel owns NaNs, signed zero, flush and status rules.
/// Its result remains exactly representable as BF, including quiet/default NaNs.
fn minmax_lane(
    format: ElementFormat,
    operation: MinMaxOperation,
    fpcr: u32,
    left: u64,
    right: u64,
) -> Result<Outcome, UnsupportedControl> {
    match format {
        ElementFormat::Ieee(format) => minmax::evaluate(format, operation, fpcr, left, right),
        ElementFormat::BFloat => {
            let mut outcome = minmax::evaluate(
                Format::Single,
                operation,
                fpcr,
                u64::from(bfloat16::widen(left as u16)),
                u64::from(bfloat16::widen(right as u16)),
            )?;
            outcome.bits >>= bfloat16::BFLOAT16_TO_SINGLE_SHIFT;
            Ok(outcome)
        }
    }
}

fn convert_lane(
    operation: Conversion,
    fpcr: u32,
    conversion_control: u32,
    bits: u64,
) -> Result<Outcome, UnsupportedControl> {
    match operation {
        Conversion::Narrow { bfloat: true, .. } => bfloat16::convert(fpcr, bits as u32),
        Conversion::Narrow { bfloat: false, .. } => precision::evaluate(
            Format::Single,
            Format::Half,
            PrecisionRounding::Fpcr,
            conversion_control,
            bits,
        ),
        Conversion::Widen { .. } => precision::evaluate(
            Format::Half,
            Format::Single,
            PrecisionRounding::Fpcr,
            conversion_control,
            bits,
        ),
        Conversion::ToInteger { unsigned } => integer::to_integer(
            Format::Single,
            IntegerFormat {
                width: IntegerWidth::Bits32,
                signed: !unsigned,
            },
            NO_FRACTION_BITS,
            IntegerRounding::TowardZero,
            fpcr,
            bits,
        ),
        Conversion::FromInteger { unsigned } => integer::from_integer(
            IntegerFormat {
                width: IntegerWidth::Bits32,
                signed: !unsigned,
            },
            Format::Single,
            NO_FRACTION_BITS,
            fpcr,
            bits,
        ),
        Conversion::Round(operation) => rounding::evaluate(Format::Single, operation, fpcr, bits),
    }
}

/// Stage every affected destination and cumulative status before committing any
/// register. Group aliases always read original inputs. Raw FPCR, GPR, P, ZA and
/// ZT state are untouched, including when a numerical control is unsupported.
pub(super) fn complete(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    controls: NumericalControls,
) -> Result<(), CompletionError> {
    require(
        scalable.mode().streaming(),
        "SME FP vectors require streaming state",
    )?;
    let length = scalable.vector_length().bytes();
    let destination = operand.destination;
    let mut result = snapshot_group(state, scalable, destination)?;
    let fpcr = controls.fpcr;
    let conversion_control = fpcr & !FPCR_AHP;
    let mut exceptions = 0;
    match operand.kind {
        Kind::MinMax { operation, right } => {
            require(
                matches!(destination.count, PAIR_COUNT | QUARTET_COUNT)
                    && (right.count == 1 || right.count == destination.count),
                "invalid SME min/max groups",
            )?;
            let right_values = snapshot_group(state, scalable, right)?;
            let bytes = format_bytes(operand.format);
            for (index, output) in result
                .iter_mut()
                .take(usize::from(destination.count))
                .enumerate()
            {
                let right = &right_values[if right.count == 1 { 0 } else { index }];
                for offset in (0..length).step_by(bytes) {
                    let outcome = minmax_lane(
                        operand.format,
                        operation,
                        fpcr,
                        read_lane(output, offset, bytes),
                        read_lane(right, offset, bytes),
                    )?;
                    write_lane(output, offset, bytes, outcome.bits);
                    exceptions |= outcome.exceptions;
                }
            }
        }
        Kind::Clamp { lower, upper } => {
            require(
                matches!(destination.count, PAIR_COUNT | QUARTET_COUNT),
                "invalid SME clamp group",
            )?;
            let mut lower_values = [0; MAX_VECTOR_BYTES];
            let mut upper_values = [0; MAX_VECTOR_BYTES];
            scalable.read_z(state, lower, &mut lower_values[..length])?;
            scalable.read_z(state, upper, &mut upper_values[..length])?;
            let bytes = format_bytes(operand.format);
            for output in result.iter_mut().take(usize::from(destination.count)) {
                for offset in (0..length).step_by(bytes) {
                    let maximum = minmax_lane(
                        operand.format,
                        MinMaxOperation::MaximumNumber,
                        fpcr,
                        read_lane(&lower_values, offset, bytes),
                        read_lane(output, offset, bytes),
                    )?;
                    let minimum = minmax_lane(
                        operand.format,
                        MinMaxOperation::MinimumNumber,
                        fpcr,
                        maximum.bits,
                        read_lane(&upper_values, offset, bytes),
                    )?;
                    write_lane(output, offset, bytes, minimum.bits);
                    exceptions |= maximum.exceptions | minimum.exceptions;
                }
            }
        }
        Kind::Convert { operation, source } => {
            let sources = snapshot_group(state, scalable, source)?;
            match operation {
                Conversion::Narrow { interleaved, .. } => {
                    require(
                        source.count == PAIR_COUNT && destination.count == 1,
                        "invalid SME narrowing groups",
                    )?;
                    for (register, input) in
                        sources.iter().take(usize::from(PAIR_COUNT)).enumerate()
                    {
                        for lane in 0..length / SINGLE_BYTES {
                            let outcome = convert_lane(
                                operation,
                                fpcr,
                                conversion_control,
                                read_lane(input, lane * SINGLE_BYTES, SINGLE_BYTES),
                            )?;
                            let output_lane = if interleaved {
                                lane * usize::from(PAIR_COUNT) + register
                            } else {
                                register * (length / SINGLE_BYTES) + lane
                            };
                            write_lane(
                                &mut result[0],
                                output_lane * HALF_BYTES,
                                HALF_BYTES,
                                outcome.bits,
                            );
                            exceptions |= outcome.exceptions;
                        }
                    }
                }
                Conversion::Widen { deinterleaved } => {
                    require(
                        source.count == 1 && destination.count == PAIR_COUNT,
                        "invalid SME widening groups",
                    )?;
                    let output_lanes = length / SINGLE_BYTES;
                    for lane in 0..length / HALF_BYTES {
                        let outcome = convert_lane(
                            operation,
                            fpcr,
                            conversion_control,
                            read_lane(&sources[0], lane * HALF_BYTES, HALF_BYTES),
                        )?;
                        let (register, output_lane) = if deinterleaved {
                            (
                                lane % usize::from(PAIR_COUNT),
                                lane / usize::from(PAIR_COUNT),
                            )
                        } else {
                            (lane / output_lanes, lane % output_lanes)
                        };
                        write_lane(
                            &mut result[register],
                            output_lane * SINGLE_BYTES,
                            SINGLE_BYTES,
                            outcome.bits,
                        );
                        exceptions |= outcome.exceptions;
                    }
                }
                _ => {
                    require(
                        source.count == destination.count
                            && matches!(source.count, PAIR_COUNT | QUARTET_COUNT),
                        "invalid SME conversion groups",
                    )?;
                    for (input, output) in sources
                        .iter()
                        .zip(&mut result)
                        .take(usize::from(source.count))
                    {
                        for offset in (0..length).step_by(SINGLE_BYTES) {
                            let outcome = convert_lane(
                                operation,
                                fpcr,
                                conversion_control,
                                read_lane(input, offset, SINGLE_BYTES),
                            )?;
                            write_lane(output, offset, SINGLE_BYTES, outcome.bits);
                            exceptions |= outcome.exceptions;
                        }
                    }
                }
            }
        }
    }
    // Successful snapshots validated every eventual write's mode/index/length;
    // write_z performs no allocation or further numerical operation.
    for (index, output) in result
        .iter()
        .take(usize::from(destination.count))
        .enumerate()
    {
        scalable.write_z(state, destination.first + index as u8, &output[..length])?;
    }
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::aarch64::{
        floating::{
            FPCR_EXCEPTION_ENABLE_MASK, FPSR_QC, INVALID, OVERFLOW, features::NumericalFeatures,
        },
        scalable::{ScalableMode, VectorLength},
        sme::fp_vector,
    };

    const TEST_SVL_BYTES: usize = 16;
    const SINGLE_ONE: u32 = 0x3f80_0000;
    const SINGLE_ONE_AND_HALF: u32 = 0x3fc0_0000;
    const SINGLE_TWO: u32 = 0x4000_0000;
    const SIGNALING_FIVE: u32 = 0x7f80_0005;
    const QUIET_FIVE: u32 = 0x7fc0_0005;
    const QUIET_SEVEN: u32 = 0x7fc0_0007;
    const SIGNALING_NINE: u32 = 0x7f80_0009;
    const QUIET_NINE: u32 = 0x7fc0_0009;
    const FMAX_SINGLE_QUARTET: u32 = 0xc1a0_a900;
    const FRINTN_PAIR: u32 = 0xc1a8_e000;
    const FCVTN_PAIR: u32 = 0xc120_e020;
    const FCVT_PAIR: u32 = 0xc120_e000;

    fn setup() -> (GuestState, ScalableState) {
        let mut state = GuestState::default();
        let mut scalable =
            ScalableState::new(VectorLength::from_bytes(TEST_SVL_BYTES).unwrap(), true);
        scalable
            .apply_mode(&mut state, ScalableMode::new(true, true))
            .unwrap();
        state.fpsr = FPSR_QC | OVERFLOW;
        (state, scalable)
    }

    fn write_single(
        state: &mut GuestState,
        scalable: &mut ScalableState,
        register: u8,
        words: &[u32; 4],
    ) {
        let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        scalable.write_z(state, register, &bytes).unwrap();
    }

    fn read_vector(
        state: &GuestState,
        scalable: &ScalableState,
        register: u8,
    ) -> [u8; TEST_SVL_BYTES] {
        let mut bytes = [0; TEST_SVL_BYTES];
        scalable.read_z(state, register, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn broadcast_alias_keeps_original_signaling_nan_priority_for_entire_group() {
        let (mut state, mut scalable) = setup();
        for (register, value) in [SIGNALING_FIVE, QUIET_SEVEN, SINGLE_ONE, SIGNALING_NINE]
            .into_iter()
            .enumerate()
        {
            write_single(&mut state, &mut scalable, register as u8, &[value; 4]);
        }
        let operand = fp_vector::decode(FMAX_SINGLE_QUARTET).unwrap();
        complete(
            &mut state,
            &mut scalable,
            &operand,
            NumericalControls::new(0, true, NumericalFeatures::default()),
        )
        .unwrap();
        for (register, expected) in [QUIET_FIVE, QUIET_FIVE, QUIET_FIVE, QUIET_NINE]
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                read_vector(&state, &scalable, register as u8).as_slice(),
                expected.to_le_bytes().repeat(4)
            );
        }
        assert_eq!(state.fpsr, FPSR_QC | OVERFLOW | INVALID);
    }

    #[test]
    fn narrowing_alias_uses_distinct_consecutive_and_interleaved_placements() {
        const FIRST: [u32; 4] = [0x3f80_0000, 0x4000_0000, 0x4040_0000, 0x4080_0000];
        const SECOND: [u32; 4] = [0x40a0_0000, 0x40c0_0000, 0x40e0_0000, 0x4100_0000];
        const CONSECUTIVE: [u16; 8] = [
            0x3c00, 0x4000, 0x4200, 0x4400, 0x4500, 0x4600, 0x4700, 0x4800,
        ];
        const INTERLEAVED: [u16; 8] = [
            0x3c00, 0x4500, 0x4000, 0x4600, 0x4200, 0x4700, 0x4400, 0x4800,
        ];
        for (word, expected) in [(FCVT_PAIR, CONSECUTIVE), (FCVTN_PAIR, INTERLEAVED)] {
            let (mut state, mut scalable) = setup();
            write_single(&mut state, &mut scalable, 0, &FIRST);
            write_single(&mut state, &mut scalable, 1, &SECOND);
            let before_source = read_vector(&state, &scalable, 0);
            let operand = fp_vector::decode(word | 1).unwrap();
            complete(
                &mut state,
                &mut scalable,
                &operand,
                NumericalControls::new(0, true, NumericalFeatures::default()),
            )
            .unwrap();
            let expected: Vec<u8> = expected
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect();
            assert_eq!(read_vector(&state, &scalable, 1).as_slice(), expected);
            assert_eq!(read_vector(&state, &scalable, 0), before_source);
            assert_eq!(state.fpsr, FPSR_QC | OVERFLOW);
        }
    }

    #[test]
    fn streaming_enable_mask_preserves_storage_and_full_a64_refusal_preserves_outputs() {
        let (mut state, mut scalable) = setup();
        state.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
        write_single(&mut state, &mut scalable, 0, &[SINGLE_ONE_AND_HALF; 4]);
        write_single(&mut state, &mut scalable, 1, &[SINGLE_ONE_AND_HALF; 4]);
        let operand = fp_vector::decode(FRINTN_PAIR).unwrap();
        let before = state.clone();
        assert!(
            complete(
                &mut state,
                &mut scalable,
                &operand,
                NumericalControls::new(
                    FPCR_EXCEPTION_ENABLE_MASK,
                    true,
                    NumericalFeatures::new(true, false, false)
                )
            )
            .is_err()
        );
        assert_eq!(state, before);
        complete(
            &mut state,
            &mut scalable,
            &operand,
            NumericalControls::new(
                FPCR_EXCEPTION_ENABLE_MASK,
                true,
                NumericalFeatures::default(),
            ),
        )
        .unwrap();
        assert_eq!(state.fpcr, FPCR_EXCEPTION_ENABLE_MASK);
        assert_eq!(state.fpsr, FPSR_QC | OVERFLOW);
        for register in 0..PAIR_COUNT {
            assert_eq!(
                read_vector(&state, &scalable, register).as_slice(),
                SINGLE_TWO.to_le_bytes().repeat(4)
            );
        }
    }
}
