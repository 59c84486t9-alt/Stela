//! Completion of SVE FP8 conversions.

use stela_compiler::{
    GuestState,
    aarch64::{
        floating::fp8::{self, ConversionFormat},
        scalable::MAX_VECTOR_BYTES,
        sve::floating::fp8::{Kind, Operand, Precision},
    },
};
use stela_contracts::refuse;

use super::{CompletionError, NumericalControls};
use crate::scalable::ScalableState;

fn format(precision: Precision) -> ConversionFormat {
    match precision {
        Precision::Half => ConversionFormat::Half,
        Precision::Bfloat16 => ConversionFormat::BFloat16,
        Precision::Single => ConversionFormat::Single,
    }
}

pub(super) fn complete(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    controls: NumericalControls,
) -> Result<(), CompletionError> {
    if !scalable.mode().streaming() {
        return Err(refuse!("FP8 conversion requires admitted streaming state").into());
    }
    if operand.destination >= 32
        || operand.source >= 32
        || matches!(
            operand.kind,
            Kind::Widen {
                precision: Precision::Single,
                ..
            }
        )
        || matches!(
            operand.kind,
            Kind::Narrow {
                precision: Precision::Half | Precision::Bfloat16,
                top: true
            }
        )
        || matches!(operand.kind, Kind::Narrow { .. }) && operand.source & 1 != 0
    {
        return Err(refuse!("invalid SVE FP8 conversion descriptor").into());
    }
    let length = scalable.vector_length().bytes();
    let fpmr = scalable.fpmr();
    let mut first = [0; MAX_VECTOR_BYTES];
    let mut second = [0; MAX_VECTOR_BYTES];
    let mut result = [0; MAX_VECTOR_BYTES];
    scalable.read_z(state, operand.source, &mut first[..length])?;
    if matches!(operand.kind, Kind::Narrow { .. }) {
        scalable.read_z(state, operand.source + 1, &mut second[..length])?;
    }
    if matches!(operand.kind, Kind::Narrow { top: true, .. }) {
        scalable.read_z(state, operand.destination, &mut result[..length])?;
    }
    let mut exceptions = 0;
    match operand.kind {
        Kind::Widen {
            precision,
            source2,
            top,
        } => {
            for offset in (0..length).step_by(precision.bytes()) {
                let value = fp8::from_fp8(
                    format(precision),
                    source2,
                    controls.fpcr,
                    fpmr,
                    first[offset + usize::from(top)],
                )?;
                result[offset..offset + precision.bytes()]
                    .copy_from_slice(&value.bits.to_le_bytes()[..precision.bytes()]);
                exceptions |= value.exceptions;
            }
        }
        Kind::Narrow { precision, top } => {
            let source_bytes = precision.bytes();
            let destination_stride = source_bytes / 2;
            for offset in (0..length).step_by(source_bytes) {
                for (register, source) in [&first, &second].into_iter().enumerate() {
                    let mut bits = [0; size_of::<u64>()];
                    bits[..source_bytes].copy_from_slice(&source[offset..offset + source_bytes]);
                    let value = fp8::to_fp8(
                        format(precision),
                        controls.fpcr,
                        fpmr,
                        u64::from_le_bytes(bits),
                    )?;
                    let destination = offset + register * destination_stride + usize::from(top);
                    result[destination] = value.bits as u8;
                    exceptions |= value.exceptions;
                }
            }
        }
    }
    scalable.write_z(state, operand.destination, &result[..length])?;
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::aarch64::{
        floating::{FPCR_EXCEPTION_ENABLE_MASK, FPSR_QC, features::NumericalFeatures},
        scalable::{LOOKUP_TABLE_BYTES, PREDICATE_REGISTER_COUNT, ScalableMode, VectorLength},
    };

    fn controls(state: &GuestState, full_a64: bool) -> NumericalControls {
        NumericalControls::new(
            state.fpcr,
            true,
            NumericalFeatures::new(full_a64, false, false),
        )
    }

    fn get(state: &GuestState, scalable: &ScalableState, register: u8) -> Vec<u8> {
        let mut result = vec![0; scalable.vector_length().bytes()];
        scalable.read_z(state, register, &mut result).unwrap();
        result
    }

    fn snapshot(state: &GuestState, scalable: &ScalableState) -> Vec<Vec<u8>> {
        let mut result: Vec<_> = (0..32)
            .map(|register| get(state, scalable, register))
            .collect();
        for register in 0..PREDICATE_REGISTER_COUNT {
            let mut predicate = vec![0; scalable.vector_length().predicate_bytes()];
            scalable.read_predicate(register, &mut predicate).unwrap();
            result.push(predicate);
        }
        let mut ffr = vec![0; scalable.vector_length().predicate_bytes()];
        scalable.read_ffr(&mut ffr).unwrap();
        result.push(ffr);
        let mut za = vec![0; scalable.vector_length().bytes().pow(2)];
        scalable.read_za(0, &mut za).unwrap();
        result.push(za);
        let mut zt0 = vec![0; LOOKUP_TABLE_BYTES];
        scalable.read_zt0(0, &mut zt0).unwrap();
        result.push(zt0);
        result
    }

    fn setup(length: usize) -> (GuestState, ScalableState) {
        let mut state = GuestState {
            x: std::array::from_fn(|index| 0x1234_0000 | index as u64),
            nzcv: 0xa000_0000,
            sp: 0x5678_0000,
            ..GuestState::default()
        };
        let mut scalable = ScalableState::new(VectorLength::from_bytes(length).unwrap(), true);
        scalable
            .apply_mode(&mut state, ScalableMode::new(true, true))
            .unwrap();
        for register in 0..32 {
            let bytes: Vec<_> = (0..length)
                .map(|byte| (byte as u8).wrapping_add(register))
                .collect();
            scalable.write_z(&mut state, register, &bytes).unwrap();
        }
        for register in 0..PREDICATE_REGISTER_COUNT {
            scalable
                .write_predicate(register, &vec![register; length / 8])
                .unwrap();
        }
        scalable.write_ffr(&vec![0xa5; length / 8]).unwrap();
        scalable.write_za(0, &vec![0x96; length.pow(2)]).unwrap();
        scalable.write_zt0(0, &[0x69; LOOKUP_TABLE_BYTES]).unwrap();
        scalable.set_tpidr2_el0(0x1234_5678);
        state.fpsr = FPSR_QC;
        (state, scalable)
    }

    #[test]
    fn every_layout_snapshots_aliases_and_preserves_unrelated_complete_state() {
        let words = [
            0x6508_3000,
            0x6509_3000,
            0x6508_3400,
            0x6509_3400,
            0x6508_3800,
            0x6509_3800,
            0x6508_3c00,
            0x6509_3c00,
            0x650a_3000,
            0x650a_3800,
            0x650a_3400,
            0x650a_3c00,
        ];
        for length in [16, 32, 64, 128, MAX_VECTOR_BYTES] {
            for word in words {
                for destination in [0, 1, 31] {
                    let operand =
                        stela_compiler::aarch64::sve::floating::fp8::decode(word | destination)
                            .unwrap()
                            .unwrap();
                    let (mut state, mut scalable) = setup(length);
                    let old = state.clone();
                    let old_scalable = scalable.clone();
                    let mut expected_snapshot = snapshot(&state, &scalable);
                    let first = &expected_snapshot[0];
                    let second = &expected_snapshot[1];
                    let mut expected = match operand.kind {
                        Kind::Narrow { top: true, .. } => {
                            expected_snapshot[destination as usize].clone()
                        }
                        _ => vec![0; length],
                    };
                    let mut exceptions = 0;
                    match operand.kind {
                        Kind::Widen {
                            precision,
                            source2,
                            top,
                        } => {
                            for (lane, output) in
                                expected.as_chunks_mut::<2>().0.iter_mut().enumerate()
                            {
                                let result = fp8::from_fp8(
                                    format(precision),
                                    source2,
                                    0,
                                    0,
                                    first[2 * lane + usize::from(top)],
                                )
                                .unwrap();
                                output.copy_from_slice(&(result.bits as u16).to_le_bytes());
                                exceptions |= result.exceptions;
                            }
                        }
                        Kind::Narrow { precision, top } => {
                            for (lane, (a, b)) in first
                                .chunks_exact(precision.bytes())
                                .zip(second.chunks_exact(precision.bytes()))
                                .enumerate()
                            {
                                for (source_index, bytes) in [a, b].into_iter().enumerate() {
                                    let mut input = [0; 8];
                                    input[..bytes.len()].copy_from_slice(bytes);
                                    let result = fp8::to_fp8(
                                        format(precision),
                                        0,
                                        0,
                                        u64::from_le_bytes(input),
                                    )
                                    .unwrap();
                                    let index = (2 * lane + source_index) * (precision.bytes() / 2)
                                        + usize::from(top);
                                    expected[index] = result.bits as u8;
                                    exceptions |= result.exceptions;
                                }
                            }
                        }
                    }
                    let control = controls(&state, false);
                    complete(&mut state, &mut scalable, &operand, control).unwrap();
                    expected_snapshot[destination as usize] = expected;
                    assert_eq!(snapshot(&state, &scalable), expected_snapshot);
                    let mut expected_state = old;
                    expected_state.v[destination as usize] = state.v[destination as usize];
                    expected_state.fpsr |= exceptions;
                    assert_eq!(state, expected_state);
                    assert_eq!(scalable.fpmr(), old_scalable.fpmr());
                    assert_eq!(scalable.tpidr2_el0(), old_scalable.tpidr2_el0());
                    assert_eq!(scalable.mode(), old_scalable.mode());
                }
            }
        }
    }

    #[test]
    fn kept_exception_enables_refuse_before_any_architectural_write() {
        let (mut state, mut scalable) = setup(32);
        state.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
        let old = state.clone();
        let old_snapshot = snapshot(&state, &scalable);
        let operand = Operand {
            kind: Kind::Narrow {
                precision: Precision::Single,
                top: true,
            },
            source: 0,
            destination: 1,
        };
        let control = controls(&state, true);
        assert!(matches!(
            complete(&mut state, &mut scalable, &operand, control),
            Err(CompletionError::UnsupportedControl(_))
        ));
        assert_eq!(state, old);
        assert_eq!(snapshot(&state, &scalable), old_snapshot);
    }
}
