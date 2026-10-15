//! Staged streaming BF dot and widening completion with complete original scalable sources.

use anyhow::anyhow;
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{FPCR_EBF, Outcome, bfloat16},
        scalable::{MAX_VECTOR_BYTES, VECTOR_CHUNK_BYTES},
        sve::{
            dot::{RightOperand, VectorPart},
            floating::bfloat16::{Kind, Operand},
        },
    },
};

use super::{CompletionError, NumericalControls};
use crate::scalable::ScalableState;

const BFLOAT_BYTES: usize = size_of::<u16>();
const SINGLE_BYTES: usize = size_of::<u32>();
const DOT_COMPONENTS: usize = 2;

fn require(condition: bool, message: &'static str) -> Result<(), CompletionError> {
    if condition {
        Ok(())
    } else {
        Err(anyhow!(message).into())
    }
}

struct Sources {
    destination: [u8; MAX_VECTOR_BYTES],
    left: [u8; MAX_VECTOR_BYTES],
    right: [u8; MAX_VECTOR_BYTES],
}

impl Sources {
    fn snapshot(
        state: &GuestState,
        scalable: &ScalableState,
        operand: &Operand,
    ) -> anyhow::Result<Self> {
        let mut result = Self {
            destination: [0; MAX_VECTOR_BYTES],
            left: [0; MAX_VECTOR_BYTES],
            right: [0; MAX_VECTOR_BYTES],
        };
        let length = scalable.vector_length().bytes();
        let right = match operand.right {
            RightOperand::Vector(register) | RightOperand::Indexed { register, .. } => register,
        };
        scalable.read_z(
            state,
            operand.destination,
            &mut result.destination[..length],
        )?;
        scalable.read_z(state, operand.left, &mut result.left[..length])?;
        scalable.read_z(state, right, &mut result.right[..length])?;
        Ok(result)
    }
}

fn read_bfloat(source: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        source[offset..offset + BFLOAT_BYTES]
            .try_into()
            .expect("BF lane"),
    )
}

fn read_single(source: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        source[offset..offset + SINGLE_BYTES]
            .try_into()
            .expect("Single lane"),
    )
}

fn right_offset(operand: &Operand, byte_offset: usize) -> usize {
    match operand.right {
        RightOperand::Vector(_) => byte_offset,
        RightOperand::Indexed { index, .. } => {
            let index_bytes = if operand.kind == Kind::Dot {
                SINGLE_BYTES
            } else {
                BFLOAT_BYTES
            };
            byte_offset - byte_offset % VECTOR_CHUNK_BYTES + usize::from(index) * index_bytes
        }
    }
}

fn evaluate(
    operand: &Operand,
    sources: &Sources,
    byte_offset: usize,
    controls: NumericalControls,
) -> Result<Outcome, CompletionError> {
    let fpcr = controls.fpcr;
    let right = right_offset(operand, byte_offset);
    Ok(match operand.kind {
        Kind::Dot => {
            let mut left = [0; DOT_COMPONENTS];
            let mut right_values = [0; DOT_COMPONENTS];
            for component in 0..DOT_COMPONENTS {
                left[component] =
                    read_bfloat(&sources.left, byte_offset + component * BFLOAT_BYTES);
                right_values[component] =
                    read_bfloat(&sources.right, right + component * BFLOAT_BYTES);
            }
            let addend = read_single(&sources.destination, byte_offset);
            if controls.features.ebf16() && fpcr & FPCR_EBF != 0 {
                bfloat16::extended_dot::evaluate(fpcr, addend, left, right_values)
            } else {
                Outcome {
                    bits: u64::from(bfloat16::dot_add(fpcr, addend, left, right_values)),
                    exceptions: 0,
                }
            }
        }
        Kind::MultiplyLong { subtract, part } => {
            let parity = match part {
                VectorPart::Bottom => 0,
                VectorPart::Top => BFLOAT_BYTES,
            };
            let left = read_bfloat(&sources.left, byte_offset + parity);
            let left = if subtract {
                bfloat16::negate(fpcr, left)
            } else {
                left
            };
            let right = if matches!(operand.right, RightOperand::Vector(_)) {
                right + parity
            } else {
                right
            };
            bfloat16::multiply_add(
                fpcr,
                read_single(&sources.destination, byte_offset),
                left,
                read_bfloat(&sources.right, right),
            )?
        }
    })
}

/// Complete one BF instruction without changing raw FPCR or unrelated state.
/// FA64 enabled numerical traps retain an explicit transactional refusal.
/// BFDOT selects enhanced semantics only when both EBF16 and EBF are available.
pub(super) fn complete(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    controls: NumericalControls,
) -> Result<(), CompletionError> {
    require(
        scalable.mode().streaming(),
        "scalable BF arithmetic requires streaming state",
    )?;

    require(
        operand.predicate.is_none(),
        "BF accumulation has no predicated form",
    )?;
    if let RightOperand::Indexed { index, .. } = operand.right {
        let indexed_bytes = if operand.kind == Kind::Dot {
            SINGLE_BYTES
        } else {
            BFLOAT_BYTES
        };
        require(
            usize::from(index) < VECTOR_CHUNK_BYTES / indexed_bytes,
            "BF source index outside its segment",
        )?;
    }
    let sources = Sources::snapshot(state, scalable, operand)?;
    let length = scalable.vector_length().bytes();
    let element_bytes = SINGLE_BYTES;
    let mut result = sources.destination;
    let mut exceptions = 0;
    for byte_offset in (0..length).step_by(element_bytes) {
        let outcome = evaluate(operand, &sources, byte_offset, controls)?;
        result[byte_offset..byte_offset + element_bytes]
            .copy_from_slice(&outcome.bits.to_le_bytes()[..element_bytes]);
        exceptions |= outcome.exceptions;
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
            FPCR_AH, FPCR_EBF, FPCR_EXCEPTION_ENABLE_MASK, FPSR_QC, features::NumericalFeatures,
        },
        scalable::{ScalableMode, VectorLength},
    };

    const DESTINATION: u8 = 31;
    const LEFT: u8 = 1;
    const RIGHT: u8 = 2;
    const BFLOAT_ONE: u16 = 0x3f80;
    const BFLOAT_SIGNALING_NAN: u16 = 0x7f81;
    const SINGLE_ONE: u32 = 0x3f80_0000;
    const SINGLE_TWO: u32 = 0x4000_0000;

    fn complete_profile(
        state: &mut GuestState,
        scalable: &mut ScalableState,
        operand: &Operand,
        full_a64: bool,
    ) -> Result<(), CompletionError> {
        let controls = NumericalControls::new(
            state.fpcr,
            scalable.mode().streaming(),
            NumericalFeatures::new(full_a64, false, false),
        );
        super::complete(state, scalable, operand, controls)
    }

    fn setup(length: usize) -> (GuestState, ScalableState) {
        let mut state = GuestState {
            x: std::array::from_fn(|index| 0x1234_0000_0000_0000 | index as u64),
            nzcv: 0xa000_0000,
            sp: 0x1111_2222_3333_4444,
            reserved: 0xaaaa_5555,
            ..GuestState::default()
        };
        let mut scalable = ScalableState::new(VectorLength::from_bytes(length).unwrap(), true);
        scalable
            .apply_mode(&mut state, ScalableMode::new(true, true))
            .unwrap();
        state.fpsr = FPSR_QC;
        (state, scalable)
    }

    fn put(
        scalable: &mut ScalableState,
        state: &mut GuestState,
        register: u8,
        values: &[u64],
        width: usize,
    ) {
        let mut bytes = vec![0; scalable.vector_length().bytes()];
        for (source, destination) in values.iter().zip(bytes.chunks_exact_mut(width)) {
            destination.copy_from_slice(&source.to_le_bytes()[..width]);
        }
        scalable.write_z(state, register, &bytes).unwrap();
    }

    fn get(scalable: &ScalableState, state: &GuestState, register: u8) -> Vec<u8> {
        let mut bytes = vec![0; scalable.vector_length().bytes()];
        scalable.read_z(state, register, &mut bytes).unwrap();
        bytes
    }

    fn base(kind: Kind) -> Operand {
        Operand {
            kind,
            destination: DESTINATION,
            left: LEFT,
            right: RightOperand::Vector(RIGHT),
            predicate: None,
        }
    }

    #[test]
    fn widening_parity_reads_original_destructive_accumulator() {
        for part in [VectorPart::Bottom, VectorPart::Top] {
            let (mut state, mut scalable) = setup(32);
            put(
                &mut scalable,
                &mut state,
                DESTINATION,
                &[u64::from(SINGLE_ONE); 8],
                SINGLE_BYTES,
            );
            put(
                &mut scalable,
                &mut state,
                RIGHT,
                &[u64::from(BFLOAT_ONE); 16],
                BFLOAT_BYTES,
            );
            let mut operand = base(Kind::MultiplyLong {
                subtract: false,
                part,
            });
            operand.left = DESTINATION;
            complete_profile(&mut state, &mut scalable, &operand, false).unwrap();
            let expected = if part == VectorPart::Bottom {
                SINGLE_ONE
            } else {
                SINGLE_TWO
            };
            assert_eq!(
                get(&scalable, &state, DESTINATION),
                expected.to_le_bytes().repeat(8)
            );
            assert_eq!(state.fpsr, FPSR_QC);
        }
    }

    #[test]
    fn widening_alternative_mode_suppresses_exceptions() {
        let (mut state, mut scalable) = setup(16);
        put(
            &mut scalable,
            &mut state,
            LEFT,
            &[u64::from(BFLOAT_SIGNALING_NAN); 8],
            BFLOAT_BYTES,
        );
        put(
            &mut scalable,
            &mut state,
            RIGHT,
            &[u64::from(BFLOAT_ONE); 8],
            BFLOAT_BYTES,
        );
        state.fpcr = FPCR_AH | FPCR_EXCEPTION_ENABLE_MASK;
        complete_profile(
            &mut state,
            &mut scalable,
            &base(Kind::MultiplyLong {
                subtract: true,
                part: VectorPart::Top,
            }),
            true,
        )
        .unwrap();
        assert_eq!(state.fpsr, FPSR_QC);
        assert_eq!(
            get(&scalable, &state, DESTINATION),
            0x7fc1_0000_u32.to_le_bytes().repeat(4)
        );
    }

    #[test]
    fn classic_dot_ignores_raw_ebf_and_preserves_status_with_all_aliases() {
        let (mut state, mut scalable) = setup(32);
        put(
            &mut scalable,
            &mut state,
            DESTINATION,
            &[u64::from(SINGLE_ONE); 8],
            SINGLE_BYTES,
        );
        state.fpcr = FPCR_EBF | FPCR_EXCEPTION_ENABLE_MASK;
        let mut operand = base(Kind::Dot);
        operand.left = DESTINATION;
        operand.right = RightOperand::Indexed {
            register: DESTINATION,
            index: 3,
        };
        complete_profile(&mut state, &mut scalable, &operand, true).unwrap();
        assert_eq!(
            get(&scalable, &state, DESTINATION),
            SINGLE_TWO.to_le_bytes().repeat(8)
        );
        assert_eq!(state.fpsr, FPSR_QC);
        assert_eq!(state.fpcr, FPCR_EBF | FPCR_EXCEPTION_ENABLE_MASK);
    }

    #[test]
    fn invalid_shape_or_index_and_nonstreaming_state_fail_without_effects() {
        let (mut state, mut scalable) = setup(32);
        let before = state.clone();
        let original = get(&scalable, &state, DESTINATION);
        for mut operand in [
            base(Kind::Dot),
            base(Kind::MultiplyLong {
                subtract: false,
                part: VectorPart::Bottom,
            }),
        ] {
            operand.predicate = Some(0);
            assert!(matches!(
                complete_profile(&mut state, &mut scalable, &operand, false),
                Err(CompletionError::State(_))
            ));
        }
        let mut operand = base(Kind::Dot);
        operand.right = RightOperand::Indexed {
            register: RIGHT,
            index: 4,
        };
        assert!(matches!(
            complete_profile(&mut state, &mut scalable, &operand, false),
            Err(CompletionError::State(_))
        ));
        assert_eq!(state, before);
        assert_eq!(get(&scalable, &state, DESTINATION), original);
        scalable
            .apply_mode(&mut state, ScalableMode::new(false, false))
            .unwrap();
        let before = state.clone();
        assert!(matches!(
            complete_profile(&mut state, &mut scalable, &base(Kind::Dot), false),
            Err(CompletionError::State(_))
        ));
        assert_eq!(state, before);
    }
    #[test]
    fn enhanced_dot_requires_both_feature_availability_and_control_selection() {
        const BFLOAT_MINIMUM: u64 = 0x0080;
        const BFLOAT_HALF: u64 = 0x3f00;
        const SINGLE_MINIMUM: u32 = 0x0080_0000;
        for available in [false, true] {
            for selected in [false, true] {
                let (mut state, mut scalable) = setup(32);
                put(
                    &mut scalable,
                    &mut state,
                    LEFT,
                    &[BFLOAT_MINIMUM; 16],
                    BFLOAT_BYTES,
                );
                put(
                    &mut scalable,
                    &mut state,
                    RIGHT,
                    &[BFLOAT_HALF; 16],
                    BFLOAT_BYTES,
                );
                state.fpcr = FPCR_EXCEPTION_ENABLE_MASK | if selected { FPCR_EBF } else { 0 };
                let controls = NumericalControls::new(
                    state.fpcr,
                    true,
                    NumericalFeatures::new(true, available, false),
                );
                super::complete(&mut state, &mut scalable, &base(Kind::Dot), controls).unwrap();
                let expected = if available && selected {
                    SINGLE_MINIMUM
                } else {
                    0
                };
                assert_eq!(
                    get(&scalable, &state, DESTINATION),
                    expected.to_le_bytes().repeat(8)
                );
                assert_eq!(state.fpsr, FPSR_QC);
                assert_eq!(
                    state.fpcr,
                    FPCR_EXCEPTION_ENABLE_MASK | if selected { FPCR_EBF } else { 0 }
                );
            }
        }
    }
}
