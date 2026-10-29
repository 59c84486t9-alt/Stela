//! PACGA.
use stela_compiler::{GuestState, block::pauth_memory::GenericCode};

const ZERO_REGISTER_INDEX: u8 = 31;
const GENERIC_CODE_MASK: u64 = (u32::MAX as u64) << u32::BITS;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault<E> {
    InvalidOperands,
    Compute(E),
}

pub fn complete<E>(
    instruction: GenericCode,
    registers: &mut GuestState,
    compute: impl FnOnce(u64, u64) -> Result<u64, E>,
) -> Result<(), Fault<E>> {
    if !instruction.is_valid() {
        return Err(Fault::InvalidOperands);
    }
    let source = if instruction.source == ZERO_REGISTER_INDEX {
        0
    } else {
        registers.x[usize::from(instruction.source)]
    };
    let modifier = if instruction.modifier == ZERO_REGISTER_INDEX {
        registers.sp
    } else {
        registers.x[usize::from(instruction.modifier)]
    };
    // Rd may alias either input. XZR discards only after the key service succeeds.
    let value = compute(source, modifier).map_err(Fault::Compute)? & GENERIC_CODE_MASK;
    if instruction.destination != ZERO_REGISTER_INDEX {
        registers.x[usize::from(instruction.destination)] = value;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_register_roles_snapshot_inputs_and_preserve_other_state() {
        for destination in 0..=ZERO_REGISTER_INDEX {
            for source in 0..=ZERO_REGISTER_INDEX {
                for modifier in 0..=ZERO_REGISTER_INDEX {
                    let mut state = GuestState::default();
                    for (index, value) in state.x.iter_mut().enumerate() {
                        *value = (index as u64).wrapping_mul(0x0102_0304_0506_0708);
                    }
                    state.sp = 0xaabb_ccdd_eeff_0010;
                    state.nzcv = 0xf000_0000;
                    state.fpcr = 0x0300_0000;
                    state.fpsr = 0x0800_009f;
                    state.v.fill([0x1234, 0xabcd]);
                    let initial = state.clone();
                    let instruction = GenericCode {
                        destination,
                        source,
                        modifier,
                    };
                    let source_value = if source == ZERO_REGISTER_INDEX {
                        0
                    } else {
                        initial.x[usize::from(source)]
                    };
                    let modifier_value = if modifier == ZERO_REGISTER_INDEX {
                        initial.sp
                    } else {
                        initial.x[usize::from(modifier)]
                    };
                    complete(instruction, &mut state, |x, y| {
                        assert_eq!(x, source_value);
                        assert_eq!(y, modifier_value);
                        Ok::<_, ()>(0x1122_3344_5566_7788)
                    })
                    .unwrap();
                    let mut expected = initial;
                    if destination != ZERO_REGISTER_INDEX {
                        expected.x[usize::from(destination)] = 0x1122_3344_0000_0000;
                    }
                    assert_eq!(state, expected);
                }
            }
        }
    }

    #[test]
    fn missing_key_changes_no_state_even_with_discard_destination() {
        for destination in [0, ZERO_REGISTER_INDEX] {
            let mut state = GuestState::default();
            let initial = state.clone();
            let result = complete(
                GenericCode {
                    destination,
                    source: 0,
                    modifier: 1,
                },
                &mut state,
                |_, _| Err::<u64, _>("key unavailable"),
            );
            assert_eq!(result, Err(Fault::Compute("key unavailable")));
            assert_eq!(state, initial);
        }
    }
    #[test]
    fn invalid_register_descriptors_decline_before_key_service_or_state_changes() {
        for instruction in [
            GenericCode {
                destination: 32,
                source: 0,
                modifier: 1,
            },
            GenericCode {
                destination: 0,
                source: 32,
                modifier: 1,
            },
            GenericCode {
                destination: 0,
                source: 1,
                modifier: 32,
            },
        ] {
            let mut state = GuestState::default();
            let initial = state.clone();
            let result = complete(
                instruction,
                &mut state,
                |_, _| -> Result<u64, core::convert::Infallible> {
                    panic!("invalid operand reached key service")
                },
            );
            assert_eq!(result, Err(Fault::InvalidOperands));
            assert_eq!(state, initial);
        }
    }
}
