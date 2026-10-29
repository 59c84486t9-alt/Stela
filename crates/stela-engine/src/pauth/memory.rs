//! LDRAA/LDRAB: authentication, then a load through the read callback with the
//! full tagged address.
use stela_compiler::{
    GuestState,
    block::pauth_memory::{DataKey, Load},
};

const ZERO_REGISTER_INDEX: u8 = 31;
const STACK_ALIGNMENT: u64 = 16;

/// Effective stack-alignment and access privilege from the selected CPU controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Controls {
    pub check_sp_alignment: bool,
    pub privileged: bool,
}

impl Default for Controls {
    fn default() -> Self {
        Self {
            check_sp_alignment: true,
            privileged: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault<A, E> {
    InvalidOperands,
    UndefinedOverlap,
    Authentication(A),
    StackAlignment { stack_pointer: u64 },
    Read { address: u64, error: E },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completion {
    pub effective_address: u64,
}

/// Complete one decoded LDRA instruction. No architectural destination is
/// changed before authentication, alignment and the complete read succeed.
/// The fixed addressing profile disables checked pointer arithmetic (CPA2).
pub fn complete<A, E>(
    instruction: Load,
    controls: Controls,
    registers: &mut GuestState,
    authenticate: impl FnOnce(DataKey, u64) -> Result<u64, A>,
    read: impl FnOnce(u64) -> Result<u64, E>,
) -> Result<Completion, Fault<A, E>> {
    if !instruction.is_valid() {
        return Err(Fault::InvalidOperands);
    }
    if instruction.undefined_overlap() {
        return Err(Fault::UndefinedOverlap);
    }
    let pointer = if instruction.base == ZERO_REGISTER_INDEX {
        registers.sp
    } else {
        registers.x[usize::from(instruction.base)]
    };
    // The June2026 architectural sequence authenticates before CheckSPAlignment.
    // The zero modifier and combined-operation policy are supplied by the caller.
    let address = authenticate(instruction.key, pointer).map_err(Fault::Authentication)?;
    if controls.check_sp_alignment
        && instruction.base == ZERO_REGISTER_INDEX
        && registers.sp & (STACK_ALIGNMENT - 1) != 0
    {
        return Err(Fault::StackAlignment {
            stack_pointer: registers.sp,
        });
    }
    let address = address.wrapping_add_signed(i64::from(instruction.displacement));
    let value = read(address).map_err(|error| Fault::Read { address, error })?;
    if instruction.destination != ZERO_REGISTER_INDEX {
        registers.x[usize::from(instruction.destination)] = value;
    }
    if instruction.writeback {
        if instruction.base == ZERO_REGISTER_INDEX {
            registers.sp = address;
        } else {
            registers.x[usize::from(instruction.base)] = address;
        }
    }
    Ok(Completion {
        effective_address: address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn load(base: u8, destination: u8, writeback: bool) -> Load {
        Load {
            key: DataKey::A,
            destination,
            base,
            displacement: -8,
            writeback,
        }
    }

    #[test]
    fn load_stages_aliases_and_commits_only_declared_outputs() {
        for base in 0..=ZERO_REGISTER_INDEX {
            for destination in 0..=ZERO_REGISTER_INDEX {
                for writeback in [false, true] {
                    let instruction = load(base, destination, writeback);
                    let mut state = GuestState::default();
                    state.x.fill(0xdead_beef_1234_5678);
                    state.sp = 0xa500_0000_0000_2000;
                    state.nzcv = 0xf000_0000;
                    state.reserved = 0xa5a5_5a5a;
                    state.fpcr = 0x0300_0000;
                    state.fpsr = 0x0800_009f;
                    state.v.fill([0x1122_3344, 0x8877_6655]);
                    let pointer = if base == ZERO_REGISTER_INDEX {
                        state.sp
                    } else {
                        state.x[usize::from(base)]
                    };
                    let initial = state.clone();
                    let result = complete(
                        instruction,
                        Controls::default(),
                        &mut state,
                        |key, old| {
                            assert_eq!(key, DataKey::A);
                            assert_eq!(old, pointer);
                            Ok::<_, ()>(0xa500_0000_0000_1000)
                        },
                        |address| {
                            assert_eq!(address, 0xa500_0000_0000_0ff8);
                            Ok::<_, ()>(0x8877_6655_4433_2211)
                        },
                    );
                    if instruction.undefined_overlap() {
                        assert_eq!(result, Err(Fault::UndefinedOverlap));
                        assert_eq!(state, initial);
                        continue;
                    }
                    assert_eq!(
                        result,
                        Ok(Completion {
                            effective_address: 0xa500_0000_0000_0ff8
                        })
                    );
                    let mut expected = initial;
                    if destination != ZERO_REGISTER_INDEX {
                        expected.x[usize::from(destination)] = 0x8877_6655_4433_2211;
                    }
                    if writeback {
                        if base == ZERO_REGISTER_INDEX {
                            expected.sp = 0xa500_0000_0000_0ff8;
                        } else {
                            expected.x[usize::from(base)] = 0xa500_0000_0000_0ff8;
                        }
                    }
                    assert_eq!(state, expected);
                }
            }
        }
    }

    #[test]
    fn authentication_precedes_sp_alignment_and_read_faults() {
        let mut state = GuestState {
            sp: 0x2001,
            ..GuestState::default()
        };
        let initial = state.clone();
        let called = Cell::new(false);
        let result = complete(
            load(ZERO_REGISTER_INDEX, 0, true),
            Controls::default(),
            &mut state,
            |_, _| Err::<u64, _>("authentication"),
            |_| {
                called.set(true);
                Ok::<_, ()>(0)
            },
        );
        assert_eq!(result, Err(Fault::Authentication("authentication")));
        assert!(!called.get());
        assert_eq!(state, initial);
        let result = complete(
            load(ZERO_REGISTER_INDEX, 0, true),
            Controls::default(),
            &mut state,
            |_, _| Ok::<_, ()>(0x3000),
            |_| {
                called.set(true);
                Ok::<_, ()>(0)
            },
        );
        assert_eq!(
            result,
            Err(Fault::StackAlignment {
                stack_pointer: 0x2001
            })
        );
        assert!(!called.get());
        assert_eq!(state, initial);
    }

    #[test]
    fn overlap_is_undefined_before_authentication_and_read() {
        let mut state = GuestState::default();
        let initial = state.clone();
        let called = Cell::new(false);
        let result = complete(
            load(3, 3, true),
            Controls::default(),
            &mut state,
            |_, _| {
                called.set(true);
                Ok::<_, ()>(0)
            },
            |_| {
                called.set(true);
                Ok::<_, ()>(0)
            },
        );
        assert_eq!(result, Err(Fault::UndefinedOverlap));
        assert!(!called.get());
        assert_eq!(state, initial);
    }

    #[test]
    fn read_failure_keeps_destination_and_base() {
        for base in [0, ZERO_REGISTER_INDEX] {
            for destination in [1, ZERO_REGISTER_INDEX] {
                let mut state = GuestState::default();
                state.x[0] = 0x3000;
                state.x[1] = 0x1122;
                state.sp = 0x4000;
                let initial = state.clone();
                let result = complete(
                    load(base, destination, true),
                    Controls::default(),
                    &mut state,
                    |_, _| Ok::<_, ()>(4),
                    |address| {
                        assert_eq!(address, u64::MAX - 3);
                        Err::<u64, _>("permission")
                    },
                );
                assert_eq!(
                    result,
                    Err(Fault::Read {
                        address: u64::MAX - 3,
                        error: "permission"
                    })
                );
                assert_eq!(state, initial);
            }
        }
    }
    #[test]
    fn nonfaulting_authentication_result_reaches_address_add_before_translation() {
        let mut state = GuestState::default();
        state.x[0] = 0x1234;
        let result = complete(
            load(0, 1, true),
            Controls::default(),
            &mut state,
            |_, _| Ok::<_, ()>(1 << 47),
            |address| {
                assert_eq!(address, 0x7fff_ffff_fff8);
                Ok::<_, ()>(0x5678)
            },
        );
        assert_eq!(
            result,
            Ok(Completion {
                effective_address: 0x7fff_ffff_fff8
            })
        );
        assert_eq!(state.x[0], 0x7fff_ffff_fff8);
        assert_eq!(state.x[1], 0x5678);
    }
    #[test]
    fn disabled_sp_alignment_reaches_read_without_weakening_enabled_checks() {
        let mut state = GuestState {
            sp: 0x2001,
            ..GuestState::default()
        };
        let result = complete(
            load(ZERO_REGISTER_INDEX, 0, true),
            Controls {
                check_sp_alignment: false,
                privileged: false,
            },
            &mut state,
            |_, pointer| {
                assert_eq!(pointer, 0x2001);
                Ok::<_, ()>(0x3001)
            },
            |address| {
                assert_eq!(address, 0x2ff9);
                Ok::<_, ()>(0x8877)
            },
        );
        assert_eq!(
            result,
            Ok(Completion {
                effective_address: 0x2ff9
            })
        );
        assert_eq!(state.x[0], 0x8877);
        assert_eq!(state.sp, 0x2ff9);
    }
    #[test]
    fn invalid_public_descriptors_decline_before_callbacks_or_commit() {
        for instruction in [
            Load {
                base: 32,
                ..load(0, 1, false)
            },
            Load {
                destination: 32,
                ..load(0, 1, false)
            },
            Load {
                displacement: -4097,
                ..load(0, 1, false)
            },
            Load {
                displacement: 4096,
                ..load(0, 1, false)
            },
            Load {
                displacement: 1,
                ..load(0, 1, false)
            },
        ] {
            let mut state = GuestState::default();
            let initial = state.clone();
            let result = complete(
                instruction,
                Controls::default(),
                &mut state,
                |_, _| -> Result<u64, core::convert::Infallible> {
                    panic!("invalid descriptor authenticated")
                },
                |_| -> Result<u64, core::convert::Infallible> {
                    panic!("invalid descriptor read memory")
                },
            );
            assert_eq!(result, Err(Fault::InvalidOperands));
            assert_eq!(state, initial);
        }
    }
}
