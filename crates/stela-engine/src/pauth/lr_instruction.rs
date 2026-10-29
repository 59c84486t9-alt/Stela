//! Operands and effects of the FEAT_PAuth_LR instructions.

#[cfg(test)]
use stela_compiler::block::pauth_lr::decode;
pub(crate) use stela_compiler::block::pauth_lr::{Instruction, Key};

const REGISTER_MASK: u32 = 31;
const INSTRUCTION_BYTES: u64 = 4;
const LINK_REGISTER: usize = 30;
const POINTER_REGISTER: usize = 17;
const FIRST_MODIFIER: usize = 16;
const SECOND_MODIFIER: usize = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Sign,
    Authenticate,
    Return,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operands {
    pub key: Key,
    pub action: Action,
    pub pointer: u64,
    pub modifier1: u64,
    pub modifier2: u64,
    pub destination: Option<u8>,
    pub implicit_bti: bool,
    pub instruction_pc: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Staged {
    Pointer(Operands),
    Pacm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageError {
    InvalidOperands,
    UnalignedPc,
}

/// A snapshot of the instruction's operands, all from the same pre-state. The
/// executing owner authorizes and applies the effects.
pub fn stage(
    instruction: Instruction,
    pc: u64,
    x: &[u64; 31],
    sp: u64,
) -> Result<Staged, StageError> {
    if !instruction.valid() {
        return Err(StageError::InvalidOperands);
    }
    if !pc.is_multiple_of(INSTRUCTION_BYTES) {
        return Err(StageError::UnalignedPc);
    }
    let mut operands = Operands {
        key: Key::Ia,
        action: Action::Authenticate,
        pointer: x[LINK_REGISTER],
        modifier1: sp,
        modifier2: pc,
        destination: Some(LINK_REGISTER as u8),
        implicit_bti: false,
        instruction_pc: pc,
    };
    match instruction {
        Instruction::Pacm => return Ok(Staged::Pacm),
        Instruction::Sign171615(key) | Instruction::Authenticate171615(key) => {
            operands.key = key;
            operands.pointer = x[POINTER_REGISTER];
            operands.modifier1 = x[FIRST_MODIFIER];
            operands.modifier2 = x[SECOND_MODIFIER];
            operands.destination = Some(POINTER_REGISTER as u8);
            if matches!(instruction, Instruction::Sign171615(_)) {
                operands.action = Action::Sign;
            }
        }
        Instruction::AuthenticateSpRegister { key, register } => {
            operands.key = key;
            operands.modifier2 = if register == REGISTER_MASK as u8 {
                0
            } else {
                x[usize::from(register)]
            };
        }
        Instruction::AuthenticateSpPc { key, offset } => {
            operands.key = key;
            operands.modifier2 = pc.wrapping_sub(u64::from(offset));
        }
        Instruction::SignSpPc { key, implicit_bti } => {
            operands.key = key;
            operands.action = Action::Sign;
            operands.implicit_bti = implicit_bti;
        }
        Instruction::ReturnSpRegister { key, register } => {
            operands.key = key;
            operands.action = Action::Return;
            operands.modifier2 = x[usize::from(register)];
            operands.destination = None;
        }
        Instruction::ReturnSpPc { key, offset } => {
            operands.key = key;
            operands.action = Action::Return;
            operands.modifier2 = pc.wrapping_sub(u64::from(offset));
            operands.destination = None;
        }
    }
    Ok(Staged::Pointer(operands))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub enum FeatureEffect {
    Execute,
    NoEffect,
    Undefined,
}

/// PACM alone is a HINT NOP when FEAT_PAuth_LR is absent.
#[cfg(test)]
pub const fn feature_effect(instruction: Instruction, present: bool) -> FeatureEffect {
    if present {
        FeatureEffect::Execute
    } else if matches!(instruction, Instruction::Pacm) {
        FeatureEffect::NoEffect
    } else {
        FeatureEffect::Undefined
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub enum PacmEffect {
    NoEffect,
    Set(bool),
}

/// Pure state effect after the system owner resolves IsPACMEnabled from the
/// selected current EL/SCTLR2/HCRX controls. No state ownership is conferred.
#[cfg(test)]
pub const fn pacm_effect(feature_present: bool, enabled: bool) -> PacmEffect {
    if feature_present {
        PacmEffect::Set(enabled)
    } else {
        PacmEffect::NoEffect
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_canonical_subjects() {
        for &(word, canonical_id) in CANONICAL_WORDS {
            let instruction = decode(word).expect("allocated June subject");
            assert_eq!(instruction.canonical_id(), canonical_id);
            assert_eq!(feature_effect(instruction, true), FeatureEffect::Execute);
            assert_eq!(
                feature_effect(instruction, false),
                if instruction == Instruction::Pacm {
                    FeatureEffect::NoEffect
                } else {
                    FeatureEffect::Undefined
                }
            );
        }
    }

    #[test]
    fn every_allocated_register_and_legacy_return_exclusion() {
        for register in 0..32 {
            for (word, key) in [(0xdac1_901e, Key::Ia), (0xdac1_941e, Key::Ib)] {
                assert_eq!(
                    decode(word | register << 5),
                    Some(Instruction::AuthenticateSpRegister {
                        key,
                        register: register as u8
                    })
                );
            }
            for (word, key) in [(0xd65f_0be0, Key::Ia), (0xd65f_0fe0, Key::Ib)] {
                assert_eq!(
                    decode(word | register),
                    (register != 31).then_some(Instruction::ReturnSpRegister {
                        key,
                        register: register as u8
                    })
                );
            }
        }
        assert_eq!(decode(0xd65f_0bff), None); // RETAA remains existing owner's form.
        assert_eq!(decode(0xd65f_0fff), None); // RETAB remains existing owner's form.
    }

    #[test]
    fn every_immediate_is_unsigned_scaled_and_subtracted_with_wrap() {
        let x = std::array::from_fn(|n| 0x4000 + n as u64);
        for immediate in 0..=u16::MAX {
            let offset = u32::from(immediate) * 4;
            for &(word, key, action) in &[
                (0xf380_001f, Key::Ia, Action::Authenticate),
                (0xf3a0_001f, Key::Ib, Action::Authenticate),
                (0x5500_001f, Key::Ia, Action::Return),
                (0x5520_001f, Key::Ib, Action::Return),
            ] {
                let instruction = decode(word | u32::from(immediate) << 5).unwrap();
                let Staged::Pointer(operands) = stage(instruction, 4, &x, 0x8000).unwrap() else {
                    panic!("pointer form");
                };
                assert_eq!(operands.modifier2, 4u64.wrapping_sub(u64::from(offset)));
                assert_eq!((operands.key, operands.action), (key, action));
                assert_eq!(operands.pointer, x[30]);
                assert_eq!(operands.modifier1, 0x8000);
                assert_eq!(
                    operands.destination,
                    if action == Action::Return {
                        None
                    } else {
                        Some(30)
                    }
                );
            }
        }
    }

    #[test]
    fn alias_snapshots_zero_register_and_destination_roles() {
        let x = std::array::from_fn(|n| 0x1122_3344_0000_0000 + n as u64);
        for key in [Key::Ia, Key::Ib] {
            for instruction in [
                Instruction::Authenticate171615(key),
                Instruction::Sign171615(key),
            ] {
                let Staged::Pointer(o) = stage(instruction, 0x1000, &x, 0x9876).unwrap() else {
                    panic!()
                };
                assert_eq!(
                    (o.pointer, o.modifier1, o.modifier2, o.destination),
                    (x[17], x[16], x[15], Some(17))
                );
            }
            for register in 0..=31 {
                let Staged::Pointer(o) = stage(
                    Instruction::AuthenticateSpRegister { key, register },
                    0x1000,
                    &x,
                    0x9876,
                )
                .unwrap() else {
                    panic!()
                };
                assert_eq!(
                    o.modifier2,
                    if register == 31 {
                        0
                    } else {
                        x[usize::from(register)]
                    }
                );
                assert_eq!(
                    (o.pointer, o.modifier1, o.destination),
                    (x[30], 0x9876, Some(30))
                );
            }
            let Staged::Pointer(o) = stage(
                Instruction::ReturnSpRegister { key, register: 30 },
                0x1000,
                &x,
                0x9876,
            )
            .unwrap() else {
                panic!()
            };
            assert_eq!(
                (o.pointer, o.modifier2, o.destination),
                (x[30], x[30], None)
            );
        }
    }

    #[test]
    fn implicit_bti_is_confined_to_pacixsppc() {
        let x = [42; 31];
        for (word, expected) in [
            (0xdac1_a3fe, true),
            (0xdac1_a7fe, true),
            (0xdac1_83fe, false),
            (0xdac1_87fe, false),
            (0xdac1_8bfe, false),
            (0xdac1_8ffe, false),
        ] {
            let Staged::Pointer(o) = stage(decode(word).unwrap(), 0x1000, &x, 0x8000).unwrap()
            else {
                panic!()
            };
            assert_eq!(o.implicit_bti, expected);
            assert_eq!(o.action, Action::Sign);
        }
    }

    #[test]
    fn invalid_typed_operands_decline_before_indexing() {
        let x = [0; 31];
        for instruction in [
            Instruction::AuthenticateSpRegister {
                key: Key::Ia,
                register: 32,
            },
            Instruction::ReturnSpRegister {
                key: Key::Ib,
                register: 31,
            },
            Instruction::AuthenticateSpPc {
                key: Key::Ia,
                offset: 1,
            },
            Instruction::ReturnSpPc {
                key: Key::Ib,
                offset: 262_144,
            },
        ] {
            assert_eq!(
                stage(instruction, 0x1000, &x, 0),
                Err(StageError::InvalidOperands)
            );
        }
        for instruction in [Instruction::Pacm, Instruction::Sign171615(Key::Ia)] {
            assert_eq!(stage(instruction, 1, &x, 0), Err(StageError::UnalignedPc));
        }
    }

    #[test]
    fn pacm_feature_and_resolved_control_truth_table() {
        assert_eq!(
            stage(Instruction::Pacm, 0x1000, &[0; 31], 0).unwrap(),
            Staged::Pacm
        );
        for enabled in [false, true] {
            assert_eq!(pacm_effect(false, enabled), PacmEffect::NoEffect);
            assert_eq!(pacm_effect(true, enabled), PacmEffect::Set(enabled));
        }
    }

    // Independent expected words and IDs pinned in contracts.json to June XML.
    const CANONICAL_WORDS: &[(u32, &str)] = &[
        (0xdac1bbfe, "AUTIA171615_64LR_dp_1src"),
        (0xdac1901e, "AUTIASPPCR_64LRR_dp_1src"),
        (0xf380001f, "AUTIASPPC_only_dp_1src_imm"),
        (0xdac1bffe, "AUTIB171615_64LR_dp_1src"),
        (0xdac1941e, "AUTIBSPPCR_64LRR_dp_1src"),
        (0xf3a0001f, "AUTIBSPPC_only_dp_1src_imm"),
        (0xdac18bfe, "PACIA171615_64LR_dp_1src"),
        (0xdac1a3fe, "PACIASPPC_64LR_dp_1src"),
        (0xdac18ffe, "PACIB171615_64LR_dp_1src"),
        (0xdac1a7fe, "PACIBSPPC_64LR_dp_1src"),
        (0xd50324ff, "PACM_HI_hints"),
        (0xdac183fe, "PACNBIASPPC_64LR_dp_1src"),
        (0xdac187fe, "PACNBIBSPPC_64LR_dp_1src"),
        (0xd65f0be0, "RETAASPPCR_64M_branch_reg"),
        (0x5500001f, "RETAASPPC_only_miscbranch"),
        (0xd65f0fe0, "RETABSPPCR_64M_branch_reg"),
        (0x5520001f, "RETABSPPC_only_miscbranch"),
    ];

    #[test]
    fn legacy_conditional_modifiers_preserve_source_distinctions() {
        use crate::{pauth::conditional, system::state::Pacm};
        use stela_compiler::block::{
            PointerAuthenticationKey as K, PointerAuthenticationModifier as M,
            PointerAuthenticationOperation as O,
        };
        let mut x = [0; 31];
        x[15] = 0x150;
        x[16] = 0x160;
        x[17] = 0x170;
        x[30] = 0x300;
        for key in [K::Ia, K::Ib] {
            for (operation, pointer, first, second, action) in [
                (O::Sign1716 { key }, x[17], x[16], x[15], Action::Sign),
                (
                    O::Authenticate1716 { key },
                    x[17],
                    x[16],
                    x[15],
                    Action::Authenticate,
                ),
                (
                    O::Sign {
                        key,
                        destination: 16,
                        modifier: M::StackPointer,
                    },
                    x[16],
                    0x8000,
                    0x1000,
                    Action::Sign,
                ),
                (
                    O::Authenticate {
                        key,
                        destination: 16,
                        modifier: M::StackPointer,
                    },
                    x[16],
                    0x8000,
                    x[16],
                    Action::Authenticate,
                ),
            ] {
                for pacm in [Pacm::Zero, Pacm::One] {
                    let operands = conditional::stage(operation, 0x1000, &x, 0x8000, pacm)
                        .unwrap()
                        .unwrap();
                    assert_eq!(operands.pointer, pointer);
                    assert_eq!(operands.first, first);
                    assert_eq!(operands.second, (pacm == Pacm::One).then_some(second));
                    assert_eq!(operands.action, action);
                }
            }
            for operation in [
                O::Sign {
                    key,
                    destination: 17,
                    modifier: M::Register(16),
                },
                O::Authenticate {
                    key,
                    destination: 17,
                    modifier: M::Register(16),
                },
            ] {
                assert!(
                    conditional::stage(operation, 0x1000, &x, 0x8000, Pacm::One)
                        .unwrap()
                        .is_none()
                );
            }
        }
        assert_eq!(x[16], 0x160);
        assert_eq!(x[17], 0x170);
    }

    #[test]
    fn legacy_sp_zero_register_and_return_stage_before_effects() {
        use crate::{pauth::conditional, system::state::Pacm};
        use stela_compiler::block::{
            PointerAuthenticationKey as K, PointerAuthenticationModifier as M,
            PointerAuthenticationOperation as O,
        };
        let mut x = [0; 31];
        x[16] = 0x160;
        x[30] = 0x300;
        for operation in [O::ReturnIaSp, O::ReturnIbSp] {
            let operands = conditional::stage(operation, 0x1000, &x, 0x8000, Pacm::One)
                .unwrap()
                .unwrap();
            assert_eq!(operands.pointer, x[30]);
            assert_eq!(operands.destination, None);
            assert_eq!(operands.second, Some(x[16]));
            assert_eq!(operands.action, Action::Return);
        }
        for key in [K::Ia, K::Ib] {
            for operation in [
                O::Sign {
                    key,
                    destination: 31,
                    modifier: M::StackPointer,
                },
                O::Authenticate {
                    key,
                    destination: 31,
                    modifier: M::StackPointer,
                },
            ] {
                let operands = conditional::stage(operation, 0x1000, &x, 0x8000, Pacm::One)
                    .unwrap()
                    .unwrap();
                assert_eq!(operands.pointer, 0);
                assert_eq!(operands.destination, Some(31));
            }
        }
        let invalid = O::Sign {
            key: K::Ia,
            destination: 32,
            modifier: M::StackPointer,
        };
        assert_eq!(
            conditional::stage(invalid, 0x1000, &x, 0x8000, Pacm::One),
            Err(StageError::InvalidOperands)
        );
        assert_eq!(
            conditional::stage(O::ReturnIaSp, 0x1001, &x, 0x8000, Pacm::One),
            Err(StageError::UnalignedPc)
        );
    }
}
