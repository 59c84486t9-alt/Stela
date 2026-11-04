//! Compile-time constant facts for non-faulting scalar sequences. Each separately
//! entered region starts with no facts.
use crate::aarch64::{Operation, Register, WideMove, Width};

const REGISTER_SLOTS: usize = 32;
const SP_SLOT: usize = 31;
const W32_MASK: u64 = u32::MAX as u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ConstantWrite {
    pub destination: Register,
    pub value: u64,
}

#[derive(Clone, Debug)]
pub(super) struct ConstantRegisters {
    values: [Option<u64>; REGISTER_SLOTS],
}

impl Default for ConstantRegisters {
    fn default() -> Self {
        Self {
            values: [None; REGISTER_SLOTS],
        }
    }
}

fn slot(register: Register) -> Option<usize> {
    match register {
        Register::X(index) if index < 31 => Some(usize::from(index)),
        Register::Sp => Some(SP_SLOT),
        _ => None,
    }
}

fn narrow(value: u64, width: Width) -> u64 {
    match width {
        Width::W32 => value & W32_MASK,
        Width::X64 => value,
    }
}

impl ConstantRegisters {
    pub fn clear(&mut self) {
        self.values.fill(None);
    }

    fn read(&self, register: Register) -> Option<u64> {
        if register == Register::Zero {
            Some(0)
        } else {
            slot(register).and_then(|index| self.values[index])
        }
    }

    fn write(&mut self, destination: Register, value: Option<u64>) -> Option<ConstantWrite> {
        let index = slot(destination)?;
        self.values[index] = value;
        value.map(|value| ConstantWrite { destination, value })
    }

    pub(super) fn fold_address_pair(
        &mut self,
        first: &Operation,
        second: &Operation,
    ) -> Option<ConstantWrite> {
        let folded = super::super::block::fold_address_pair(first, second)?;
        self.write(folded.destination, Some(folded.address))
    }

    /// Observe exactly one guest instruction. Returned writes can replace only
    /// that instruction's value computation; they never authorize removing its
    /// native commit, source-map entry, or observable intermediate guest value.
    /// Unknown operations conservatively erase every fact. Host-register
    /// eviction need not erase facts because it does not change guest values.
    pub fn step(&mut self, operation: &Operation) -> Option<ConstantWrite> {
        match *operation {
            Operation::MoveWide {
                width,
                kind,
                destination,
                immediate,
                shift,
            } => {
                let lane = u64::from(immediate) << shift;
                let value = match kind {
                    WideMove::Zero => Some(lane),
                    WideMove::Not => Some(!lane),
                    WideMove::Keep => self
                        .read(destination)
                        .map(|previous| (previous & !(u64::from(u16::MAX) << shift)) | lane),
                }
                .map(|value| narrow(value, width));
                self.write(destination, value)
            }
            Operation::PcRelative(operand) => {
                self.write(operand.destination, Some(operand.address))
            }
            Operation::AddSub {
                width,
                subtract,
                flags: false,
                destination,
                source,
                immediate,
            } => {
                let value = self.read(source).map(|source| {
                    let immediate = u64::from(immediate);
                    narrow(
                        if subtract {
                            source.wrapping_sub(immediate)
                        } else {
                            source.wrapping_add(immediate)
                        },
                        width,
                    )
                });
                self.write(destination, value)
            }
            Operation::Nop => None,
            _ => {
                self.clear();
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(
        kind: WideMove,
        width: Width,
        destination: Register,
        immediate: u16,
        shift: u8,
    ) -> Operation {
        Operation::MoveWide {
            kind,
            width,
            destination,
            immediate,
            shift,
        }
    }

    #[test]
    fn known_wide_moves_keep_each_intermediate_value_and_width_effect() {
        let mut facts = ConstantRegisters::default();
        let destination = Register::X(12);
        let operations = [
            wide(WideMove::Not, Width::X64, destination, 0x1234, 32),
            wide(WideMove::Keep, Width::W32, destination, 0x89ab, 16),
            wide(WideMove::Keep, Width::X64, destination, 0xcdef, 48),
        ];
        let expected = [0xffff_edcb_ffff_ffff, 0x89ab_ffff, 0xcdef_0000_89ab_ffff];
        for (operation, value) in operations.iter().zip(expected) {
            assert_eq!(
                facts.step(operation),
                Some(ConstantWrite { destination, value })
            );
        }
    }

    #[test]
    fn independent_interior_entry_does_not_inherit_a_predecessor_constant() {
        let mut facts = ConstantRegisters::default();
        assert_eq!(
            facts.step(&wide(WideMove::Keep, Width::X64, Register::X(0), 7, 16)),
            None
        );
        assert_eq!(facts.read(Register::X(0)), None);
    }

    #[test]
    fn pc_relative_address_then_add_can_alias_or_write_sp_and_wrap() {
        for destination in [Register::X(0), Register::Sp] {
            let mut facts = ConstantRegisters::default();
            let source = Register::X(0);
            facts.step(&Operation::PcRelative(
                crate::aarch64::pc_relative::Operand {
                    destination: source,
                    address: u64::MAX - 15,
                },
            ));
            assert_eq!(
                facts.step(&Operation::AddSub {
                    width: Width::X64,
                    subtract: false,
                    flags: false,
                    destination,
                    source,
                    immediate: 32,
                }),
                Some(ConstantWrite {
                    destination,
                    value: 16
                })
            );
        }
    }

    #[test]
    fn flags_and_unknown_operations_erase_facts_instead_of_dropping_effects() {
        let mut facts = ConstantRegisters::default();
        facts.step(&wide(WideMove::Zero, Width::X64, Register::X(0), 7, 0));
        assert_eq!(
            facts.step(&Operation::AddSub {
                width: Width::X64,
                subtract: false,
                flags: true,
                destination: Register::X(0),
                source: Register::X(0),
                immediate: 1,
            }),
            None
        );
        assert_eq!(facts.read(Register::X(0)), None);
    }

    #[test]
    fn zero_register_never_acquires_a_fact() {
        let mut facts = ConstantRegisters::default();
        assert_eq!(
            facts.step(&wide(WideMove::Not, Width::X64, Register::Zero, 0, 0)),
            None
        );
        assert_eq!(facts.read(Register::Zero), Some(0));
    }
}
