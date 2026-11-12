//! Compile-time constant facts for non-faulting scalar sequences. Each separately
//! entered region starts with no facts.
//!
//! A fact derived from the guest PC stays a guest address only while it
//! moves with the block's page: ADR, ADRP and 64-bit additions to them. A
//! MOVK or 32-bit result of one is a value no relocation reproduces, so the
//! fact is dropped and the instruction computes it at run time.
use super::encoding::{self, HostGpr};
use crate::GuestAddress;
use crate::aarch64::{Instruction, Operation, Register, WideMove, Width};
use crate::x86_64::asm::Code;

const REGISTER_SLOTS: usize = 32;
const SP_SLOT: usize = 31;
const W32_MASK: u64 = u32::MAX as u64;

/// A known register value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Constant {
    /// The same at every address of the block.
    Plain(u64),
    /// Moves with the block's page: emitted as a relocation field.
    Guest(GuestAddress),
}

impl Constant {
    /// Load it into `destination`: a plain value at `width`, a guest
    /// address always as a full relocated field.
    pub(super) fn emit(self, code: &mut Code, destination: HostGpr, width: Width) {
        match self {
            Self::Plain(value) => encoding::immediate(code, destination, value, width),
            Self::Guest(address) => encoding::guest_immediate(code, destination, address),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ConstantWrite {
    pub destination: Register,
    pub value: Constant,
}

#[derive(Clone, Debug)]
pub(super) struct ConstantRegisters {
    values: [Option<Constant>; REGISTER_SLOTS],
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

    fn read(&self, register: Register) -> Option<Constant> {
        if register == Register::Zero {
            Some(Constant::Plain(0))
        } else {
            slot(register).and_then(|index| self.values[index])
        }
    }

    fn write(&mut self, destination: Register, value: Option<Constant>) -> Option<ConstantWrite> {
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
        self.write(folded.destination, Some(Constant::Guest(folded.address)))
    }

    pub(super) fn fold_wide_run(
        &mut self,
        instructions: &[Instruction],
    ) -> Option<(usize, ConstantWrite)> {
        let (first, rest) = instructions.split_first()?;
        let Operation::MoveWide {
            width,
            kind: WideMove::Zero | WideMove::Not,
            destination: destination @ Register::X(_),
            ..
        } = first.operation
        else {
            return None;
        };
        let mut keeps = rest.iter().take_while(|instruction| {
            matches!(
                instruction.operation,
                Operation::MoveWide {
                    width: next_width,
                    kind: WideMove::Keep,
                    destination: next_destination,
                    ..
                } if next_width == width && next_destination == destination
            )
        });
        let second = keeps.next()?;
        self.step(&first.operation);
        let mut write = self
            .step(&second.operation)
            .expect("wide move initializer supplies the destination");
        let mut count = 2;
        for instruction in keeps {
            write = self
                .step(&instruction.operation)
                .expect("wide move continuation retains its constant destination");
            count += 1;
        }
        Some((count, write))
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
                    WideMove::Keep => match self.read(destination) {
                        Some(Constant::Plain(previous)) => {
                            Some((previous & !(u64::from(u16::MAX) << shift)) | lane)
                        }
                        _ => None,
                    },
                }
                .map(|value| Constant::Plain(narrow(value, width)));
                self.write(destination, value)
            }
            Operation::PcRelative(operand) => {
                self.write(operand.destination, Some(Constant::Guest(operand.address)))
            }
            Operation::AddSub {
                width,
                subtract,
                flags: false,
                destination,
                source,
                immediate,
            } => {
                let immediate = u64::from(immediate);
                let add = |source: u64| {
                    if subtract {
                        source.wrapping_sub(immediate)
                    } else {
                        source.wrapping_add(immediate)
                    }
                };
                let value = match (self.read(source), width) {
                    (Some(Constant::Plain(source)), _) => {
                        Some(Constant::Plain(narrow(add(source), width)))
                    }
                    (Some(Constant::Guest(source)), Width::X64) => {
                        Some(Constant::Guest(GuestAddress(add(source.0))))
                    }
                    _ => None,
                };
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
                Some(ConstantWrite {
                    destination,
                    value: Constant::Plain(value)
                })
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
                    address: GuestAddress(u64::MAX - 15),
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
                    value: Constant::Guest(GuestAddress(16))
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
        assert_eq!(facts.read(Register::Zero), Some(Constant::Plain(0)));
    }

    #[test]
    fn a_guest_address_narrowed_or_patched_is_no_longer_known() {
        let address = || {
            Operation::PcRelative(crate::aarch64::pc_relative::Operand {
                destination: Register::X(1),
                address: GuestAddress(0x1_2345_6000),
            })
        };
        let mut facts = ConstantRegisters::default();
        facts.step(&address());
        assert_eq!(
            facts.step(&wide(WideMove::Keep, Width::X64, Register::X(1), 7, 0)),
            None
        );
        facts.step(&address());
        let narrowed = Operation::AddSub {
            width: Width::W32,
            subtract: false,
            flags: false,
            destination: Register::X(2),
            source: Register::X(1),
            immediate: 8,
        };
        assert_eq!(facts.step(&narrowed), None);
        let mut facts = ConstantRegisters::default();
        facts.step(&wide(WideMove::Zero, Width::X64, Register::X(1), 0x10, 16));
        assert_eq!(
            facts.step(&narrowed),
            Some(ConstantWrite {
                destination: Register::X(2),
                value: Constant::Plain(0x10_0008)
            })
        );
    }
}
