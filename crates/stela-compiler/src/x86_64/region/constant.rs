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
mod tests;
