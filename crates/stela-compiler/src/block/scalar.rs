//! Integer scalar loads and stores decoded for the system engine's device
//! accesses. One operand from the shared checked scalar adapter describes the
//! access; the descriptor grants no memory access.
use crate::{
    GuestAddress,
    aarch64::{
        AddressMode, Instruction, MemoryTransfer, Register, Width, register_offset::IndexExtend,
    },
    x86_64::memory_store::checked_scalar::{Address, Operand},
};

/// Addressing derived from the source instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarLoadAddress {
    Literal {
        address: u64,
    },
    Immediate {
        base: Register,
        displacement: i32,
        mode: AddressMode,
    },
    RegisterOffset {
        base: Register,
        index: Register,
        extend: IndexExtend,
        shift: u8,
    },
}

fn scalar_address(operand: Operand) -> ScalarLoadAddress {
    match operand.address() {
        Address::Literal { address } => ScalarLoadAddress::Literal { address },
        Address::Immediate { displacement, mode } => ScalarLoadAddress::Immediate {
            base: operand.base(),
            displacement,
            mode,
        },
        Address::RegisterOffset {
            index,
            extend,
            shift,
        } => ScalarLoadAddress::RegisterOffset {
            base: operand.base(),
            index,
            extend,
            shift,
        },
    }
}

/// An integer load of 1, 2, 4 or 8 bytes, including literals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalarLoad {
    source_pc: GuestAddress,
    operand: Operand,
}
impl ScalarLoad {
    pub fn from_instruction(instruction: &Instruction) -> Option<Self> {
        Some(Self {
            source_pc: instruction.pc,
            operand: Operand::scalar_load(&instruction.operation)?,
        })
    }
    pub fn source_pc(self) -> GuestAddress {
        self.source_pc
    }
    pub fn bytes(self) -> u8 {
        self.operand.bytes()
    }
    pub fn destination(self) -> Register {
        self.operand.data()
    }
    pub fn result_width(self) -> Width {
        let MemoryTransfer::Load { width, .. } = self.operand.transfer() else {
            unreachable!("scalar_load admits only loads")
        };
        width
    }
    pub fn signed(self) -> bool {
        let MemoryTransfer::Load { signed, .. } = self.operand.transfer() else {
            unreachable!("scalar_load admits only loads")
        };
        signed
    }
    pub fn address(self) -> ScalarLoadAddress {
        scalar_address(self.operand)
    }
}

/// Store addressing; `ScalarStore::address` never produces `Literal`.
pub type ScalarStoreAddress = ScalarLoadAddress;

/// An integer store of 1, 2, 4 or 8 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalarStore {
    source_pc: GuestAddress,
    operand: Operand,
}
impl ScalarStore {
    pub fn from_instruction(instruction: &Instruction) -> Option<Self> {
        Some(Self {
            source_pc: instruction.pc,
            operand: Operand::scalar_store(&instruction.operation)?,
        })
    }
    pub fn source_pc(self) -> GuestAddress {
        self.source_pc
    }
    pub fn bytes(self) -> u8 {
        self.operand.bytes()
    }
    pub fn source_register(self) -> Register {
        self.operand.data()
    }
    pub fn address(self) -> ScalarStoreAddress {
        scalar_address(self.operand)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Lifter, aarch64::Decoder};

    fn lift(word: u32) -> Instruction {
        Decoder.lift(GuestAddress(0x1000), word).unwrap()
    }

    #[test]
    fn loads_keep_width_sign_and_address() {
        // ldrsh w1, [x2, #6]
        let load = ScalarLoad::from_instruction(&lift(0x79c0_0c41)).unwrap();
        assert_eq!(load.bytes(), 2);
        assert_eq!(load.destination(), Register::X(1));
        assert_eq!(load.result_width(), Width::W32);
        assert!(load.signed());
        assert_eq!(
            load.address(),
            ScalarLoadAddress::Immediate {
                base: Register::X(2),
                displacement: 6,
                mode: AddressMode::Offset,
            }
        );
        // ldr x3, #8 (literal)
        let literal = ScalarLoad::from_instruction(&lift(0x5800_0043)).unwrap();
        assert_eq!(literal.bytes(), 8);
        assert_eq!(
            literal.address(),
            ScalarLoadAddress::Literal { address: 0x1008 }
        );
        assert!(ScalarStore::from_instruction(&lift(0x79c0_0c41)).is_none());
    }

    #[test]
    fn stores_keep_width_source_and_writeback() {
        // strb w4, [x5], #1
        let store = ScalarStore::from_instruction(&lift(0x3800_14a4)).unwrap();
        assert_eq!(store.bytes(), 1);
        assert_eq!(store.source_register(), Register::X(4));
        assert_eq!(
            store.address(),
            ScalarStoreAddress::Immediate {
                base: Register::X(5),
                displacement: 1,
                mode: AddressMode::PostIndex,
            }
        );
        // sttr x0, [x1]: unprivileged
        assert!(ScalarStore::from_instruction(&lift(0xf800_0820)).is_none());
        assert!(ScalarLoad::from_instruction(&lift(0x3800_14a4)).is_none());
    }
}
