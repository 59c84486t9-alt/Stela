//! Canonical typed descriptors and decoder for the June PAuth_LR forms.
//! A decoded descriptor conveys source facts, not execution or key authority.

use serde::Serialize;

const REGISTER_MASK: u32 = 31;
const REGISTER_SHIFT: u32 = 5;
const OFFSET_SCALE: u32 = 2;
const OFFSET_MASK: u32 = u16::MAX as u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Key {
    Ia,
    Ib,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Instruction {
    Authenticate171615(Key),
    AuthenticateSpRegister { key: Key, register: u8 },
    AuthenticateSpPc { key: Key, offset: u32 },
    Sign171615(Key),
    SignSpPc { key: Key, implicit_bti: bool },
    ReturnSpRegister { key: Key, register: u8 },
    ReturnSpPc { key: Key, offset: u32 },
    Pacm,
}

impl Instruction {
    pub const fn valid(self) -> bool {
        match self {
            Self::AuthenticateSpRegister { register, .. } => register <= REGISTER_MASK as u8,
            // Rm31 is the existing RETAA/RETAB word, excluded by the LR diagram.
            Self::ReturnSpRegister { register, .. } => register < REGISTER_MASK as u8,
            Self::AuthenticateSpPc { offset, .. } | Self::ReturnSpPc { offset, .. } => {
                offset <= OFFSET_MASK << OFFSET_SCALE && offset.is_multiple_of(1 << OFFSET_SCALE)
            }
            _ => true,
        }
    }

    pub const fn is_return(self) -> bool {
        matches!(
            self,
            Self::ReturnSpRegister { .. } | Self::ReturnSpPc { .. }
        )
    }

    pub const fn key(self) -> Option<Key> {
        match self {
            Self::Pacm => None,
            Self::Authenticate171615(key) | Self::Sign171615(key) => Some(key),
            Self::AuthenticateSpRegister { key, .. }
            | Self::AuthenticateSpPc { key, .. }
            | Self::SignSpPc { key, .. }
            | Self::ReturnSpRegister { key, .. }
            | Self::ReturnSpPc { key, .. } => Some(key),
        }
    }

    pub const fn canonical_id(self) -> &'static str {
        match self {
            Self::Authenticate171615(Key::Ia) => "AUTIA171615_64LR_dp_1src",
            Self::Authenticate171615(Key::Ib) => "AUTIB171615_64LR_dp_1src",
            Self::AuthenticateSpRegister { key: Key::Ia, .. } => "AUTIASPPCR_64LRR_dp_1src",
            Self::AuthenticateSpRegister { key: Key::Ib, .. } => "AUTIBSPPCR_64LRR_dp_1src",
            Self::AuthenticateSpPc { key: Key::Ia, .. } => "AUTIASPPC_only_dp_1src_imm",
            Self::AuthenticateSpPc { key: Key::Ib, .. } => "AUTIBSPPC_only_dp_1src_imm",
            Self::Sign171615(Key::Ia) => "PACIA171615_64LR_dp_1src",
            Self::Sign171615(Key::Ib) => "PACIB171615_64LR_dp_1src",
            Self::SignSpPc {
                key: Key::Ia,
                implicit_bti: true,
            } => "PACIASPPC_64LR_dp_1src",
            Self::SignSpPc {
                key: Key::Ib,
                implicit_bti: true,
            } => "PACIBSPPC_64LR_dp_1src",
            Self::SignSpPc {
                key: Key::Ia,
                implicit_bti: false,
            } => "PACNBIASPPC_64LR_dp_1src",
            Self::SignSpPc {
                key: Key::Ib,
                implicit_bti: false,
            } => "PACNBIBSPPC_64LR_dp_1src",
            Self::ReturnSpRegister { key: Key::Ia, .. } => "RETAASPPCR_64M_branch_reg",
            Self::ReturnSpRegister { key: Key::Ib, .. } => "RETABSPPCR_64M_branch_reg",
            Self::ReturnSpPc { key: Key::Ia, .. } => "RETAASPPC_only_miscbranch",
            Self::ReturnSpPc { key: Key::Ib, .. } => "RETABSPPC_only_miscbranch",
            Self::Pacm => "PACM_HI_hints",
        }
    }
}

/// Fixed bits taken from the exact June members, not assembler acceptance.
const EXACT_FORMS: [(u32, Instruction); 9] = [
    (0xdac1_bbfe, Instruction::Authenticate171615(Key::Ia)),
    (0xdac1_bffe, Instruction::Authenticate171615(Key::Ib)),
    (0xdac1_8bfe, Instruction::Sign171615(Key::Ia)),
    (0xdac1_8ffe, Instruction::Sign171615(Key::Ib)),
    (
        0xdac1_a3fe,
        Instruction::SignSpPc {
            key: Key::Ia,
            implicit_bti: true,
        },
    ),
    (
        0xdac1_a7fe,
        Instruction::SignSpPc {
            key: Key::Ib,
            implicit_bti: true,
        },
    ),
    (
        0xdac1_83fe,
        Instruction::SignSpPc {
            key: Key::Ia,
            implicit_bti: false,
        },
    ),
    (
        0xdac1_87fe,
        Instruction::SignSpPc {
            key: Key::Ib,
            implicit_bti: false,
        },
    ),
    (0xd503_24ff, Instruction::Pacm),
];
const AUTH_REGISTER_MASK: u32 = 0xffff_fc1f;
const AUTH_REGISTER_FORMS: [(u32, Key); 2] = [(0xdac1_901e, Key::Ia), (0xdac1_941e, Key::Ib)];
const RETURN_REGISTER_MASK: u32 = 0xffff_ffe0;
const RETURN_REGISTER_FORMS: [(u32, Key); 2] = [(0xd65f_0be0, Key::Ia), (0xd65f_0fe0, Key::Ib)];
const PC_MASK: u32 = 0xffe0_001f;
const AUTH_PC_FORMS: [(u32, Key); 2] = [(0xf380_001f, Key::Ia), (0xf3a0_001f, Key::Ib)];
const RETURN_PC_FORMS: [(u32, Key); 2] = [(0x5500_001f, Key::Ia), (0x5520_001f, Key::Ib)];

/// A match conveys source facts only; it grants no execution capability.
pub fn decode(word: u32) -> Option<Instruction> {
    for (value, instruction) in EXACT_FORMS {
        if word == value {
            return Some(instruction);
        }
    }
    for (value, key) in AUTH_REGISTER_FORMS {
        if word & AUTH_REGISTER_MASK == value {
            return Some(Instruction::AuthenticateSpRegister {
                key,
                register: ((word >> REGISTER_SHIFT) & REGISTER_MASK) as u8,
            });
        }
    }
    for (value, key) in RETURN_REGISTER_FORMS {
        if word & RETURN_REGISTER_MASK == value {
            let instruction = Instruction::ReturnSpRegister {
                key,
                register: (word & REGISTER_MASK) as u8,
            };
            return instruction.valid().then_some(instruction);
        }
    }
    let offset = ((word >> REGISTER_SHIFT) & OFFSET_MASK) << OFFSET_SCALE;
    for (value, key) in AUTH_PC_FORMS {
        if word & PC_MASK == value {
            return Some(Instruction::AuthenticateSpPc { key, offset });
        }
    }
    for (value, key) in RETURN_PC_FORMS {
        if word & PC_MASK == value {
            return Some(Instruction::ReturnSpPc { key, offset });
        }
    }
    None
}
