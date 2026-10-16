//! AMX instruction words: `0x00201000 + (operation << 5) + operand`
//! (corsix/amx `aarch64.md`).
use crate::{CompileError, GuestAddress};
use serde::Serialize;

/// Bits 31:10 of every AMX word.
const SPACE_MASK: u32 = 0xffff_fc00;
const SPACE: u32 = 0x0020_1000;
const OPERATION_SHIFT: u32 = 5;
const FIELD_MASK: u32 = 0x1f;
const SET_CLEAR: u32 = 17;
const INSTRUCTION_BYTES: u64 = 4;

/// The 23 allocated operations; 17 is split by its immediate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmxOperation {
    LoadX,
    LoadY,
    StoreX,
    StoreY,
    LoadZ,
    StoreZ,
    LoadZInterleaved,
    StoreZInterleaved,
    ExtractX,
    ExtractY,
    Fma64,
    Fms64,
    Fma32,
    Fms32,
    Mac16,
    Fma16,
    Fms16,
    Set,
    Clear,
    VectorInteger,
    VectorFloat,
    MatrixInteger,
    MatrixFloat,
    GenerateLookup,
}

impl AmxOperation {
    /// The operation field, and for 17 the immediate.
    pub const fn encoding(self) -> (u32, Option<u32>) {
        match self {
            Self::LoadX => (0, None),
            Self::LoadY => (1, None),
            Self::StoreX => (2, None),
            Self::StoreY => (3, None),
            Self::LoadZ => (4, None),
            Self::StoreZ => (5, None),
            Self::LoadZInterleaved => (6, None),
            Self::StoreZInterleaved => (7, None),
            Self::ExtractX => (8, None),
            Self::ExtractY => (9, None),
            Self::Fma64 => (10, None),
            Self::Fms64 => (11, None),
            Self::Fma32 => (12, None),
            Self::Fms32 => (13, None),
            Self::Mac16 => (14, None),
            Self::Fma16 => (15, None),
            Self::Fms16 => (16, None),
            Self::Set => (SET_CLEAR, Some(0)),
            Self::Clear => (SET_CLEAR, Some(1)),
            Self::VectorInteger => (18, None),
            Self::VectorFloat => (19, None),
            Self::MatrixInteger => (20, None),
            Self::MatrixFloat => (21, None),
            Self::GenerateLookup => (22, None),
        }
    }

    /// corsix/amx mnemonic.
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::LoadX => "ldx",
            Self::LoadY => "ldy",
            Self::StoreX => "stx",
            Self::StoreY => "sty",
            Self::LoadZ => "ldz",
            Self::StoreZ => "stz",
            Self::LoadZInterleaved => "ldzi",
            Self::StoreZInterleaved => "stzi",
            Self::ExtractX => "extrx",
            Self::ExtractY => "extry",
            Self::Fma64 => "fma64",
            Self::Fms64 => "fms64",
            Self::Fma32 => "fma32",
            Self::Fms32 => "fms32",
            Self::Mac16 => "mac16",
            Self::Fma16 => "fma16",
            Self::Fms16 => "fms16",
            Self::Set => "set",
            Self::Clear => "clr",
            Self::VectorInteger => "vecint",
            Self::VectorFloat => "vecfp",
            Self::MatrixInteger => "matint",
            Self::MatrixFloat => "matfp",
            Self::GenerateLookup => "genlut",
        }
    }

    pub const ALL: [Self; 24] = [
        Self::LoadX,
        Self::LoadY,
        Self::StoreX,
        Self::StoreY,
        Self::LoadZ,
        Self::StoreZ,
        Self::LoadZInterleaved,
        Self::StoreZInterleaved,
        Self::ExtractX,
        Self::ExtractY,
        Self::Fma64,
        Self::Fms64,
        Self::Fma32,
        Self::Fms32,
        Self::Mac16,
        Self::Fma16,
        Self::Fms16,
        Self::Set,
        Self::Clear,
        Self::VectorInteger,
        Self::VectorFloat,
        Self::MatrixInteger,
        Self::MatrixFloat,
        Self::GenerateLookup,
    ];

    /// The word for this operation and operand register (ignored by set/clr).
    pub const fn word(self, register: u8) -> u32 {
        let (operation, immediate) = self.encoding();
        let field = match immediate {
            Some(immediate) => immediate,
            None => register as u32 & FIELD_MASK,
        };
        SPACE | (operation << OPERATION_SHIFT) | field
    }

    pub const fn accesses_memory(self) -> bool {
        matches!(
            self,
            Self::LoadX
                | Self::LoadY
                | Self::StoreX
                | Self::StoreY
                | Self::LoadZ
                | Self::StoreZ
                | Self::LoadZInterleaved
                | Self::StoreZInterleaved
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum AmxOperand {
    /// General-purpose register index; 31 reads zero, never SP.
    Register(u8),
    /// Operation 17 only.
    None,
}

/// One AMX word at its guest PC. It writes no general-purpose or FP state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AmxInstruction {
    pub operation: AmxOperation,
    pub operand: AmxOperand,
    pub word: u32,
    pub instruction_pc: GuestAddress,
    pub next_pc: GuestAddress,
}

/// `Ok(None)` outside the AMX space. Operations 23..31 and operation-17
/// immediates other than 0/1 have no researched behavior and are refused.
pub fn decode(pc: GuestAddress, word: u32) -> Result<Option<AmxInstruction>, CompileError> {
    if word & SPACE_MASK != SPACE {
        return Ok(None);
    }
    if !pc.0.is_multiple_of(INSTRUCTION_BYTES) {
        return Err(CompileError(
            "AMX instruction PC must be aligned to 4 bytes".into(),
        ));
    }
    let operation = (word >> OPERATION_SHIFT) & FIELD_MASK;
    let field = word & FIELD_MASK;
    let (operation, operand) = match operation {
        SET_CLEAR => match field {
            0 => (AmxOperation::Set, AmxOperand::None),
            1 => (AmxOperation::Clear, AmxOperand::None),
            _ => {
                return Err(CompileError(alloc::format!(
                    "AMX operation 17 immediate {field} has no researched behavior"
                )));
            }
        },
        0..=22 => {
            let operation = AmxOperation::ALL
                .into_iter()
                .find(|candidate| candidate.encoding() == (operation, None))
                .expect("allocated AMX operation");
            (operation, AmxOperand::Register(field as u8))
        }
        _ => {
            return Err(CompileError(alloc::format!(
                "AMX operation {operation} is unallocated in the M2 generation"
            )));
        }
    };
    Ok(Some(AmxInstruction {
        operation,
        operand,
        word,
        instruction_pc: pc,
        next_pc: GuestAddress(pc.0.checked_add(INSTRUCTION_BYTES).ok_or_else(|| {
            CompileError("AMX continuation PC overflows guest address range".into())
        })?),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PC: GuestAddress = GuestAddress(0x1000);

    #[test]
    fn every_operation_and_register_round_trips() {
        for operation in AmxOperation::ALL {
            for register in 0..32u8 {
                let word = operation.word(register);
                let decoded = decode(PC, word).unwrap().unwrap();
                assert_eq!(decoded.operation, operation);
                assert_eq!(decoded.word, word);
                assert_eq!(decoded.next_pc, GuestAddress(PC.0 + 4));
                let expected = match operation {
                    AmxOperation::Set | AmxOperation::Clear => AmxOperand::None,
                    _ => AmxOperand::Register(register),
                };
                assert_eq!(decoded.operand, expected);
            }
        }
    }

    #[test]
    fn published_accelerate_examples_decode() {
        // docs/research/userspace.md: SET, CLR and FMA32 X10.
        let set = decode(PC, 0x0020_1220).unwrap().unwrap();
        assert_eq!(set.operation, AmxOperation::Set);
        let clear = decode(PC, 0x0020_1221).unwrap().unwrap();
        assert_eq!(clear.operation, AmxOperation::Clear);
        let fma = decode(PC, 0x0020_118a).unwrap().unwrap();
        assert_eq!(fma.operation, AmxOperation::Fma32);
        assert_eq!(fma.operand, AmxOperand::Register(10));
    }

    #[test]
    fn unresearched_encodings_are_refused_and_neighbors_are_not_amx() {
        for operation in 23..32u32 {
            assert!(decode(PC, SPACE | (operation << 5)).is_err());
        }
        for immediate in 2..32u32 {
            assert!(decode(PC, SPACE | (SET_CLEAR << 5) | immediate).is_err());
        }
        // Bits 11:10 and 15:12 are part of the fixed space.
        for word in [
            0x0020_1400,
            0x0020_1800,
            0x0020_0000,
            0x0020_3000,
            0x0021_1000,
        ] {
            assert_eq!(decode(PC, word).unwrap(), None);
        }
        assert!(decode(GuestAddress(2), SPACE).is_err());
        assert!(decode(GuestAddress(u64::MAX - 3), SPACE).is_err());
    }
}
